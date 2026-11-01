// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"tailscale.com/derp/derphttp"
	"tailscale.com/health"
	"tailscale.com/net/netmon"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/util/eventbus/eventbustest"
	"tailscale.com/util/usermetric"
)

// These listeners implement the packet boundary entirely in memory. In
// particular, NewConn must not open UDP sockets in the pipe-based tests.
type siloPacketListener struct{}

func (siloPacketListener) ListenPacket(context.Context, string, string) (net.PacketConn, error) {
	return &siloPacketConn{blockForeverConn: newBlockForeverConn()}, nil
}

type siloPacketConn struct{ *blockForeverConn }

func (c *siloPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, ap, err := c.ReadFromUDPAddrPort(b)
	return n, net.UDPAddrFromAddrPort(ap), err
}

func (c *siloPacketConn) WriteTo(b []byte, a net.Addr) (int, error) {
	return c.WriteToUDPAddrPort(b, a.(*net.UDPAddr).AddrPort())
}

func newSiloTestConn(t *testing.T, opts Options) *Conn {
	t.Helper()
	opts.TestOnlyPacketListener = siloPacketListener{}
	return newSiloConn(t, opts)
}

func newSiloConn(t *testing.T, opts Options) *Conn {
	t.Helper()
	bus := eventbustest.NewBus(t)
	opts.EventBus = bus
	opts.NetMon = netmon.NewStatic()
	opts.Logf = t.Logf
	opts.HealthTracker = health.NewTracker(bus)
	opts.Metrics = new(usermetric.Registry)
	opts.DisablePortMapper = true
	c, err := NewConn(opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.privateKey = key.NewNode()
	c.publicKeyAtomic.Store(c.privateKey.Public())
	c.havePrivateKey.Store(true)
	return c
}

func siloTestDERPMap() *tailcfg.DERPMap {
	return &tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{
		1: {RegionID: 1, RegionCode: "test", Nodes: []*tailcfg.DERPNode{
			{Name: "test", RegionID: 1, HostName: "signal.invalid", IPv4: "none", IPv6: "none"},
		}},
	}}
}

func captureSiloDERPWrites(c *Conn) chan derpWriteRequest {
	c.derpMap = siloTestDERPMap()
	c.derpMapAtomic.Store(c.derpMap)
	ch := make(chan derpWriteRequest, 32)
	dc := derphttp.NewRegionClient(c.privateKey, c.logf, c.netMon, func() *tailcfg.DERPRegion { return c.derpMap.Regions[1] })
	c.activeDerp = map[tailcfg.DERPRegionID]activeDerp{
		1: {c: dc, cancel: func() {}, writeCh: ch, lastWrite: new(time.Time)},
	}
	close(c.derpStarted)
	return ch
}

func TestRelayedDataAllowedPerPeer(t *testing.T) {
	denied, allowed := key.NewNode().Public(), key.NewNode().Public()
	for _, usePolicy := range []bool{false, true} {
		t.Run(fmt.Sprintf("policy=%t", usePolicy), func(t *testing.T) {
			var calls int
			allowDenied := false
			opts := Options{}
			if usePolicy {
				opts.RelayedDataAllowed = func(peer key.NodePublic) bool {
					calls++
					return peer != denied || allowDenied
				}
			}
			c := newSiloTestConn(t, opts)
			ch := captureSiloDERPWrites(c)
			derpAddr := netip.AddrPortFrom(tailcfg.DerpMagicIPAddr, 1)
			for _, peer := range []key.NodePublic{denied, allowed} {
				for _, isDisco := range []bool{false, true} {
					want := !usePolicy || peer != denied || isDisco
					sent, err := c.sendAddr(derpAddr, peer, []byte("packet"), isDisco, false)
					if sent != want || err != nil {
						t.Fatalf("peer=%v disco=%t: sent=%t err=%v, want %t", peer, isDisco, sent, err, want)
					}
					select {
					case wr := <-ch:
						if !want || wr.pubKey != peer || wr.isDisco != isDisco {
							t.Fatalf("unexpected DERP write: %+v", wr)
						}
					default:
						if want {
							t.Fatal("DERP write missing")
						}
					}
				}
			}
			if sent, err := c.sendAddr(netip.MustParseAddrPort("127.0.0.1:1234"), denied, []byte("direct"), false, false); !sent || err != nil {
				t.Fatalf("direct copy: sent=%t err=%v", sent, err)
			}
			if usePolicy {
				if calls != 2 {
					t.Fatalf("policy calls = %d, want 2", calls)
				}
				if got := c.DERPDataSuppressed(); got != 1 {
					t.Fatalf("suppressed = %d, want 1", got)
				}
				allowDenied = true
				if sent, err := c.sendAddr(derpAddr, denied, nil, false, false); !sent || err != nil {
					t.Fatalf("changed policy: sent=%t err=%v", sent, err)
				}
				if calls != 3 {
					t.Fatalf("policy calls after change = %d, want 3", calls)
				}
			} else if got := c.DERPDataSuppressed(); got != 0 {
				t.Fatalf("default suppressed = %d, want 0", got)
			}
		})
	}
}
