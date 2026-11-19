// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	wgconn "github.com/tailscale/wireguard-go/conn"
	"tailscale.com/derp/derphttp"
	"tailscale.com/derp/derpserver"
	"tailscale.com/disco"
	"tailscale.com/health"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/netmon"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/util/eventbus/eventbustest"
	"tailscale.com/util/usermetric"
)

// These listeners implement the packet boundary entirely in memory. In
// particular, NewConn must not open UDP sockets in the pipe-based tests.
type idlePacketListener struct{}

func (idlePacketListener) ListenPacket(context.Context, string, string) (net.PacketConn, error) {
	return &idlePacketConn{blockForeverConn: newBlockForeverConn()}, nil
}

type idlePacketConn struct{ *blockForeverConn }

func (c *idlePacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, ap, err := c.ReadFromUDPAddrPort(b)
	return n, net.UDPAddrFromAddrPort(ap), err
}

func (c *idlePacketConn) WriteTo(b []byte, a net.Addr) (int, error) {
	return c.WriteToUDPAddrPort(b, a.(*net.UDPAddr).AddrPort())
}

func newPacketListenerTestConn(t *testing.T, opts Options) *Conn {
	t.Helper()
	opts.TestOnlyPacketListener = idlePacketListener{}
	return newConfiguredTestConn(t, opts)
}

func newConfiguredTestConn(t *testing.T, opts Options) *Conn {
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

func signalingDERPMap() *tailcfg.DERPMap {
	return &tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{
		1: {RegionID: 1, RegionCode: "test", Nodes: []*tailcfg.DERPNode{
			{Name: "test", RegionID: 1, HostName: "signal.invalid", IPv4: "none", IPv6: "none"},
		}},
	}}
}

func captureDERPDataWrites(c *Conn) chan derpWriteRequest {
	c.derpMap = signalingDERPMap()
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
			c := newPacketListenerTestConn(t, opts)
			ch := captureDERPDataWrites(c)
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

func orderedTestEndpoints(n int) []tailcfg.Endpoint {
	eps := make([]tailcfg.Endpoint, n)
	for i := range eps {
		addr := netip.MustParseAddr("2001:db8::1")
		typ := tailcfg.EndpointLocal
		switch i % 4 {
		case 1:
			addr = netip.MustParseAddr("192.0.2.1")
		case 2:
			typ = tailcfg.EndpointSTUN
		case 3:
			typ = tailcfg.EndpointPortmapped
		}
		eps[i] = tailcfg.Endpoint{Addr: netip.AddrPortFrom(addr, uint16(i+1)), Type: typ}
	}
	return eps
}

func TestCapEndpointsOrder(t *testing.T) {
	eps := orderedTestEndpoints(8)
	eps = append(eps, tailcfg.Endpoint{Addr: netip.MustParseAddrPort("192.0.2.2:9"), Type: tailcfg.EndpointSTUN4LocalPort})
	want := []tailcfg.Endpoint{eps[2], eps[3], eps[6], eps[7], eps[8], eps[1], eps[5], eps[0], eps[4]}
	before := slices.Clone(eps)
	for _, max := range []int{0, 1, 6, 9, 64} {
		got := CapEndpoints(eps, max)
		expect := want[:min(max, len(want))]
		if !slices.Equal(got, expect) {
			t.Errorf("max=%d: got %v, want %v", max, got, expect)
		}
	}
	if !slices.Equal(eps, before) {
		t.Fatal("CapEndpoints mutates input")
	}
}

func TestCallMeMaybeEndpointCap(t *testing.T) {
	for _, tc := range []struct {
		name                   string
		cap, count, want, size int
	}{
		{"default", 0, 80, 80, 1520}, {"capped", 64, 80, 64, 1232}, {"short", 64, 40, 40, 800},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newPacketListenerTestConn(t, Options{MaxCallMeMaybeEndpoints: tc.cap})
			ch := captureDERPDataWrites(c)
			peerDisco := key.NewDisco()
			node := (&tailcfg.Node{ID: 1, Key: key.NewNode().Public(), DiscoKey: peerDisco.Public(), HomeDERP: 1}).View()
			c.mu.Lock()
			c.upsertPeerLocked(node, debugFlags{}, 1)
			de, ok := c.peerMap.endpointForNodeKey(node.Key())
			c.mu.Unlock()
			if !ok {
				t.Fatal("missing peer")
			}
			c.lastEndpoints = orderedTestEndpoints(tc.count)
			c.lastEndpointsTime = time.Now()
			c.enqueueCallMeMaybe(netip.AddrPortFrom(tailcfg.DerpMagicIPAddr, 1), de)
			select {
			case wr := <-ch:
				if len(wr.b) != tc.size {
					t.Fatalf("body = %d bytes, want %d", len(wr.b), tc.size)
				}
				shared := peerDisco.Shared(c.discoAtomic.Public())
				plain, ok := shared.Open(wr.b[len(disco.Magic)+32:])
				if !ok {
					t.Fatal("cannot open CallMeMaybe")
				}
				m, err := disco.Parse(plain)
				if err != nil {
					t.Fatal(err)
				}
				cmm, ok := m.(*disco.CallMeMaybe)
				if !ok {
					t.Fatalf("message = %T, want CallMeMaybe", m)
				}
				if len(cmm.MyNumber) != tc.want {
					t.Fatalf("endpoints = %d, want %d", len(cmm.MyNumber), tc.want)
				}
				wantEndpoints := c.lastEndpoints
				if tc.cap > 0 {
					wantEndpoints = CapEndpoints(c.lastEndpoints, tc.cap)
				}
				for i, ep := range wantEndpoints {
					if cmm.MyNumber[i] != ep.Addr {
						t.Fatalf("endpoint %d = %v, want %v", i, cmm.MyNumber[i], ep.Addr)
					}
				}
			case <-time.After(time.Second):
				t.Fatal("CallMeMaybe not sent")
			}
		})
	}
}

func TestSignalingRegionDial(t *testing.T) {
	s := derpserver.New(key.NewNode(), t.Logf)
	defer s.Close()
	var calls atomic.Int32
	dial := func(ctx context.Context, url string) (net.Conn, error) {
		calls.Add(1)
		if url != "https://signal.invalid/derp" {
			return nil, fmt.Errorf("unexpected dial URL %q", url)
		}
		client, peer := net.Pipe()
		go s.Accept(t.Context(), peer, bufio.NewReadWriter(bufio.NewReader(peer), bufio.NewWriter(peer)), "127.0.0.1:1")
		return client, nil
	}
	opts := Options{SignalingRegions: map[int]SignalingRegion{1: {Dial: dial}}}
	a, b := newPacketListenerTestConn(t, opts), newPacketListenerTestConn(t, opts)
	for _, c := range []*Conn{a, b} {
		c.SetDERPMapWithoutReSTUN(signalingDERPMap())
		if ch := c.derpWriteChanForRegion(1, key.NodePublic{}); ch == nil {
			t.Fatal("missing region")
		}
		c.mu.Lock()
		dc := c.activeDerp[1].c
		c.mu.Unlock()
		if dc.StreamDial == nil {
			t.Fatal("region did not install StreamDial")
		}
		c.WaitReady(t)
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		err := dc.Ping(ctx)
		cancel()
		if err != nil {
			t.Fatalf("DERP handshake: %v", err)
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("stream calls = %d, want 2", calls.Load())
	}
	if !s.IsClientConnectedForTest(a.privateKey.Public()) || !s.IsClientConnectedForTest(b.privateKey.Public()) {
		t.Fatal("clients not registered")
	}
	// A Ping is encrypted as a disco frame; a Pong over this same region
	// proves both directions pass through magicsock's region transport.
	var peerNode tailcfg.NodeView
	for i, pair := range [][2]*Conn{{a, b}, {b, a}} {
		c, peer := pair[0], pair[1]
		node := (&tailcfg.Node{ID: tailcfg.NodeID(i + 1), Name: "peer.test", Key: peer.privateKey.Public(), DiscoKey: peer.discoAtomic.Public(), HomeDERP: 1}).View()
		c.mu.Lock()
		c.upsertPeerLocked(node, debugFlags{}, 1)
		c.mu.Unlock()
		if c == a {
			peerNode = node
		}
		fns, _, err := c.Bind().Open(0)
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			fns[len(fns)-1](make([]byte, 2048), make([]wgconn.ReceivedPacket, 1))
		}()
		t.Cleanup(func() {
			c.Bind().Close()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Error("DERP receive did not close")
			}
		})
	}
	pong := make(chan *ipnstate.PingResult, 1)
	a.Ping(peerNode, new(ipnstate.PingResult), 0, func(res *ipnstate.PingResult) { pong <- res })
	select {
	case res := <-pong:
		if res.Err != "" || res.DERPRegionID != 1 {
			t.Fatalf("disco round trip = %+v, want region 1", res)
		}
	case <-time.After(time.Second):
		t.Fatal("disco frame did not round-trip through signaling region")
	}
}
