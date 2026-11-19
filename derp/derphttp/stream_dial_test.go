// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package derphttp_test

import (
	"bufio"
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/derp/derpserver"
	"tailscale.com/net/netmon"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

type closeTrackedStream struct {
	net.Conn
	closed chan struct{}
	once   sync.Once
}

func (c *closeTrackedStream) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

func TestStreamDialEveryConnect(t *testing.T) {
	newClient := func(t *testing.T) *derphttp.Client {
		t.Helper()
		c, err := derphttp.NewClient(key.NewNode(), "https://signal.invalid/derp", t.Logf, netmon.NewStatic())
		if err != nil {
			t.Fatal(err)
		}
		c.SetURLDialer(func(context.Context, string, string) (net.Conn, error) {
			t.Error("unexpected network dial")
			return nil, errors.New("network dial forbidden")
		})
		t.Cleanup(func() { c.Close() })
		return c
	}
	t.Run("empty_region", func(t *testing.T) {
		c := derphttp.NewRegionClient(key.NewNode(), t.Logf, netmon.NewStatic(), func() *tailcfg.DERPRegion {
			return &tailcfg.DERPRegion{RegionID: 7, RegionCode: "signal"}
		})
		defer c.Close()
		c.StreamDial = func(context.Context, string) (net.Conn, error) {
			t.Fatal("empty region reaches StreamDial")
			return nil, errors.New("unexpected stream dial")
		}
		if err := c.Connect(t.Context()); err == nil || !strings.Contains(err.Error(), "no nodes for region 7 (signal)") {
			t.Fatalf("empty region error = %v, want no nodes for region 7 (signal)", err)
		}
	})
	awaitClosed := func(t *testing.T, c *closeTrackedStream) {
		t.Helper()
		select {
		case <-c.closed:
		case <-time.After(time.Second):
			t.Fatal("stream is not closed")
		}
	}

	t.Run("reconnect", func(t *testing.T) {
		s := derpserver.New(key.NewNode(), t.Logf)
		defer s.Close()
		c := newClient(t)
		calls := 0
		var server net.Conn
		c.StreamDial = func(ctx context.Context, url string) (net.Conn, error) {
			calls++
			if url != "https://signal.invalid/derp" {
				t.Errorf("URL = %q", url)
			}
			client, peer := net.Pipe()
			server = peer
			go s.Accept(t.Context(), peer, bufio.NewReadWriter(bufio.NewReader(peer), bufio.NewWriter(peer)), "127.0.0.1:1")
			return client, nil
		}
		for i := 1; i <= 2; i++ {
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			err := c.Connect(ctx)
			cancel()
			if err != nil {
				t.Fatal(err)
			}
			m, err := c.Recv()
			if _, ok := m.(derp.ServerInfoMessage); !ok || err != nil {
				t.Fatalf("handshake: %T, %v", m, err)
			}
			if calls != i {
				t.Fatalf("dial calls = %d, want %d", calls, i)
			}
			server.Close()
			if _, err := c.Recv(); err == nil {
				t.Fatal("closed server: Recv succeeded")
			}
		}
	})
	t.Run("dial_error", func(t *testing.T) {
		c := newClient(t)
		calls := 0
		c.StreamDial = func(context.Context, string) (net.Conn, error) {
			calls++
			return nil, errors.New("stream dial refused")
		}
		if err := c.Connect(t.Context()); err == nil {
			t.Fatal("dial error: Connect succeeded")
		}
		if calls != 1 {
			t.Fatalf("dial calls = %d, want 1", calls)
		}
	})
	for _, mode := range []string{"deadline", "close", "malformed"} {
		t.Run(mode, func(t *testing.T) {
			c := newClient(t)
			client, peer := net.Pipe()
			defer peer.Close()
			stream := &closeTrackedStream{Conn: client, closed: make(chan struct{})}
			defer stream.Close()
			dialed := make(chan struct{})
			c.StreamDial = func(context.Context, string) (net.Conn, error) {
				close(dialed)
				return stream, nil
			}
			ctx, cancel := context.WithCancel(t.Context())
			if mode == "deadline" {
				cancel()
				ctx, cancel = context.WithTimeout(t.Context(), 200*time.Millisecond)
			}
			defer cancel()
			result := make(chan error, 1)
			go func() { result <- c.Connect(ctx) }()
			select {
			case <-dialed:
			case <-time.After(time.Second):
				t.Fatal("StreamDial not called")
			}
			if mode == "close" {
				closed := make(chan error, 1)
				go func() { closed <- c.Close() }()
				select {
				case err := <-closed:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(time.Second):
					t.Fatal("Close blocked during handshake")
				}
			}
			if mode == "malformed" {
				go func() { peer.Write(make([]byte, 45)) }()
			}
			select {
			case err := <-result:
				if err == nil {
					t.Fatal("invalid handshake: Connect succeeded")
				}
			case <-time.After(time.Second):
				t.Fatal("Connect blocked during handshake")
			}
			awaitClosed(t, stream)
		})
	}
}
