// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"tailscale.com/disco"
	"tailscale.com/envknob"
	"tailscale.com/net/packet"
	"tailscale.com/net/stun"
	"tailscale.com/tailcfg"
	"tailscale.com/tstime/mono"
	"tailscale.com/types/key"
	"tailscale.com/types/views"
	"tailscale.com/util/ringlog"
)

func recoverySynctest(t *testing.T, f func(*testing.T)) {
	t.Helper()
	now := time.Now()
	synctest.Test(t, func(t *testing.T) {
		// mono.Now derives its epoch from package initialization outside the
		// bubble. Move the fake clock forward so its zero sentinel stays past.
		time.Sleep(time.Until(now))
		f(t)
	})
}

func recoveryTestTimeouts(t *testing.T) {
	t.Helper()
	oldTimeout, oldInterval := pingTimeoutDuration, discoPingInterval
	pingTimeoutDuration, discoPingInterval = 5*time.Second, 5*time.Second
	t.Cleanup(func() { pingTimeoutDuration, discoPingInterval = oldTimeout, oldInterval })
}

func recoveryTestEndpoint(t *testing.T, enabled bool) (*Conn, *endpoint, chan key.NodePublic) {
	t.Helper()
	validated := make(chan key.NodePublic, 16)
	c := newSiloTestConn(t, Options{
		DirectPathRecovery: enabled,
		DirectPathValidatedFunc: func(peer key.NodePublic) {
			validated <- peer
		},
	})
	c.mu.Lock()
	node := (&tailcfg.Node{ID: 1, Key: key.NewNode().Public(), DiscoKey: key.NewDisco().Public(),
		Endpoints: []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:1234")}}).View()
	c.upsertPeerLocked(node, debugFlags{}, 1)
	de, ok := c.peerMap.endpointForNodeKey(node.Key())
	c.endpointsUpdateActive = true // Observe ReSTUN's coalescing state without starting netcheck.
	c.mu.Unlock()
	if !ok {
		t.Fatal("missing peer")
	}
	t.Cleanup(func() {
		c.mu.Lock()
		c.endpointsUpdateActive = false
		c.mu.Unlock()
	})
	synctest.Wait()
	de.mu.Lock()
	for tx, sp := range de.sentPing {
		sp.timer.Stop()
		delete(de.sentPing, tx)
	}
	now := mono.Now()
	de.bestAddr = addrQuality{epAddr: epAddr{ap: node.Endpoints().At(0)}, latency: 50 * time.Millisecond}
	de.bestAddrAt = now.Add(-time.Second)
	de.trustBestAddrUntil = now.Add(trustUDPAddrDuration)
	de.freshAfter = 0
	de.derpAddr = netip.AddrPort{}
	for _, st := range de.endpointState {
		st.lastPing = now
	}
	de.mu.Unlock()
	return c, de, validated
}

func recoveryTestPong(t *testing.T, de *endpoint, addr netip.AddrPort, at mono.Time, size int) {
	t.Helper()
	tx := stun.NewTxID()
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	de.mu.Lock()
	de.sentPing[tx] = sentPing{to: epAddr{ap: addr}, at: at, timer: timer, purpose: pingHeartbeat, size: size}
	de.mu.Unlock()
	de.c.mu.Lock()
	known := de.handlePongConnLocked(&disco.Pong{TxID: tx, Src: addr}, &discoInfo{}, epAddr{ap: addr})
	de.c.mu.Unlock()
	if !known {
		t.Fatal("pong did not match its sent ping")
	}
	synctest.Wait()
}

func recoveryTestReSTUN(c *Conn) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.wantEndpointsUpdate
}

func TestDirectPathRecoveryNewEndpoint(t *testing.T) {
	recoveryTestTimeouts(t)
	newAddr := netip.MustParseAddrPort("192.0.2.2:5678")
	for _, source := range []string{"netmap", "callmemaybe", "ping", "rebind"} {
		for _, enabled := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/enabled=%t", source, enabled), func(t *testing.T) {
				recoverySynctest(t, func(t *testing.T) {
					_, de, validated := recoveryTestEndpoint(t, enabled)
					oldBest, oldTrust := de.bestAddr, de.trustBestAddrUntil
					now := mono.Now()
					switch source {
					case "netmap":
						de.mu.Lock()
						de.setEndpointsLocked(views.SliceOf([]netip.AddrPort{oldBest.ap, newAddr}))
						de.mu.Unlock()
					case "callmemaybe":
						de.handleCallMeMaybe(&disco.CallMeMaybe{MyNumber: []netip.AddrPort{oldBest.ap, newAddr}})
					case "ping":
						de.addCandidateEndpoint(newAddr, stun.NewTxID())
					case "rebind":
						de.mu.Lock()
						de.endpointState[newAddr] = &endpointState{lastPing: now, recentPongs: []pongReply{{latency: time.Second}}}
						de.mu.Unlock()
						de.noteConnectivityChange()
					}
					synctest.Wait()
					if enabled {
						if de.bestAddr != oldBest || de.trustBestAddrUntil != now || de.freshAfter != now {
							t.Errorf("revalidate: best=%v trust=%v freshAfter=%v; want %v, %v, %v", de.bestAddr, de.trustBestAddrUntil, de.freshAfter, oldBest, now, now)
						}
						for _, addr := range []netip.AddrPort{oldBest.ap, newAddr} {
							count := 0
							for _, sp := range de.sentPing {
								if sp.to.ap == addr && sp.at == now && sp.purpose == pingDiscovery {
									count++
								}
							}
							if de.endpointState[addr].lastPing != now || count != 1 {
								t.Errorf("target %v: lastPing=%v pings=%d, want %v and 1", addr, de.endpointState[addr].lastPing, count, now)
							}
						}
						if source == "rebind" && len(de.endpointState[newAddr].recentPongs) != 0 {
							t.Error("rebind retained derived candidate state")
						}
					} else if source == "rebind" {
						if de.bestAddr.ap.IsValid() {
							t.Errorf("upstream rebind retained bestAddr %v", de.bestAddr)
						}
					} else if de.trustBestAddrUntil != oldTrust || de.freshAfter != 0 {
						t.Errorf("option off changed trust=%v or freshAfter=%v", de.trustBestAddrUntil, de.freshAfter)
					}
					if source == "rebind" {
						return
					}
					time.Sleep(50 * time.Millisecond)
					recoveryTestPong(t, de, newAddr, now, 0)
					wantBest, wantCallbacks := oldBest.ap, 0
					if enabled {
						wantBest, wantCallbacks = newAddr, 1
					}
					if de.bestAddr.ap != wantBest || len(validated) != wantCallbacks {
						t.Errorf("equal-latency pong: best=%v callbacks=%d, want %v and %d", de.bestAddr.ap, len(validated), wantBest, wantCallbacks)
					}
					if enabled {
						if !mono.Now().Before(de.trustBestAddrUntil) || de.bestAddrAt != mono.Now() {
							t.Error("fresh pong did not validate the peer")
						}
						select {
						case peer := <-validated:
							if peer != de.publicKey {
								t.Errorf("validated peer=%v, want %v", peer, de.publicKey)
							}
						default:
							t.Error("validated callback missing")
						}
					}
				})
			})
		}
	}
	t.Run("reordered-list", func(t *testing.T) {
		recoverySynctest(t, func(t *testing.T) {
			_, de, validated := recoveryTestEndpoint(t, true)
			de.endpointState[newAddr] = &endpointState{index: 1}
			best, trust := de.bestAddr, de.trustBestAddrUntil
			de.mu.Lock()
			de.setEndpointsLocked(views.SliceOf([]netip.AddrPort{newAddr, best.ap}))
			de.mu.Unlock()
			synctest.Wait()
			if de.bestAddr != best || de.trustBestAddrUntil != trust || de.freshAfter != 0 || len(de.sentPing) != 0 || len(validated) != 0 {
				t.Error("reordering the same network-map endpoints changed path state")
			}
		})
	})
	for _, row := range []string{"trust-already-expired", "stale-better-path-after-validation", "stale-current-path", "second-trigger", "renewal-while-trusted", "better-path-while-trusted"} {
		t.Run(row, func(t *testing.T) {
			recoverySynctest(t, func(t *testing.T) {
				_, de, validated := recoveryTestEndpoint(t, true)
				now := mono.Now()
				oldAddr := de.bestAddr.ap
				staleAt := now.Add(-time.Millisecond)
				if row == "renewal-while-trusted" || row == "better-path-while-trusted" {
					addr := oldAddr
					if row == "better-path-while-trusted" {
						addr = newAddr
						de.endpointState[addr] = &endpointState{}
					}
					recoveryTestPong(t, de, addr, now.Add(-time.Millisecond), 0)
					if len(validated) != 0 || de.bestAddr.ap != addr || de.bestAddrAt != now {
						t.Errorf("trusted pong: callbacks=%d best=%v bestAddrAt=%v", len(validated), de.bestAddr, de.bestAddrAt)
					}
					return
				}
				if row == "trust-already-expired" {
					de.trustBestAddrUntil = now.Add(-time.Second)
				}
				logs := make(chan string, 16)
				if row == "second-trigger" {
					de.c.logf = func(format string, args ...any) { logs <- fmt.Sprintf(format, args...) }
				}
				de.addCandidateEndpoint(newAddr, stun.NewTxID())
				synctest.Wait()
				if row == "second-trigger" {
					time.Sleep(time.Millisecond)
					de.addCandidateEndpoint(netip.MustParseAddrPort("192.0.2.3:9"), stun.NewTxID())
					synctest.Wait()
					if de.freshAfter != now || de.trustBestAddrUntil != mono.Now() {
						t.Errorf("second trigger: freshAfter=%v trust=%v, want %v and %v", de.freshAfter, de.trustBestAddrUntil, now, mono.Now())
					}
					var episodes []string
					for len(logs) > 0 {
						if line := <-logs; strings.Contains(line, " revalidate (") {
							episodes = append(episodes, line)
						}
					}
					wantLog := fmt.Sprintf("magicsock: disco: node %v revalidate (ping)", de.publicKey.ShortString())
					if len(episodes) != 1 || episodes[0] != wantLog {
						t.Errorf("episode logs=%q, want one %q", episodes, wantLog)
					}
					return
				}
				if row == "stale-better-path-after-validation" {
					time.Sleep(50 * time.Millisecond)
					recoveryTestPong(t, de, newAddr, now, 0)
					// A loopback candidate wins betterAddr even with a slightly older ping.
					oldAddr = netip.MustParseAddrPort("127.0.0.1:9")
					de.endpointState[oldAddr] = &endpointState{}
					if !betterAddr(addrQuality{epAddr: epAddr{ap: oldAddr}, latency: mono.Now().Sub(staleAt)}, de.bestAddr) {
						t.Fatal("fixture's stale pong would not win betterAddr")
					}
				}
				best, bestAt, trust, callbacks := de.bestAddr, de.bestAddrAt, de.trustBestAddrUntil, len(validated)
				recoveryTestPong(t, de, oldAddr, staleAt, 0)
				if de.bestAddr != best || de.bestAddrAt != bestAt || de.trustBestAddrUntil != trust || len(validated) != callbacks {
					t.Errorf("stale pong changed best=%v bestAt=%v trust=%v callbacks=%d", de.bestAddr, de.bestAddrAt, de.trustBestAddrUntil, len(validated))
				}
				if len(de.endpointState[oldAddr].recentPongs) != 1 {
					t.Error("stale pong was not recorded in endpoint history")
				}
				if de.freshAfter != now {
					t.Errorf("episode boundary=%v, want %v", de.freshAfter, now)
				}
			})
		})
	}
	for _, enabled := range []bool{true, false} {
		t.Run(fmt.Sprintf("callmemaybe-omits-netmap-best/enabled=%t", enabled), func(t *testing.T) {
			recoverySynctest(t, func(t *testing.T) {
				_, de, _ := recoveryTestEndpoint(t, enabled)
				best, trust := de.bestAddr, de.trustBestAddrUntil
				de.handleCallMeMaybe(&disco.CallMeMaybe{MyNumber: []netip.AddrPort{best.ap}})
				synctest.Wait()
				time.Sleep(time.Millisecond)
				now := mono.Now()
				de.handleCallMeMaybe(&disco.CallMeMaybe{})
				synctest.Wait()
				st, exists := de.endpointState[best.ap]
				if enabled {
					if de.bestAddr != best || de.trustBestAddrUntil != trust || !exists {
						t.Fatalf("omission: best=%v trust=%v entry=%t, want %v, %v, true", de.bestAddr, de.trustBestAddrUntil, exists, best, trust)
					}
					if _, marked := de.isCallMeMaybeEP[best.ap]; marked || !st.callMeMaybeTime.IsZero() || st.lastPing != now {
						t.Errorf("kept entry: map mark=%t callMeMaybeTime=%v lastPing=%v, want false, zero, %v", marked, st.callMeMaybeTime, st.lastPing, now)
					}
				} else if exists || de.bestAddr.ap.IsValid() {
					t.Errorf("option off: entry=%t best=%v, want deleted and cleared", exists, de.bestAddr)
				}
			})
		})
	}
}

func TestDirectPathRecoveryAnnouncesEndpoints(t *testing.T) {
	for _, row := range []string{"changed", "unchanged", "option-off", "no-recipients"} {
		t.Run(row, func(t *testing.T) {
			recoverySynctest(t, func(t *testing.T) {
				c := newSiloTestConn(t, Options{DirectPathRecovery: row != "option-off"})
				writes := captureSiloDERPWrites(c)
				var logs []string
				c.logf = func(format string, args ...any) { logs = append(logs, fmt.Sprintf(format, args...)) }
				peers := make(map[key.NodePublic]key.DiscoPrivate)
				want := make(map[key.NodePublic]bool)
				for i, kind := range []string{"data-active", "idle", "new-episode", "old-episode", "no-derp"} {
					dk := key.NewDisco()
					node := (&tailcfg.Node{ID: tailcfg.NodeID(i + 1), Key: key.NewNode().Public(), DiscoKey: dk.Public(), HomeDERP: 1}).View()
					c.mu.Lock()
					c.upsertPeerLocked(node, debugFlags{}, 1)
					de, _ := c.peerMap.endpointForNodeKey(node.Key())
					c.mu.Unlock()
					de.mu.Lock()
					switch kind {
					case "data-active", "no-derp":
						de.lastSendData = mono.Now()
					case "new-episode":
						de.freshAfter = mono.Now().Add(-time.Second)
					case "old-episode":
						de.freshAfter = mono.Now().Add(-5 * time.Second)
					}
					if kind == "no-derp" || row == "no-recipients" {
						de.derpAddr = netip.AddrPort{}
					}
					de.mu.Unlock()
					peers[node.Key()] = dk
					if row == "changed" && (kind == "data-active" || kind == "new-episode") {
						want[node.Key()] = true
					}
				}
				endpoints := siloEndpoints(3)
				c.epFunc = func(got []tailcfg.Endpoint) {
					if !slices.Equal(got, endpoints) {
						t.Errorf("endpoint callback = %v, want %v", got, endpoints)
					}
				}
				if row == "unchanged" {
					c.setEndpoints(endpoints)
				}
				c.setEndpointsAndNotify(endpoints)
				synctest.Wait()
				got := make(map[key.NodePublic]int)
				for len(writes) > 0 {
					wr := <-writes
					got[wr.pubKey]++
					shared := peers[wr.pubKey].Shared(c.discoAtomic.Public())
					plain, ok := shared.Open(wr.b[len(disco.Magic)+32:])
					if !ok {
						t.Fatal("cannot open announcement")
					}
					msg, err := disco.Parse(plain)
					if err != nil {
						t.Fatal(err)
					}
					cmm, ok := msg.(*disco.CallMeMaybe)
					if !ok {
						t.Fatalf("announcement=%T, want CallMeMaybe", msg)
					}
					if !slices.Equal(cmm.MyNumber, epFromTyped(endpoints)) {
						t.Errorf("announced endpoints=%v, want %v", cmm.MyNumber, epFromTyped(endpoints))
					}
				}
				if len(got) != len(want) {
					t.Errorf("announcement recipients=%v, want %v", got, want)
				}
				for peer := range want {
					if got[peer] != 1 {
						t.Errorf("announcements to %v = %d, want 1", peer, got[peer])
					}
				}
				wantLog := ""
				if row == "changed" || row == "no-recipients" {
					wantLog = fmt.Sprintf("magicsock: announcing new endpoints to %d active peers", len(want))
				}
				var announcements []string
				for _, line := range logs {
					if strings.Contains(line, "announcing new endpoints") {
						announcements = append(announcements, line)
					}
				}
				if wantLog != "" && (len(announcements) != 1 || announcements[0] != wantLog) || wantLog == "" && len(announcements) != 0 {
					t.Errorf("announcement logs=%q, want %q", announcements, wantLog)
				}
			})
		})
	}
}

func TestDirectPathRecoveryLiveness(t *testing.T) {
	recoveryTestTimeouts(t)
	for _, latency := range []time.Duration{350 * time.Millisecond, 500 * time.Millisecond, 525 * time.Millisecond} {
		t.Run(fmt.Sprintf("data-active-latency=%v", latency), func(t *testing.T) {
			recoverySynctest(t, func(t *testing.T) {
				c, de, _ := recoveryTestEndpoint(t, true)
				de.bestAddr.latency = latency
				other := netip.MustParseAddrPort("192.0.2.2:5678")
				de.endpointState[other] = &endpointState{index: 1, lastPing: mono.Now()}
				start, best := mono.Now(), de.bestAddr
				if err := de.send([][]byte{make([]byte, packet.GeneveFixedHeaderLength+4)}, packet.GeneveFixedHeaderLength); err != nil {
					t.Fatal(err)
				}
				if de.lastSendData != start {
					t.Errorf("lastSendData=%v, want %v", de.lastSendData, start)
				}
				time.Sleep(500 * time.Millisecond)
				synctest.Wait()
				if de.endpointState[best.ap].lastPing != mono.Now() {
					t.Errorf("first heartbeat lastPing=%v, want %v", de.endpointState[best.ap].lastPing, mono.Now())
				}
				first := start.Add(500 * time.Millisecond)
				time.Sleep(500 * time.Millisecond)
				synctest.Wait()
				if de.endpointState[best.ap].lastPing != mono.Now() || de.firstUnansweredAt != first {
					t.Errorf("second beat lastPing=%v firstUnansweredAt=%v, want %v and %v", de.endpointState[best.ap].lastPing, de.firstUnansweredAt, mono.Now(), first)
				}
				deadline := first.Add(max(time.Second, 3*latency))
				time.Sleep(deadline.Sub(mono.Now()) - time.Nanosecond)
				synctest.Wait()
				if why := recoveryTestReSTUN(c); why != "" || de.freshAfter != 0 {
					t.Errorf("loss before L: ReSTUN=%q freshAfter=%v", why, de.freshAfter)
				}
				time.Sleep(time.Nanosecond)
				synctest.Wait()
				if why := recoveryTestReSTUN(c); why != "direct-path-lost" || de.freshAfter != deadline || de.trustBestAddrUntil != deadline || de.bestAddr != best || !de.firstUnansweredAt.IsZero() {
					t.Errorf("at L: ReSTUN=%q freshAfter=%v trust=%v best=%v firstUnanswered=%v", why, de.freshAfter, de.trustBestAddrUntil, de.bestAddr, de.firstUnansweredAt)
				}
				for addr, st := range de.endpointState {
					if st.lastPing != deadline {
						t.Errorf("candidate %v lastPing=%v, want %v", addr, st.lastPing, deadline)
					}
				}
				time.Sleep(2 * time.Second)
				synctest.Wait()
				if de.freshAfter != deadline {
					t.Errorf("untrusted endpoint opened a second B episode at %v", de.freshAfter)
				}
			})
		})
	}
	for _, row := range []string{"idle", "idle-open-episode", "option-off", "already-untrusted"} {
		t.Run(row, func(t *testing.T) {
			recoverySynctest(t, func(t *testing.T) {
				c, de, _ := recoveryTestEndpoint(t, row != "option-off")
				start := mono.Now()
				de.lastSendExt = start
				if row == "option-off" || row == "already-untrusted" {
					de.lastSendData = start
				}
				if row == "idle-open-episode" {
					de.freshAfter = start
					de.trustBestAddrUntil = start
				}
				if row == "already-untrusted" {
					de.trustBestAddrUntil = start
				}
				de.heartbeat()
				synctest.Wait()
				fresh := de.freshAfter
				if row != "already-untrusted" {
					time.Sleep(3*time.Second - time.Nanosecond)
					synctest.Wait()
					if de.endpointState[de.bestAddr.ap].lastPing != start {
						t.Errorf("idle or option-off heartbeat fired before 3s: %v", de.endpointState[de.bestAddr.ap].lastPing)
					}
					time.Sleep(time.Nanosecond)
					synctest.Wait()
					if de.endpointState[de.bestAddr.ap].lastPing != mono.Now() {
						t.Errorf("heartbeat did not fire at 3s: %v", de.endpointState[de.bestAddr.ap].lastPing)
					}
				} else {
					time.Sleep(2 * time.Second)
					synctest.Wait()
				}
				if why := recoveryTestReSTUN(c); why != "" || de.freshAfter != fresh || !de.firstUnansweredAt.IsZero() {
					t.Errorf("unexpected B: ReSTUN=%q freshAfter=%v firstUnanswered=%v", why, de.freshAfter, de.firstUnansweredAt)
				}
			})
		})
	}
	for _, latency := range []time.Duration{350 * time.Millisecond, 525 * time.Millisecond} {
		for _, lost := range []bool{false, true} {
			t.Run(fmt.Sprintf("pong-latency=%v/one-lost=%t", latency, lost), func(t *testing.T) {
				recoverySynctest(t, func(t *testing.T) {
					c, de, _ := recoveryTestEndpoint(t, true)
					de.bestAddr.latency = latency
					de.lastSendData, de.lastSendExt = mono.Now(), mono.Now()
					start := mono.Now()
					de.heartbeat()
					if lost {
						time.Sleep(500 * time.Millisecond)
					}
					at := mono.Now()
					time.Sleep(latency)
					recoveryTestPong(t, de, de.bestAddr.ap, at, 0)
					if !de.firstUnansweredAt.IsZero() {
						t.Errorf("pong did not clear unanswered ping: %v", de.firstUnansweredAt)
					}
					// Stop automatic beats to isolate the timer the answered ping armed.
					de.heartBeatTimer.Stop()
					time.Sleep(start.Add(3*latency).Sub(mono.Now()) + time.Nanosecond)
					synctest.Wait()
					if why := recoveryTestReSTUN(c); why != "" || de.freshAfter != 0 {
						t.Errorf("answered heartbeat caused B: ReSTUN=%q freshAfter=%v", why, de.freshAfter)
					}
				})
			})
		}
	}
	t.Run("late-earlier-pong-then-unanswered", func(t *testing.T) {
		recoverySynctest(t, func(t *testing.T) {
			c, de, _ := recoveryTestEndpoint(t, true)
			de.bestAddr.latency = 350 * time.Millisecond
			de.lastSendData = mono.Now()
			start := mono.Now()
			de.mu.Lock()
			de.startDiscoPingLocked(de.bestAddr.epAddr, start, pingCLI, 0, nil)
			de.mu.Unlock()
			time.Sleep(350 * time.Millisecond)
			recoveryTestPong(t, de, de.bestAddr.ap, start.Add(-time.Millisecond), 0)
			de.mu.Lock()
			de.startDiscoPingLocked(de.bestAddr.epAddr, mono.Now(), pingHeartbeat, 0, nil)
			de.mu.Unlock()
			deadline := mono.Now().Add(3 * de.bestAddr.latency)
			if de.heartBeatTimer != nil {
				de.heartBeatTimer.Stop()
			}
			time.Sleep(deadline.Sub(mono.Now()) - time.Nanosecond)
			synctest.Wait()
			if why := recoveryTestReSTUN(c); why != "" {
				t.Errorf("old timer caused loss early: %q", why)
			}
			time.Sleep(time.Nanosecond)
			synctest.Wait()
			if why := recoveryTestReSTUN(c); why != "direct-path-lost" || de.freshAfter != deadline {
				t.Errorf("new unanswered ping: ReSTUN=%q freshAfter=%v, want direct-path-lost and %v", why, de.freshAfter, deadline)
			}
		})
	})
	t.Run("episode-retry", func(t *testing.T) {
		recoverySynctest(t, func(t *testing.T) {
			_, de, _ := recoveryTestEndpoint(t, true)
			other := netip.MustParseAddrPort("192.0.2.2:5678")
			de.addCandidateEndpoint(other, stun.NewTxID())
			start := mono.Now()
			de.lastSendData, de.lastSendExt = start, start
			de.heartbeat()
			for i := 1; i < 10; i++ {
				time.Sleep(500 * time.Millisecond)
				synctest.Wait()
				if de.endpointState[other].lastPing != mono.Now() {
					t.Errorf("beat %d candidate lastPing=%v, want %v", i, de.endpointState[other].lastPing, mono.Now())
				}
			}
			time.Sleep(500 * time.Millisecond)
			synctest.Wait()
			if de.endpointState[other].lastPing != start.Add(4500*time.Millisecond) {
				t.Errorf("candidate limit bypassed after 5s: lastPing=%v", de.endpointState[other].lastPing)
			}
			de.heartBeatTimer.Stop()
			de.heartBeatTimer = nil
			if de.bestAddr.ap.IsValid() {
				t.Errorf("ping timeout retained the untrusted dead best address %v", de.bestAddr)
			}
			recoveryTestPong(t, de, other, mono.Now().Add(-time.Millisecond), 0)
			// Episode alone uses the normal cadence; a new data send restarts fast beats.
			if err := de.send([][]byte{make([]byte, packet.GeneveFixedHeaderLength+4)}, packet.GeneveFixedHeaderLength); err != nil {
				t.Fatal(err)
			}
			time.Sleep(500 * time.Millisecond)
			synctest.Wait()
			if de.heartBeatTimer == nil {
				t.Error("data after idle did not restart heartbeats")
			}
			if de.endpointState[other].lastPing != mono.Now() {
				t.Errorf("data after idle: heartbeat at %v, want %v", de.endpointState[other].lastPing, mono.Now())
			}
		})
	})
	for _, timerState := range []string{"absent", "armed", "stopped", "disabled"} {
		t.Run("first-data-heartbeat/"+timerState, func(t *testing.T) {
			recoverySynctest(t, func(t *testing.T) {
				_, de, _ := recoveryTestEndpoint(t, true)
				start := mono.Now()
				de.lastSendData = start.Add(-5 * time.Second)
				switch timerState {
				case "armed", "stopped":
					de.heartBeatTimer = time.AfterFunc(heartbeatInterval, de.heartbeat)
					if timerState == "stopped" {
						de.heartBeatTimer.Stop()
					}
				case "disabled":
					de.heartbeatDisabled = true
				}
				if err := de.send([][]byte{make([]byte, packet.GeneveFixedHeaderLength+4)}, packet.GeneveFixedHeaderLength); err != nil {
					t.Fatal(err)
				}
				time.Sleep(500 * time.Millisecond)
				synctest.Wait()
				want := mono.Now()
				if timerState == "disabled" {
					want = start
				}
				if got := de.endpointState[de.bestAddr.ap].lastPing; got != want {
					t.Errorf("first data heartbeat at %v, want %v", got, want)
				}
			})
		})
	}
	for _, reset := range []string{"resetLocked", "stopAndReset"} {
		t.Run("liveness-timer/"+reset, func(t *testing.T) {
			recoverySynctest(t, func(t *testing.T) {
				c, de, _ := recoveryTestEndpoint(t, true)
				de.lastSendData = mono.Now()
				de.mu.Lock()
				de.startDiscoPingLocked(de.bestAddr.epAddr, mono.Now(), pingHeartbeat, 0, nil)
				timer := de.livenessTimer
				de.mu.Unlock()
				if timer == nil {
					t.Fatal("trusted active ping did not arm liveness")
				}
				if reset == "resetLocked" {
					de.mu.Lock()
					de.resetLocked()
					de.mu.Unlock()
				} else {
					de.stopAndReset()
				}
				if timer.Stop() {
					t.Error("reset left the liveness timer running")
				}
				time.Sleep(time.Second)
				synctest.Wait()
				if why := recoveryTestReSTUN(c); why != "" {
					t.Errorf("reset caused a stale ReSTUN request: %q", why)
				}
			})
		})
	}
}

func TestProbeUDPLifetimeConfig_Equals(t *testing.T) {
	tests := []struct {
		name string
		a    *ProbeUDPLifetimeConfig
		b    *ProbeUDPLifetimeConfig
		want bool
	}{
		{
			"both sides nil",
			nil,
			nil,
			true,
		},
		{
			"equal pointers",
			defaultProbeUDPLifetimeConfig,
			defaultProbeUDPLifetimeConfig,
			true,
		},
		{
			"a nil",
			nil,
			&ProbeUDPLifetimeConfig{
				Cliffs:             []time.Duration{time.Second},
				CycleCanStartEvery: time.Hour,
			},
			false,
		},
		{
			"b nil",
			&ProbeUDPLifetimeConfig{
				Cliffs:             []time.Duration{time.Second},
				CycleCanStartEvery: time.Hour,
			},
			nil,
			false,
		},
		{
			"Cliffs unequal",
			&ProbeUDPLifetimeConfig{
				Cliffs:             []time.Duration{time.Second},
				CycleCanStartEvery: time.Hour,
			},
			&ProbeUDPLifetimeConfig{
				Cliffs:             []time.Duration{time.Second * 2},
				CycleCanStartEvery: time.Hour,
			},
			false,
		},
		{
			"CycleCanStartEvery unequal",
			&ProbeUDPLifetimeConfig{
				Cliffs:             []time.Duration{time.Second},
				CycleCanStartEvery: time.Hour,
			},
			&ProbeUDPLifetimeConfig{
				Cliffs:             []time.Duration{time.Second},
				CycleCanStartEvery: time.Hour * 2,
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.a.Equals(tt.b); got != tt.want {
				t.Errorf("Equals() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProbeUDPLifetimeConfig_Valid(t *testing.T) {
	tests := []struct {
		name string
		p    *ProbeUDPLifetimeConfig
		want bool
	}{
		{
			"default config valid",
			defaultProbeUDPLifetimeConfig,
			true,
		},
		{
			"no cliffs",
			&ProbeUDPLifetimeConfig{
				CycleCanStartEvery: time.Hour,
			},
			false,
		},
		{
			"zero CycleCanStartEvery",
			&ProbeUDPLifetimeConfig{
				Cliffs:             []time.Duration{time.Second * 10},
				CycleCanStartEvery: 0,
			},
			false,
		},
		{
			"cliff too small",
			&ProbeUDPLifetimeConfig{
				Cliffs:             []time.Duration{min(udpLifetimeProbeCliffSlack*2, heartbeatInterval)},
				CycleCanStartEvery: time.Hour,
			},
			false,
		},
		{
			"duplicate Cliffs values",
			&ProbeUDPLifetimeConfig{
				Cliffs:             []time.Duration{time.Second * 2, time.Second * 2},
				CycleCanStartEvery: time.Hour,
			},
			false,
		},
		{
			"Cliffs not ascending",
			&ProbeUDPLifetimeConfig{
				Cliffs:             []time.Duration{time.Second * 2, time.Second * 1},
				CycleCanStartEvery: time.Hour,
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.Valid(); got != tt.want {
				t.Errorf("Valid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_endpoint_maybeProbeUDPLifetimeLocked(t *testing.T) {
	var lowerPriv, higherPriv key.DiscoPrivate
	var lower, higher key.DiscoPublic
	privA := key.NewDisco()
	privB := key.NewDisco()
	a := privA.Public()
	b := privB.Public()
	if a.String() < b.String() {
		lower = a
		higher = b
		lowerPriv = privA
		higherPriv = privB
	} else {
		lower = b
		higher = a
		lowerPriv = privB
		higherPriv = privA
	}
	addr := addrQuality{epAddr: epAddr{ap: netip.MustParseAddrPort("1.1.1.1:1")}}
	newProbeUDPLifetime := func() *probeUDPLifetime {
		return &probeUDPLifetime{
			config: *defaultProbeUDPLifetimeConfig,
		}
	}

	tests := []struct {
		name                     string
		localDisco               key.DiscoPublic
		remoteDisco              *key.DiscoPublic
		probeUDPLifetimeFn       func() *probeUDPLifetime
		bestAddr                 addrQuality
		wantAfterInactivityForFn func(*probeUDPLifetime) time.Duration
		wantMaybe                bool
	}{
		{
			name:        "nil-probeUDPLifetime",
			localDisco:  higher,
			remoteDisco: &lower,
			probeUDPLifetimeFn: func() *probeUDPLifetime {
				return nil
			},
			bestAddr: addr,
		},
		{
			name:               "local-higher-disco-key",
			localDisco:         higher,
			remoteDisco:        &lower,
			probeUDPLifetimeFn: newProbeUDPLifetime,
			bestAddr:           addr,
		},
		{
			name:               "remote-no-disco-key",
			localDisco:         higher,
			remoteDisco:        nil,
			probeUDPLifetimeFn: newProbeUDPLifetime,
			bestAddr:           addr,
		},
		{
			name:               "invalid-bestAddr",
			localDisco:         lower,
			remoteDisco:        &higher,
			probeUDPLifetimeFn: newProbeUDPLifetime,
			bestAddr:           addrQuality{},
		},
		{
			name:        "cycle-started-too-recently",
			localDisco:  lower,
			remoteDisco: &higher,
			probeUDPLifetimeFn: func() *probeUDPLifetime {
				lt := newProbeUDPLifetime()
				lt.cycleActive = false
				lt.cycleStartedAt = time.Now()
				return lt
			},
			bestAddr: addr,
		},
		{
			name:        "maybe-cliff-0-cycle-not-active",
			localDisco:  lower,
			remoteDisco: &higher,
			probeUDPLifetimeFn: func() *probeUDPLifetime {
				lt := newProbeUDPLifetime()
				lt.cycleActive = false
				lt.cycleStartedAt = time.Now().Add(-lt.config.CycleCanStartEvery).Add(-time.Second)
				return lt
			},
			bestAddr: addr,
			wantAfterInactivityForFn: func(lifetime *probeUDPLifetime) time.Duration {
				return lifetime.config.Cliffs[0] - udpLifetimeProbeCliffSlack
			},
			wantMaybe: true,
		},
		{
			name:        "maybe-cliff-0",
			localDisco:  lower,
			remoteDisco: &higher,
			probeUDPLifetimeFn: func() *probeUDPLifetime {
				lt := newProbeUDPLifetime()
				lt.cycleActive = true
				lt.currentCliff = 0
				return lt
			},
			bestAddr: addr,
			wantAfterInactivityForFn: func(lifetime *probeUDPLifetime) time.Duration {
				return lifetime.config.Cliffs[0] - udpLifetimeProbeCliffSlack
			},
			wantMaybe: true,
		},
		{
			name:        "maybe-cliff-1",
			localDisco:  lower,
			remoteDisco: &higher,
			probeUDPLifetimeFn: func() *probeUDPLifetime {
				lt := newProbeUDPLifetime()
				lt.cycleActive = true
				lt.currentCliff = 1
				return lt
			},
			bestAddr: addr,
			wantAfterInactivityForFn: func(lifetime *probeUDPLifetime) time.Duration {
				return lifetime.config.Cliffs[1] - udpLifetimeProbeCliffSlack
			},
			wantMaybe: true,
		},
		{
			name:        "maybe-cliff-2",
			localDisco:  lower,
			remoteDisco: &higher,
			probeUDPLifetimeFn: func() *probeUDPLifetime {
				lt := newProbeUDPLifetime()
				lt.cycleActive = true
				lt.currentCliff = 2
				return lt
			},
			bestAddr: addr,
			wantAfterInactivityForFn: func(lifetime *probeUDPLifetime) time.Duration {
				return lifetime.config.Cliffs[2] - udpLifetimeProbeCliffSlack
			},
			wantMaybe: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Conn{logf: func(msg string, args ...any) {}}
			if tt.localDisco.IsZero() {
				c.discoAtomic.Set(key.NewDisco())
			} else if tt.localDisco.Compare(lower) == 0 {
				c.discoAtomic.Set(lowerPriv)
			} else if tt.localDisco.Compare(higher) == 0 {
				c.discoAtomic.Set(higherPriv)
			} else {
				t.Fatalf("unexpected localDisco value")
			}
			de := &endpoint{
				c:        c,
				bestAddr: tt.bestAddr,
			}
			if tt.remoteDisco != nil {
				de.updateDiscoKey(*tt.remoteDisco)
			}
			p := tt.probeUDPLifetimeFn()
			de.probeUDPLifetime = p
			gotAfterInactivityFor, gotMaybe := de.maybeProbeUDPLifetimeLocked()
			var wantAfterInactivityFor time.Duration
			if tt.wantAfterInactivityForFn != nil {
				wantAfterInactivityFor = tt.wantAfterInactivityForFn(p)
			}
			if gotAfterInactivityFor != wantAfterInactivityFor {
				t.Errorf("maybeProbeUDPLifetimeLocked() gotAfterInactivityFor = %v, want %v", gotAfterInactivityFor, wantAfterInactivityFor)
			}
			if gotMaybe != tt.wantMaybe {
				t.Errorf("maybeProbeUDPLifetimeLocked() gotMaybe = %v, want %v", gotMaybe, tt.wantMaybe)
			}
		})
	}
}

func Test_epAddr_isDirectUDP(t *testing.T) {
	vni := packet.VirtualNetworkID{}
	vni.Set(7)
	tests := []struct {
		name string
		ap   netip.AddrPort
		vni  packet.VirtualNetworkID
		want bool
	}{
		{
			name: "true",
			ap:   netip.MustParseAddrPort("192.0.2.1:7"),
			vni:  packet.VirtualNetworkID{},
			want: true,
		},
		{
			name: "false-derp-magic-addr",
			ap:   netip.AddrPortFrom(tailcfg.DerpMagicIPAddr, 0),
			vni:  packet.VirtualNetworkID{},
			want: false,
		},
		{
			name: "false-vni-set",
			ap:   netip.MustParseAddrPort("192.0.2.1:7"),
			vni:  vni,
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := epAddr{
				ap:  tt.ap,
				vni: tt.vni,
			}
			if got := e.isDirect(); got != tt.want {
				t.Errorf("isDirect() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_endpoint_udpRelayEndpointReady(t *testing.T) {
	directAddrQuality := addrQuality{epAddr: epAddr{ap: netip.MustParseAddrPort("192.0.2.1:7")}}
	peerRelayAddrQuality := addrQuality{epAddr: epAddr{ap: netip.MustParseAddrPort("192.0.2.2:77")}, latency: time.Second}
	peerRelayAddrQuality.vni.Set(1)
	peerRelayAddrQualityHigherLatencySameServer := addrQuality{
		epAddr:  epAddr{ap: netip.MustParseAddrPort("192.0.2.3:77"), vni: peerRelayAddrQuality.vni},
		latency: peerRelayAddrQuality.latency * 10,
	}
	peerRelayAddrQualityHigherLatencyDiffServer := addrQuality{
		epAddr:           epAddr{ap: netip.MustParseAddrPort("192.0.2.3:77"), vni: peerRelayAddrQuality.vni},
		latency:          peerRelayAddrQuality.latency * 10,
		relayServerDisco: key.NewDisco().Public(),
	}
	peerRelayAddrQualityLowerLatencyDiffServer := addrQuality{
		epAddr:           epAddr{ap: netip.MustParseAddrPort("192.0.2.4:77"), vni: peerRelayAddrQuality.vni},
		latency:          peerRelayAddrQuality.latency / 10,
		relayServerDisco: key.NewDisco().Public(),
	}
	peerRelayAddrQualityEqualLatencyDiffServer := addrQuality{
		epAddr:           epAddr{ap: netip.MustParseAddrPort("192.0.2.4:77"), vni: peerRelayAddrQuality.vni},
		latency:          peerRelayAddrQuality.latency,
		relayServerDisco: key.NewDisco().Public(),
	}
	tests := []struct {
		name               string
		curBestAddr        addrQuality
		trustBestAddrUntil mono.Time
		maybeBest          addrQuality
		wantBestAddr       addrQuality
	}{
		{
			name:               "bestAddr-trusted-direct",
			curBestAddr:        directAddrQuality,
			trustBestAddrUntil: mono.Now().Add(1 * time.Hour),
			maybeBest:          peerRelayAddrQuality,
			wantBestAddr:       directAddrQuality,
		},
		{
			name:               "bestAddr-untrusted-direct",
			curBestAddr:        directAddrQuality,
			trustBestAddrUntil: mono.Now().Add(-1 * time.Hour),
			maybeBest:          peerRelayAddrQuality,
			wantBestAddr:       peerRelayAddrQuality,
		},
		{
			name:               "maybeBest-same-relay-higher-latency-trusted",
			curBestAddr:        peerRelayAddrQuality,
			trustBestAddrUntil: mono.Now().Add(1 * time.Hour),
			maybeBest:          peerRelayAddrQualityHigherLatencySameServer,
			wantBestAddr:       peerRelayAddrQualityHigherLatencySameServer,
		},
		{
			name:               "maybeBest-diff-relay-higher-latency-trusted",
			curBestAddr:        peerRelayAddrQuality,
			trustBestAddrUntil: mono.Now().Add(1 * time.Hour),
			maybeBest:          peerRelayAddrQualityHigherLatencyDiffServer,
			wantBestAddr:       peerRelayAddrQuality,
		},
		{
			name:               "maybeBest-diff-relay-lower-latency-trusted",
			curBestAddr:        peerRelayAddrQuality,
			trustBestAddrUntil: mono.Now().Add(1 * time.Hour),
			maybeBest:          peerRelayAddrQualityLowerLatencyDiffServer,
			wantBestAddr:       peerRelayAddrQualityLowerLatencyDiffServer,
		},
		{
			name:               "maybeBest-diff-relay-equal-latency-trusted",
			curBestAddr:        peerRelayAddrQuality,
			trustBestAddrUntil: mono.Now().Add(1 * time.Hour),
			maybeBest:          peerRelayAddrQualityEqualLatencyDiffServer,
			wantBestAddr:       peerRelayAddrQuality,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			de := &endpoint{
				c:                  &Conn{logf: func(msg string, args ...any) { return }},
				bestAddr:           tt.curBestAddr,
				trustBestAddrUntil: tt.trustBestAddrUntil,
			}
			de.udpRelayEndpointReady(tt.maybeBest)
			if de.bestAddr != tt.wantBestAddr {
				t.Errorf("de.bestAddr = %v, want %v", de.bestAddr, tt.wantBestAddr)
			}
		})
	}
}

func Test_endpoint_discoPingTimeout(t *testing.T) {
	expired := -1 * time.Hour
	valid := 1 * time.Hour
	directAddrA := epAddr{ap: netip.MustParseAddrPort("192.0.2.1:7")}
	relayAddrA := epAddr{ap: netip.MustParseAddrPort("192.0.2.2:77")}
	relayAddrA.vni.Set(1)
	directAddrB := epAddr{ap: netip.MustParseAddrPort("192.0.2.3:7")}
	relayAddrB := epAddr{ap: netip.MustParseAddrPort("192.0.2.4:77")}
	relayAddrB.vni.Set(1)

	for _, tc := range []struct {
		name                string
		bestAddr            addrQuality
		trustBestAddrUntil  time.Duration
		pingTo              epAddr
		wantBestAddrCleared bool
	}{
		{
			name:                "relay-path-trust-expired",
			bestAddr:            addrQuality{epAddr: relayAddrA},
			trustBestAddrUntil:  expired,
			pingTo:              relayAddrA,
			wantBestAddrCleared: true,
		},
		{
			name:                "direct-udp-path-trust-expired",
			bestAddr:            addrQuality{epAddr: directAddrA},
			trustBestAddrUntil:  expired,
			pingTo:              directAddrA,
			wantBestAddrCleared: true,
		},
		{
			name:                "direct-udp-path-trust-valid",
			bestAddr:            addrQuality{epAddr: directAddrA},
			trustBestAddrUntil:  valid,
			pingTo:              directAddrA,
			wantBestAddrCleared: false,
		},
		{
			name:                "relay-path-trust-valid",
			bestAddr:            addrQuality{epAddr: relayAddrA},
			trustBestAddrUntil:  valid,
			pingTo:              relayAddrA,
			wantBestAddrCleared: false,
		},
		{
			name:                "ping-to-different-direct-addr-trust-expired",
			bestAddr:            addrQuality{epAddr: directAddrA},
			trustBestAddrUntil:  expired,
			pingTo:              directAddrB,
			wantBestAddrCleared: false,
		},
		{
			name:                "ping-to-different-relay-addr-trust-expired",
			bestAddr:            addrQuality{epAddr: relayAddrA},
			trustBestAddrUntil:  expired,
			pingTo:              relayAddrB,
			wantBestAddrCleared: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				now := mono.Now() // synctest to match this to the internal 'now'
				c := &Conn{
					logf: func(msg string, args ...any) {},
				}
				c.discoAtomic.Set(key.NewDisco())
				de := &endpoint{
					c:                  c,
					bestAddr:           tc.bestAddr,
					trustBestAddrUntil: now.Add(tc.trustBestAddrUntil),
					sentPing:           make(map[stun.TxID]sentPing),
				}
				txid := stun.NewTxID()
				timer := time.NewTimer(time.Hour)
				timer.Stop()
				de.sentPing[txid] = sentPing{
					to:      tc.pingTo,
					at:      now.Add(-100 * time.Millisecond),
					timer:   timer,
					purpose: pingDiscovery,
				}

				de.discoPingTimeout(txid)
				if tc.wantBestAddrCleared {
					if de.bestAddr.ap.IsValid() {
						t.Errorf("expected bestAddr to be cleared, but bestAddr.ap is valid: %v", de.bestAddr.ap)
					}
					if de.trustBestAddrUntil != 0 {
						t.Errorf("expected trustBestAddrUntil to be cleared, but got: %v", de.trustBestAddrUntil)
					}
				} else {
					if de.bestAddr != tc.bestAddr {
						t.Errorf("expected bestAddr to be unchanged, got: %v, want: %v", de.bestAddr, tc.bestAddr)
					}
				}
				if _, ok := de.sentPing[txid]; ok {
					t.Errorf("expected sentPing[txid] to be removed, but it still exists")
				}
			})
		})
	}
}

func Test_endpoint_sendDiscoPingsLocked_neverDirectUDP(t *testing.T) {
	directAddr := netip.MustParseAddrPort("192.0.2.1:7")
	for _, neverDirectUDP := range []bool{false, true} {
		t.Run(fmt.Sprintf("neverDirectUDP=%v", neverDirectUDP), func(t *testing.T) {
			prev := envknob.String("TS_DEBUG_NEVER_DIRECT_UDP")
			if neverDirectUDP {
				envknob.SetenvForTest(t, "TS_DEBUG_NEVER_DIRECT_UDP", "true")
			} else {
				envknob.SetenvForTest(t, "TS_DEBUG_NEVER_DIRECT_UDP", "")
			}
			t.Cleanup(func() { envknob.Setenv("TS_DEBUG_NEVER_DIRECT_UDP", prev) })
			now := mono.Now()
			c := &Conn{
				logf: func(msg string, args ...any) {},
			}
			c.discoAtomic.Set(key.NewDisco())
			de := &endpoint{
				c:             c,
				sentPing:      make(map[stun.TxID]sentPing),
				endpointState: make(map[netip.AddrPort]*endpointState),
			}
			de.updateDiscoKey(key.NewDisco().Public())
			de.endpointState[directAddr] = &endpointState{}
			de.sendDiscoPingsLocked(now, true)

			wantPing := !neverDirectUDP
			if gotPing := de.lastFullPing == now; gotPing != wantPing {
				t.Errorf("lastFullPing set = %v, want %v", gotPing, wantPing)
			}
			if gotPing := de.endpointState[directAddr].lastPing == now; gotPing != wantPing {
				t.Errorf("direct endpoint lastPing set = %v, want %v", gotPing, wantPing)
			}
		})
	}
}

func Test_endpoint_updateFromNodeAfterDiscoKeyChange(t *testing.T) {
	relayAddr := epAddr{ap: netip.MustParseAddrPort("192.0.2.2:77")}
	relayAddr.vni.Set(1)
	directAddr := epAddr{ap: netip.MustParseAddrPort("192.0.2.1:7")}

	for _, tc := range []struct {
		name       string
		bestAddr   epAddr
		keyChanges bool
	}{
		{
			name:       "relay-bestaddr-key-changed",
			bestAddr:   relayAddr,
			keyChanges: true,
		},
		{
			name:       "direct-bestaddr-key-changed",
			bestAddr:   directAddr,
			keyChanges: true,
		},
		{
			name:       "relay-bestaddr-key-unchanged",
			bestAddr:   relayAddr,
			keyChanges: false,
		},
		{
			name:       "direct-bestaddr-key-unchanged",
			bestAddr:   directAddr,
			keyChanges: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := mono.Now()
			c := &Conn{
				logf: func(msg string, args ...any) {},
			}
			c.discoAtomic.Set(key.NewDisco())
			c.relayManager.hasPeerRelayServers.Store(true)

			oldKey := key.NewDisco().Public()
			de := &endpoint{
				c:                  c,
				publicKey:          key.NewNode().Public(),
				bestAddr:           addrQuality{epAddr: tc.bestAddr},
				trustBestAddrUntil: now.Add(time.Hour),
				sentPing:           make(map[stun.TxID]sentPing),
				endpointState:      make(map[netip.AddrPort]*endpointState),
				debugUpdates:       ringlog.New[EndpointChange](10),
			}
			de.lastUDPRelayPathDiscovery = mono.Now()
			de.disco.Store(&endpointDisco{controlKey: oldKey, controlShort: oldKey.ShortString()})

			incomingKey := oldKey
			if tc.keyChanges {
				incomingKey = key.NewDisco().Public()
			}
			nv := (&tailcfg.Node{
				ID:       1,
				Key:      key.NewNode().Public(),
				DiscoKey: incomingKey,
				HomeDERP: 1,
				Cap:      121, // capVerIsRelayCapable
			}).View()
			de.updateFromNode(nv, false, false)

			de.mu.Lock()
			got := de.wantUDPRelayPathDiscoveryLocked(now)
			de.mu.Unlock()
			if got != tc.keyChanges {
				t.Errorf("wantUDPRelayPathDiscoveryLocked = %v, want %v", got, tc.keyChanges)
			}
		})
	}
}

func Test_endpoint_handlePongConnLocked(t *testing.T) {
	goodLatency := 50 * time.Millisecond
	badLatency := 100 * time.Millisecond
	expired := -1 * time.Hour
	valid := 1 * time.Hour
	directAddrA := epAddr{ap: netip.MustParseAddrPort("192.0.2.1:7")}
	directAddrB := epAddr{ap: netip.MustParseAddrPort("192.0.2.2:8")}
	derpAddr := epAddr{ap: netip.AddrPortFrom(tailcfg.DerpMagicIPAddr, 0)}

	for _, tc := range []struct {
		name               string
		bestAddr           addrQuality
		trustBestAddrUntil time.Duration
		pongFrom           epAddr
		pongLatency        time.Duration
		wantBestAddr       epAddr
	}{
		{
			name:               "better-latency-trust-valid",
			bestAddr:           addrQuality{epAddr: directAddrA, latency: badLatency},
			trustBestAddrUntil: valid,
			pongFrom:           directAddrB,
			pongLatency:        goodLatency,
			wantBestAddr:       directAddrB,
		},
		{
			name:               "worse-latency-trust-valid",
			bestAddr:           addrQuality{epAddr: directAddrA, latency: goodLatency},
			trustBestAddrUntil: valid,
			pongFrom:           directAddrB,
			pongLatency:        badLatency,
			wantBestAddr:       directAddrA,
		},
		{
			name:               "worse-latency-trust-expired",
			bestAddr:           addrQuality{epAddr: directAddrA, latency: goodLatency},
			trustBestAddrUntil: expired,
			pongFrom:           directAddrB,
			pongLatency:        badLatency,
			wantBestAddr:       directAddrB,
		},
		{
			name:               "same-path-trust-expired",
			bestAddr:           addrQuality{epAddr: directAddrA, latency: badLatency},
			trustBestAddrUntil: expired,
			pongFrom:           directAddrA,
			pongLatency:        goodLatency, // updated latency
			wantBestAddr:       directAddrA,
		},
		{
			name:               "derp-pong-trust-expired",
			bestAddr:           addrQuality{epAddr: directAddrA, latency: badLatency},
			trustBestAddrUntil: expired,
			pongFrom:           derpAddr,
			pongLatency:        goodLatency,
			wantBestAddr:       directAddrA,
		},
		{
			name:               "better-latency-trust-expired",
			bestAddr:           addrQuality{epAddr: directAddrA, latency: badLatency},
			trustBestAddrUntil: expired,
			pongFrom:           directAddrB,
			pongLatency:        goodLatency,
			wantBestAddr:       directAddrB,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				now := mono.Now() // synctest to match this to the internal 'now'
				pm := newPeerMap()
				c := &Conn{
					logf:    func(msg string, args ...any) {},
					peerMap: pm,
				}
				c.discoAtomic.Set(key.NewDisco())
				de := &endpoint{
					c:                  c,
					bestAddr:           tc.bestAddr,
					bestAddrAt:         now.Add(-5 * time.Minute),
					trustBestAddrUntil: now.Add(tc.trustBestAddrUntil),
					sentPing:           make(map[stun.TxID]sentPing),
					endpointState:      make(map[netip.AddrPort]*endpointState),
					debugUpdates:       ringlog.New[EndpointChange](10),
				}
				txid := stun.NewTxID()
				pong := &disco.Pong{
					TxID: txid,
					Src:  tc.pongFrom.ap,
				}
				timer := time.NewTimer(time.Hour)
				timer.Stop()
				de.sentPing[txid] = sentPing{
					to:      tc.pongFrom,
					at:      now.Add(-tc.pongLatency),
					timer:   timer,
					purpose: pingDiscovery,
				}
				if tc.pongFrom.ap.Addr() != tailcfg.DerpMagicIPAddr && !tc.pongFrom.vni.IsSet() {
					de.endpointState[tc.pongFrom.ap] = &endpointState{}
				}
				di := &discoInfo{
					discoKey:   key.NewDisco().Public(),
					discoShort: "test",
				}

				knownTxID := de.handlePongConnLocked(pong, di, tc.pongFrom)
				if !knownTxID {
					t.Errorf("expected knownTxID to be true, got false")
				}
				if de.bestAddr.epAddr != tc.wantBestAddr {
					t.Errorf("expected bestAddr.epAddr to be %v, got: %v", tc.wantBestAddr, de.bestAddr.epAddr)
				}
				if tc.pongFrom == tc.bestAddr.epAddr && de.bestAddr.latency-tc.pongLatency > 0 {
					t.Errorf("expected latency to be  %v, got: %v", tc.pongLatency, de.bestAddr.latency)
				}
				if tc.pongFrom != derpAddr && de.trustBestAddrUntil.Before(now) {
					t.Errorf("expected trustBestAddrUntil to be refreshed, but it's in the past: %v", de.trustBestAddrUntil)
				}
				if _, ok := de.sentPing[txid]; ok {
					t.Errorf("expected sentPing[txid] to be removed, but it still exists")
				}
			})
		})
	}
}

// TestUpdateFromNodeUsesControlKeyForComparison verifies that updateFromNode
// compares the netmap-provided disco key against the endpoint's control-learned
// key (keyFromControl), not the currently active key (key()).
func TestUpdateFromNodeUsesControlKeyForComparison(t *testing.T) {
	dk1 := key.NewDisco().Public() // initial control key
	dk2 := key.NewDisco().Public() // TSMP key

	tests := []struct {
		name           string
		netmapDiscoKey key.DiscoPublic
		wantControlKey key.DiscoPublic
		wantActiveKey  key.DiscoPublic
		wantTsmpActive bool
	}{
		{
			name:           "control_catches_up_to_tsmp_key",
			netmapDiscoKey: dk2,
			wantControlKey: dk2,
			wantActiveKey:  dk2,
			wantTsmpActive: true,
		},
		{
			name:           "unchanged_netmap_key_preserves_active",
			netmapDiscoKey: dk1,
			wantControlKey: dk1,
			wantActiveKey:  dk2,
			wantTsmpActive: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			de := &endpoint{c: &Conn{logf: func(msg string, args ...any) {}}}
			de.updateDiscoKey(dk1)
			de.updateTSMPDiscoKey(dk2)

			// Calls updateDiscoKey() internally and sets the endpoint `disco` field.
			de.updateFromNode(
				(&tailcfg.Node{Key: de.publicKey, DiscoKey: tt.netmapDiscoKey}).View(),
				false, false)

			epDisco := de.disco.Load()
			if got := epDisco.keyFromControl(); got != tt.wantControlKey {
				t.Errorf("keyFromControl: got %v, want %v", got, tt.wantControlKey)
			}
			if got := epDisco.tsmpActive; got != tt.wantTsmpActive {
				t.Errorf("tsmpActive: got %t, want %t", got, tt.wantTsmpActive)
			}
			if got := epDisco.key(); got != tt.wantActiveKey {
				t.Errorf("key(): got %v, want %v", got, tt.wantActiveKey)
			}
		})
	}
}

func TestSawDiscoKey(t *testing.T) {
	controlKey := key.NewDisco().Public()
	tsmpKey := key.NewDisco().Public()
	unknownKey := key.NewDisco().Public()
	controlKey2 := key.NewDisco().Public()

	tests := []struct {
		name           string
		initial        *endpointDisco
		seen           key.DiscoPublic
		hook           func(de *endpoint) // injected between Load and CAS; nil = no hook
		wantResult     bool
		wantNil        bool
		wantTsmpActive bool // checked only when initial != nil
		wantCalled     bool // whether changedActiveDisco should be called
	}{
		{
			name:       "nil-disco",
			initial:    nil,
			seen:       controlKey,
			wantResult: false,
			wantNil:    true,
		},
		{
			name:           "active-control-key-seen",
			initial:        &endpointDisco{controlKey: controlKey, tsmpKey: tsmpKey, tsmpActive: false},
			seen:           controlKey,
			wantResult:     true,
			wantTsmpActive: false,
		},
		{
			name:           "active-tsmp-key-seen",
			initial:        &endpointDisco{controlKey: controlKey, tsmpKey: tsmpKey, tsmpActive: true},
			seen:           tsmpKey,
			wantResult:     true,
			wantTsmpActive: true,
		},
		{
			name:           "inactive-tsmp-key-seen-swaps-to-tsmp-active",
			initial:        &endpointDisco{controlKey: controlKey, tsmpKey: tsmpKey, tsmpActive: false},
			seen:           tsmpKey,
			wantResult:     true,
			wantTsmpActive: true,
			wantCalled:     true,
		},
		{
			name:           "inactive-control-key-seen-swaps-to-control-active",
			initial:        &endpointDisco{controlKey: controlKey, tsmpKey: tsmpKey, tsmpActive: true},
			seen:           controlKey,
			wantResult:     true,
			wantTsmpActive: false,
			wantCalled:     true,
		},
		{
			name:           "unknown-key",
			initial:        &endpointDisco{controlKey: controlKey, tsmpKey: tsmpKey, tsmpActive: false},
			seen:           unknownKey,
			wantResult:     false,
			wantTsmpActive: false,
		},
		{
			name:           "only-control-key-seen",
			initial:        &endpointDisco{controlKey: controlKey},
			seen:           controlKey,
			wantResult:     true,
			wantTsmpActive: false,
		},
		{
			name:           "only-tsmp-key-seen",
			initial:        &endpointDisco{tsmpKey: tsmpKey, tsmpActive: true},
			seen:           tsmpKey,
			wantResult:     true,
			wantTsmpActive: true,
		},
		{
			// Hook fires once and replaces the struct (same tsmpKey, different controlKey),
			// forcing the first CAS to fail. The retry should still find tsmpKey as the
			// inactive key and succeed.
			name:    "CAS-retry-on-concurrent-update",
			initial: &endpointDisco{controlKey: controlKey, tsmpKey: tsmpKey, tsmpActive: false},
			seen:    tsmpKey,
			hook: func(de *endpoint) {
				de.disco.Store(&endpointDisco{
					controlKey: controlKey2,
					tsmpKey:    tsmpKey,
					tsmpActive: false,
				})
			},
			wantResult:     true,
			wantTsmpActive: true,
			wantCalled:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			de := &endpoint{c: &Conn{logf: func(msg string, args ...any) {}}}
			if tt.initial != nil {
				de.disco.Store(tt.initial)
			}

			if tt.wantCalled {
				de.trustBestAddrUntil = mono.Now().Add(time.Hour)
			}

			hookFired := false
			if tt.hook != nil {
				sawDiscoKeyTestHook = func() {
					if !hookFired {
						hookFired = true
						tt.hook(de)
					}
				}
				t.Cleanup(func() { sawDiscoKeyTestHook = nil })
			}

			epDisco, got := de.checkAndUpdateDiscoKey(tt.seen)

			if got != tt.wantResult {
				t.Errorf("sawDiscoKey().seen = %v, want %v", got, tt.wantResult)
			}
			if tt.wantNil && epDisco != nil {
				t.Errorf("sawDiscoKey().epDisco = %v, want %v", epDisco, nil)
			}
			if tt.hook != nil && !hookFired {
				t.Error("test hook was never called; CAS retry path not exercised")
			}
			if tt.initial != nil {
				if active := de.disco.Load(); active.tsmpActive != tt.wantTsmpActive {
					t.Errorf("after call: tsmpActive = %v, want %v", active.tsmpActive, tt.wantTsmpActive)
				}
			}
			if tt.wantCalled && de.trustBestAddrUntil != 0 {
				t.Errorf("de.trustBedstAddrUntil expected to be 0, got %d", de.trustBestAddrUntil)
			}
		})
	}
}

func TestUpdateDiscoKey(t *testing.T) {
	dk1 := key.NewDisco().Public()
	dk2 := key.NewDisco().Public()
	dk3 := key.NewDisco().Public()
	zero := key.DiscoPublic{}

	tests := []struct {
		name          string
		setup         func(de *endpoint)
		newKey        key.DiscoPublic
		wantChanged   bool
		wantActiveKey key.DiscoPublic
	}{
		{
			name:          "first-key-set",
			newKey:        dk1,
			wantChanged:   true,
			wantActiveKey: dk1,
		},
		{
			name: "same-control-key-no-change",
			setup: func(de *endpoint) {
				de.disco.Store(&endpointDisco{controlKey: dk1, controlShort: dk1.ShortString()})
			},
			newKey:        dk1,
			wantChanged:   false,
			wantActiveKey: dk1,
		},
		{
			name: "control-key-rotates-while-control-active",
			setup: func(de *endpoint) {
				de.disco.Store(&endpointDisco{controlKey: dk1, controlShort: dk1.ShortString()})
			},
			newKey:        dk2,
			wantChanged:   true,
			wantActiveKey: dk2,
		},
		{
			name: "control-key-rotates-while-tsmp-active",
			setup: func(de *endpoint) {
				de.disco.Store(&endpointDisco{
					controlKey: dk1, controlShort: dk1.ShortString(),
					tsmpKey: dk2, tsmpShort: dk2.ShortString(),
					tsmpActive: true,
				})
			},
			newKey:        dk3,
			wantChanged:   true,
			wantActiveKey: dk2,
		},
		{
			name: "control-key-cleared-tsmp-present",
			setup: func(de *endpoint) {
				de.disco.Store(&endpointDisco{
					controlKey: dk1, controlShort: dk1.ShortString(),
					tsmpKey: dk2, tsmpShort: dk2.ShortString(),
					tsmpActive: false,
				})
			},
			newKey:        zero,
			wantChanged:   true,
			wantActiveKey: dk2,
		},
		{
			name: "control-key-cleared-no-tsmp",
			setup: func(de *endpoint) {
				de.disco.Store(&endpointDisco{controlKey: dk1, controlShort: dk1.ShortString()})
			},
			newKey:        zero,
			wantChanged:   true,
			wantActiveKey: zero,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			de := &endpoint{c: &Conn{logf: func(msg string, args ...any) {}}}
			if tt.setup != nil {
				tt.setup(de)
			}

			if got := de.updateDiscoKey(tt.newKey); got != tt.wantChanged {
				t.Errorf("expected de.updateDiscoKey()=%t, got %t", tt.wantChanged, got)
			}
			if got := de.disco.Load().key(); got != tt.wantActiveKey {
				t.Errorf("active key: got %v, want %v", got, tt.wantActiveKey)
			}
		})
	}
}

func TestUpdateTSMPDiscoKey(t *testing.T) {
	dk1 := key.NewDisco().Public()
	dk2 := key.NewDisco().Public()
	dk3 := key.NewDisco().Public()
	zero := key.DiscoPublic{}

	tests := []struct {
		name          string
		setup         func(de *endpoint)
		newKey        key.DiscoPublic
		wantChanged   bool
		wantActiveKey key.DiscoPublic
	}{
		{
			name:          "first-tsmp-key-set",
			newKey:        dk1,
			wantChanged:   true,
			wantActiveKey: dk1,
		},
		{
			name: "same-tsmp-key-no-change",
			setup: func(de *endpoint) {
				de.disco.Store(&endpointDisco{tsmpKey: dk1, tsmpShort: dk1.ShortString(), tsmpActive: true})
			},
			newKey:        dk1,
			wantChanged:   false,
			wantActiveKey: dk1,
		},
		{
			name: "tsmp-key-rotates-while-tsmp-active",
			setup: func(de *endpoint) {
				de.disco.Store(&endpointDisco{tsmpKey: dk1, tsmpShort: dk1.ShortString(), tsmpActive: true})
			},
			newKey:        dk2,
			wantChanged:   true,
			wantActiveKey: dk2,
		},
		{
			name: "tsmp-key-set-while-tsmp-active",
			setup: func(de *endpoint) {
				de.disco.Store(&endpointDisco{
					controlKey: dk1, controlShort: dk1.ShortString(), tsmpActive: true,
					tsmpKey: dk2, tsmpShort: dk2.ShortString(),
				})
			},
			newKey:        dk3,
			wantChanged:   true,
			wantActiveKey: dk3,
		},
		{
			name: "tsmp-key-cleared-control-present",
			setup: func(de *endpoint) {
				de.disco.Store(&endpointDisco{
					controlKey: dk1, controlShort: dk1.ShortString(),
					tsmpKey: dk2, tsmpShort: dk2.ShortString(),
					tsmpActive: true,
				})
			},
			newKey:        zero,
			wantChanged:   true,
			wantActiveKey: dk1,
		},
		{
			name: "tsmp-key-cleared-no-control",
			setup: func(de *endpoint) {
				de.disco.Store(&endpointDisco{tsmpKey: dk2, tsmpShort: dk2.ShortString(), tsmpActive: true})
			},
			newKey:        zero,
			wantChanged:   true,
			wantActiveKey: zero,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			de := &endpoint{c: &Conn{logf: func(msg string, args ...any) {}}}
			if tt.setup != nil {
				tt.setup(de)
			}

			if got := de.updateTSMPDiscoKey(tt.newKey); got != tt.wantChanged {
				t.Errorf("expected de.updateDiscoKey()=%t, got %t", tt.wantChanged, got)
			}
			if got := de.disco.Load().key(); got != tt.wantActiveKey {
				t.Errorf("active key: got %v, want %v", got, tt.wantActiveKey)
			}
		})
	}
}

// TestUpdateFromNodeChangedActiveDisco verifies that updateFromNode resets
// trustBestAddrUntil (via changedActiveDisco) when the control disco key
// changes, and leaves it untouched when the key is unchanged.
func TestUpdateFromNodeChangedActiveDisco(t *testing.T) {
	dk1 := key.NewDisco().Public()
	dk2 := key.NewDisco().Public()

	tests := []struct {
		name           string
		initialControl key.DiscoPublic
		netmapKey      key.DiscoPublic
		wantCalled     bool
	}{
		{
			name:           "control-key-changes-fires",
			initialControl: dk1,
			netmapKey:      dk2,
			wantCalled:     true,
		},
		{
			name:           "control-key-unchanged-no-fire",
			initialControl: dk1,
			netmapKey:      dk1,
			wantCalled:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			de := &endpoint{c: &Conn{logf: func(string, ...any) {}}}
			de.disco.Store(&endpointDisco{controlKey: tt.initialControl, controlShort: tt.initialControl.ShortString()})

			// Set a future trustBestAddrUntil so we can detect if it was zeroed.
			de.trustBestAddrUntil = mono.Now().Add(time.Hour)
			before := de.trustBestAddrUntil

			de.updateFromNode(
				(&tailcfg.Node{Key: de.publicKey, DiscoKey: tt.netmapKey}).View(),
				false, false)

			addrUntil := de.trustBestAddrUntil
			if tt.wantCalled && addrUntil != 0 {
				t.Errorf("trustBestAddrUntil not reset: got %v, want 0", addrUntil)
			}
			if !tt.wantCalled && addrUntil != before {
				t.Errorf("trustBestAddrUntil unexpectedly changed from %v to %v", before, addrUntil)
			}
		})
	}
}

func TestChangedActiveDiscoLocked(t *testing.T) {
	t.Run("resets-trustBestAddrUntil", func(t *testing.T) {
		de := &endpoint{}
		de.trustBestAddrUntil = mono.Now().Add(time.Hour)
		de.mu.Lock()
		de.changedActiveDiscoLocked()
		de.mu.Unlock()
		if de.trustBestAddrUntil != 0 {
			t.Errorf("trustBestAddrUntil not reset to zero, got %v", de.trustBestAddrUntil)
		}
	})

	t.Run("invalidates-disco-path-fields", func(t *testing.T) {
		de := &endpoint{}
		de.lastSendExt = mono.Now()
		de.lastFullPing = mono.Now()
		de.lastUDPRelayPathDiscovery = mono.Now()
		de.isWireguardOnly = true // avoid sentPing iteration, which requires de.c
		de.mu.Lock()
		de.changedActiveDiscoLocked()
		de.mu.Unlock()
		if de.lastSendExt != 0 {
			t.Error("lastSendExt not reset to zero")
		}
		if de.lastFullPing != 0 {
			t.Error("lastFullPing not reset to zero")
		}
		if de.lastUDPRelayPathDiscovery != 0 {
			t.Error("lastUDPRelayPathDiscovery not reset to zero")
		}
	})
}
