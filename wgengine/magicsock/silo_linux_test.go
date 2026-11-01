// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestQUICDontFragmentOnRebind(t *testing.T) {
	calls := map[string]int{}
	control := func(network, address string, raw syscall.RawConn) error {
		calls[network]++
		var sockErr error
		if err := raw.Control(func(fd uintptr) {
			level, opt, value := unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DO
			if network == "udp6" {
				level, opt = unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER
			}
			sockErr = unix.SetsockoptInt(int(fd), level, opt, value)
		}); err != nil {
			return err
		}
		return sockErr
	}
	c := newSiloConn(t, Options{QUICDontFragment: control})
	if !c.SupportsDF() {
		t.Fatal("SupportsDF is false with DF control")
	}
	for i := 0; i < 2; i++ {
		if calls["udp4"] <= i {
			t.Fatalf("rebind %d: IPv4 DF calls = %d, want > %d", i, calls["udp4"], i)
		}
		for _, socket := range []struct {
			c          *RebindingUDPConn
			level, opt int
		}{
			{&c.pconn4, unix.IPPROTO_IP, unix.IP_MTU_DISCOVER},
			{&c.pconn6, unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER},
		} {
			raw, err := socket.c.SyscallConn()
			if err != nil {
				t.Fatal(err)
			}
			var got int
			var sockErr error
			if err := raw.Control(func(fd uintptr) { got, sockErr = unix.GetsockoptInt(int(fd), socket.level, socket.opt) }); err != nil {
				t.Fatal(err)
			}
			if sockErr != nil || got != unix.IP_PMTUDISC_DO {
				t.Fatalf("DF after bind %d: got %d err=%v, want %d", i, got, sockErr, unix.IP_PMTUDISC_DO)
			}
		}
		if i == 0 {
			before4, before6 := calls["udp4"], calls["udp6"]
			if err := c.rebind(dropCurrentPort); err != nil {
				t.Fatal(err)
			}
			if calls["udp4"] <= before4 || calls["udp6"] <= before6 {
				t.Fatalf("DF calls unchanged on rebind: %v", calls)
			}
		}
	}
	if plain := newSiloConn(t, Options{}); plain.SupportsDF() {
		t.Fatal("default SupportsDF is true")
	}
}
