// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"context"
	"net"

	"tailscale.com/tailcfg"
)

// SignalingRegion supplies a transport for a region's DERP stream.
type SignalingRegion struct {
	// Dial returns a stream that speaks DERP from its first byte. It owns
	// transport authentication and any HTTP upgrade and must honor ctx.
	// An error fails this attempt; magicsock's normal reconnect backoff applies.
	Dial func(ctx context.Context, url string) (net.Conn, error)
}

// DERPDataSuppressed counts non-disco DERP copies refused by RelayedDataAllowed.
func (c *Conn) DERPDataSuppressed() int64 { return c.derpDataSuppressed.Load() }

// SupportsDF reports whether the socket creation callback requires DF,
// including on replacement sockets after a rebind.
func (c *Conn) SupportsDF() bool { return c.quicDontFragment != nil }

// CapEndpoints selects at most max endpoints, with STUN and port-mapped
// addresses first, then IPv4, then IPv6. Order within each group is stable.
// It does not mutate eps. A non-positive max returns no endpoints.
func CapEndpoints(eps []tailcfg.Endpoint, max int) []tailcfg.Endpoint {
	if max <= 0 {
		return nil
	}
	selected := make([]tailcfg.Endpoint, 0, min(max, len(eps)))
	for group := 0; group < 3; group++ {
		for _, ep := range eps {
			priority := 2
			switch ep.Type {
			case tailcfg.EndpointSTUN, tailcfg.EndpointSTUN4LocalPort, tailcfg.EndpointPortmapped:
				priority = 0
			default:
				if ep.Addr.Addr().Is4() {
					priority = 1
				}
			}
			if priority == group {
				selected = append(selected, ep)
				if len(selected) == max {
					return selected
				}
			}
		}
	}
	return selected
}
