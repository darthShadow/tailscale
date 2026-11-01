// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"context"
	"net"
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
