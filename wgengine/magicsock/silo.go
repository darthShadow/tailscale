// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

// DERPDataSuppressed counts non-disco DERP copies refused by RelayedDataAllowed.
func (c *Conn) DERPDataSuppressed() int64 { return c.derpDataSuppressed.Load() }
