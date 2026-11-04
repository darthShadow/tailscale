# Tailscale Patches

Module: `tailscale.com`. Base: Tailscale `v1.104.2`, commit
`e26db7a5797683ec99ad1516c40b628c7f2dfd71`. Go: `1.27.3`.
The fork tag format is `<upstream-version>-patch.<n>`; the first release target
is `v1.104.2-patch.1`.

All behavior changes are opt-in. Default `magicsock.Options` and a
`derphttp.Client` without `StreamDial` retain upstream behavior.

| Patch | Intent | Tests |
|---|---|---|
| T1 | Decide each non-disco DERP data send with `Options.RelayedDataAllowed`; nil permits upstream traffic. Count refused copies through `DERPDataSuppressed()`. Disco and direct UDP stay independent. | `TestRelayedDataAllowedPerPeer` |
| T2 | Apply `Options.QUICDontFragment` before exposing each UDP socket, including rebinds; report the contract with `SupportsDF()`. | `TestQUICDontFragmentOnRebind` (Linux) |
| T5 | Dial authenticated DERP streams through `Client.StreamDial` and `Options.SignalingRegions`. Own streams through handshake failure, cancellation and Close; use the connect watchdog. | `TestStreamDialEveryConnect`, `TestSignalingRegionDial` |
| T7 | Cap CallMeMaybe endpoints only when `MaxCallMeMaybeEndpoints` is positive. Export `CapEndpoints` for the same registration selection: STUN and port-mapped addresses, IPv4, then IPv6, with stable order in each group. | `TestCallMeMaybeEndpointCap`, `TestCapEndpointsOrder` |
| T8 | Opt in with `Options.DirectPathRecovery` to retain the best address while revalidating after new peer endpoints, local rebinds or data-active path loss. Keep one freshness boundary per recovery episode and reject stale pongs for path selection. Announce changed local endpoints to data-active peers and peers in the first 5 s of recovery; use 500 ms heartbeats only during data activity. Run `DirectPathValidatedFunc` asynchronously when a fresh direct pong restores trust. A CallMeMaybe omission clears both advertisement marks and keeps the current best address; ping timeouts still clear a dead path. | `TestDirectPathRecoveryNewEndpoint`, `TestDirectPathRecoveryAnnouncesEndpoints`, `TestDirectPathRecoveryLiveness`, `TestDirectPathRecoverySilentRemap` |

T3 (ECN), T4 (UDP buffer sizing) and T6 (patch-level constants) are not part
of this fork. Upstream's UDP buffer settings stay in place. This fork adds no
environment-variable reads or research counters.

The fork uses upstream `github.com/tailscale/wireguard-go`
`v0.0.0-20260928213032-417aef361226`, commit
`417aef361226c869ab29e15fe3539b01173c4719`. It carries no wireguard-go
replacement.

Run the named tests with `go test` in `./wgengine/magicsock`
and `./derp/derphttp`. The DF test requires Linux and real UDP sockets;
the signaling tests use in-memory pipes. The upstream suite,
`go vet ./...` and `go build ./...` remain release checks.

The upstream BSD-3-Clause license and copyright notices remain in place.
