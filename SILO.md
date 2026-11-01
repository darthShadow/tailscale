# Silo Tailscale Fork

Module: `tailscale.com`. Base: Tailscale `v1.104.2`, commit
`e26db7a5797683ec99ad1516c40b628c7f2dfd71`. Go: `1.27.3`.
The fork tag format is `<upstream-version>-silo.<n>`; the first release target
is `v1.104.2-silo.1`.

All behavior changes are opt-in. Default `magicsock.Options` and a
`derphttp.Client` without `StreamDial` retain upstream behavior.

| Patch | Intent | Tests | Source |
|---|---|---|---|
| T1 | Decide each non-disco DERP data send with `Options.RelayedDataAllowed`; nil permits upstream traffic. Count refused copies through `DERPDataSuppressed()`. Disco and direct UDP stay independent. | `TestRelayedDataAllowedPerPeer` | `spike/bench/direct/magicsock-derp-data.patch`, ported from a connection-wide flag to the per-peer callback |
| T2 | Apply `Options.QUICDontFragment` before exposing each UDP socket, including rebinds; report the contract with `SupportsDF()`. | `TestQUICDontFragmentOnRebind` (Linux) | `spike/bench/direct/magicsock-derp-data.patch` |
| T5 | Dial authenticated DERP streams through `Client.StreamDial` and `Options.SignalingRegions`. Own streams through handshake failure, cancellation and Close; use the connect watchdog. | `TestStreamDialEveryConnect`, `TestSignalingRegionDial` | `spike/bench/direct/worker-signal.patch`, ported from `WebSocketDial` and a setter to construction options |
| T7 | Cap CallMeMaybe endpoints only when `MaxCallMeMaybeEndpoints` is positive. Export `CapEndpoints` for the same registration selection: STUN and port-mapped addresses, IPv4, then IPv6, with stable order in each group. | `TestCallMeMaybeEndpointCap`, `TestCapEndpointsOrder` | New; spec C-F9 |

T3 (ECN), T4 (UDP buffer sizing) and T6 (patch-level constants) are not part
of this fork. Upstream's UDP buffer settings stay in place. This fork adds no
environment-variable reads or research counters.

The source patches target spike pin `98f7c4241ee2`; this fork ports them to the
stable base above, which has no WebRTC path.

The fork uses upstream `github.com/tailscale/wireguard-go`
`v0.0.0-20260928213032-417aef361226`, commit
`417aef361226c869ab29e15fe3539b01173c4719`. It carries no wireguard-go
replacement.

Run the named tests with `go test` in `./wgengine/magicsock`
and `./derp/derphttp`. The DF test requires Linux and real UDP sockets;
the signaling tests use in-memory pipes. The upstream suite,
`go vet ./...` and `go build ./...` remain release checks.

The upstream BSD-3-Clause license and copyright notices remain in place.
