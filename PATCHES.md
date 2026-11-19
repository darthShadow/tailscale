# Tailscale Patches

Module: `tailscale.com`. Base: Tailscale `v1.104.2`, commit
`e26db7a5797683ec99ad1516c40b628c7f2dfd71`. Go: `1.27.3`.

This fork carries the changes that shunpike needs from Tailscale's
magicsock and DERP client. Shunpike connects peers over direct UDP paths
and serves HTTP/3 across them with quic-go. It uses DERP only to signal
those connections, and it keeps relayed data denied unless the embedding
application permits the peer.

## Tags and History

The fork tag format is `<upstream-version>-shunpike.<n>`.

- `v1.104.2-shunpike.1`, the first release, points at the earlier,
  finer history: one commit per patch and follow-up fix.
- `v1.104.2-shunpike.2` is the first tag on the consolidated history,
  which groups the same patches into three commits by area. Its Go code
  is the same as `v1.104.2-shunpike.1`; only this file and the fork CI
  workflow differ.

## Patch Inventory

Transport policy changes are opt-in. Default `magicsock.Options` and a
`derphttp.Client` without `StreamDial` retain upstream transport policy.
T9 fixes the bind receive shutdown contract for all callers.

Each patch lives in one of these commits:

- DERP: `feat(derp): authenticate signaling streams and gate relayed data per peer`
- UDP path: `feat(magicsock): keep direct UDP paths usable for QUIC and quick to recover`
- Bind receive lifetime: `fix(magicsock): closed bind receives never read a replaced socket`

| Patch | Commit | Why | Intent | Tests |
|---|---|---|---|---|
| T1 | DERP | Shunpike keeps data on direct paths and denies relayed data unless the application permits the peer. | Decide each non-disco DERP data send with `Options.RelayedDataAllowed`; nil permits upstream traffic. Count refused copies through `DERPDataSuppressed()`. Disco and direct UDP stay independent. | `TestRelayedDataAllowedPerPeer` |
| T2 | UDP path | QUIC path MTU probes must not be fragmented, and shunpike keeps path MTU discovery off unless magicsock reports DF. | Apply `Options.QUICDontFragment` before exposing each UDP socket, including rebinds; report the contract with `SupportsDF()`. | `TestQUICDontFragmentOnRebind` (Linux) |
| T5 | DERP | Shunpike's signaling service serves DERP over a WebSocket whose credentials the embedding application supplies. | Dial authenticated DERP streams through `Client.StreamDial` and `Options.SignalingRegions`. Own streams through handshake failure, cancellation and Close; use the connect watchdog. A region with no nodes returns an error instead of panicking. | `TestStreamDialEveryConnect`, `TestSignalingRegionDial` |
| T7 | UDP path | Shunpike's coordination protocol accepts at most 64 endpoints per registration or host, and registrations and CallMeMaybe messages should carry the same ones. | Cap CallMeMaybe endpoints only when `MaxCallMeMaybeEndpoints` is positive. Export `CapEndpoints` for the same registration selection: STUN and port-mapped addresses, IPv4, then IPv6, with stable order in each group. | `TestCallMeMaybeEndpointCap`, `TestCapEndpointsOrder` |
| T8 | UDP path | With relayed data denied, a lost direct path stops data, so shunpike needs the path back quickly and a signal to probe its QUIC connections when it is. | Opt in with `Options.DirectPathRecovery` to retain the best address while revalidating after new peer endpoints, local rebinds or data-active path loss. Keep one freshness boundary per recovery episode and reject stale pongs for path selection. Announce changed local endpoints to data-active peers and peers in the first 5 s of recovery; use 500 ms heartbeats only during data activity. Run `DirectPathValidatedFunc` asynchronously when a fresh direct pong restores trust. A CallMeMaybe omission clears both advertisement marks and keeps the current best address; recovery never deletes the best address, and ping timeouts still clear a dead path. | `TestDirectPathRecoveryNewEndpoint`, `TestDirectPathRecoveryAnnouncesEndpoints`, `TestDirectPathRecoveryLiveness`, `TestDirectPathRecoverySilentRemap` |
| T9 | Bind receive lifetime | Shunpike reads every QUIC packet through one bind's receive functions, so a stale receive function would take the live bind's packets. | End each bind Open's UDP receive lifetime before Close closes sockets. Coordinate each socket snapshot and replacement retry with that lifetime; reopening leaves old receive functions closed. Preserve open-bind retries and DERP sentinel draining. | `TestBindReceiveLifetime` |

T3 (ECN), T4 (UDP buffer sizing) and T6 (patch-level constants) are not part
of this fork. Upstream's UDP buffer settings stay in place. This fork adds no
environment-variable reads or research counters.

## Dependencies

The fork uses upstream `github.com/tailscale/wireguard-go`
`v0.0.0-20260928213032-417aef361226`, commit
`417aef361226c869ab29e15fe3539b01173c4719`. It carries no wireguard-go
replacement.

## Checks

Run the named tests with `go test` in `./wgengine/magicsock`
and `./derp/derphttp`. The DF test requires Linux and real UDP sockets;
the signaling tests use in-memory pipes. The upstream suite,
`go vet ./...` and `go build ./...` remain release checks.

## License

The upstream BSD-3-Clause license and copyright notices remain in place.
