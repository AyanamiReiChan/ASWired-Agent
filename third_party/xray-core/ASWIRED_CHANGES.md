# ASWired core integration

Upstream: https://github.com/XTLS/Xray-core, Go module version **v1.260327.0**. Upstream MPL-2.0 applies to this directory; see LICENSE. Copied runtime source includes the generated protobufs and embedded browser dialer HTML. Test fixtures, caches and compiled binaries are excluded.

Original ASWired modifications:

- `common/aswired/hooks.go`: Agent-installed admission/transfer callbacks, preserving proxy user identity and per-session release.
- `common/aswired/hooks.go` and `proxy/proxy.go`: optional observer counts actual limited/unlimited download bytes passing through the Linux Vision splice branch. It does not record payloads or change billing counters. Agent reports process-scoped totals under `vision_splice`.
- `app/dispatcher/aswired.go` and `default.go`: enforce the Agent's shared user policy for normal buffered traffic, both directions and Dispatch/DispatchLink; keep the existing outer statistics wrapper.
- `proxy/proxy.go`: policy-controlled Vision raw transfers use bounded `TCPConn.ReadFrom(io.LimitReader(...))` chunks. Go's Linux TCP implementation can use splice through LimitedReader. The callback shares the same token bucket as buffered traffic. Unconfigured or unlimited authenticated users retain upstream's direct path after atomically registering that raw transfer. Activating a policy closes those registered unlimited raw sessions so reconnect cannot bypass the new limits; removing policy restores the direct path at the next chunk boundary.
- `proxy/freedom/freedom.go` and `proxy/vless/encoding/encoding.go`: propagate explicit download/upload direction to raw transfers. Dispatcher links mark their corresponding direction. Policies may select download-only rate enforcement; disabled/admission checks still apply to both directions.

This is an original ASWired integration, not a copy of 妙妙屋's private fork. No licensing server or commercial feature gate is present. It does not add Snell or AnyTLS. The splice path requires Linux runtime verification: successful Windows tests and Linux cross-compilation do not prove zero-copy operation or all Vision combinations. Chunking adds scheduling overhead and permits a bounded in-flight chunk before a reduced limit is observed.

Limits apply to authenticated proxy sessions sharing a configured user ID on this physical Agent. They are not device counts. Missing mappings remain separate email identities until the controller supplies the group. Runtime policy changes reassign existing connection counts. Already controlled sessions remain connected; activation on an unlimited splice transfer closes that transfer as described above. Disabled policies explicitly cancel tracked sessions and close their inbound connection; protocol user removal alone does not perform that policy operation. Revoked credentials must remain mapped to a disabled policy instead of being silently omitted.
