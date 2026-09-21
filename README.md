# ASWired Agent

Go management Agent with an embedded Xray core and encrypted controller connection. Host monitoring is provided exclusively by Komari; install and bind its Agent separately. Prebuilt Linux amd64/arm64 artifacts and complete installation instructions are published in [ASWired-Release](https://github.com/AyanamiReiChan/ASWired-Release). It contains no commercial license check or paid feature switch.

## Build and run

Requires Go 1.27 or later.

```sh
go build -o bin/aswired-agent ./cmd/aswired-agent
cp agent.example.json agent.json
# Fill in the per-server installation values supplied by ASWired Server.
./bin/aswired-agent -config agent.json -check
./bin/aswired-agent -config agent.json
```

The master public key is pinned. Server Token authenticates reports over the encrypted WebSocket channel. User JWTs never enter Agent configuration. Connection modes are `websocket`, `http` (controller-to-Agent encrypted RPC), `pull` (Agent-to-controller encrypted polling), and `auto`. Auto tries WebSocket first, opens the HTTP management listener on failure, and starts polling after a 10-second direct-connect window if HTTP is inactive; it retries WebSocket after a one-minute fallback window. WebSocket and Pull modes do not open a management listener. HTTP/Auto use `listen_address` (default `0.0.0.0:23889`); the controller must be able to reach that address/port, or its configured `agentUrl`. The controller sends authenticated connection settings to upgraded Agents, which persist them before switching; failed persistence retains the current mode. Existing Agents must be upgraded to support selection changes. The versioned wire protocol is ASWired-specific.


For local diagnostics use `-observe` to print real host metrics, `-standalone` to run the core without controller connection, or `-command request.json` to execute a local management command. No command shell is exposed by the remote API.

## Implemented operations

| Action | Actual operation |
| --- | --- |
| `core.status/start/stop/restart` | Same-process embedded core |
| `core.config.get/test/apply/history/restore` | Xray JSON validation, restricted writes, snapshots, actual restart and previous-config recovery |
| `core.users.sync` | VLESS/VMess/Trojan/Hysteria2/traditional AEAD Shadowsocks actual user-manager changes, persisted configuration |
| `core.stats` | Non-resetting Xray counters with persisted embedded-core generation |
| `core.policy.apply/connections` | Original embedded shared-user rate/connection/IP controls and live tracked connections |
| `agent.report` | Core state, task results and Xray accounting; host monitoring uses Komari |
| `server.scan/ports.check` | Installed binary/interface scan; real TCP/UDP bind check |
| `network.latency` | Real TCP connect samples; connection-failure percentage is not ICMP packet loss |
| `certificate.deploy` | Certificate/private-key pair validation, validity check and immutable version paths |
| `site.apply/status` | Nginx config test and real reload; failure returns error |
| `federation.identity/grant/execute` | Persistent Agent encryption identity, signed owner ACL and opaque scoped consumer operations |
| `network.forward.apply/status` | Native TCP/UDP listeners, actual per-client relays, counters and persisted rules |
| `network.wireguard.apply/remove/status` | Supplied WireGuard configuration, Linux interface lifecycle, rollback and private-key-safe status |
| `network.warp.apply/remove/status` | The same managed tunnel lifecycle using user-supplied WARP account keys/endpoint |
| `network.quality` | TCP connect or ICMP echo samples, latency/jitter and method-specific failure rates |
| `mihomo.config.apply/get`, `mihomo.users.sync` | Optional separate AnyTLS/Snell service configuration and verified auxiliary process reload |
| `mihomo.status/start/stop/restart` | Actual auxiliary process lifecycle, loopback authenticated API and persistent recovery |
| `agent.update` | Pinned artifact validation, authenticated restart confirmation and automatic Linux worker rollback |
| `identity.rotate` | Persist new Server/Agent Tokens before the next report uses them |

`core.users.sync` receives `{ "inbound": "tag", "users": [{"email":"user/instance", "id":"UUID"}] }`. Trojan uses `password` in place of `id`; Hysteria2 uses `auth`; traditional Shadowsocks uses `password` and `method` (AES-128/256-GCM, ChaCha20/XChaCha20-Poly1305). SS2022 requires a different credential model and is explicitly rejected by this adapter. An explicit empty users array removes the owner's managed users from that inbound. Registered consumer namespaces are preserved by owner user synchronization and full configuration updates. The core configuration persists successful changes for restart recovery.

`core.policy.apply` receives a full `policies` array, with `user_id`, `emails`, `bytes_per_second`, `connection_limit`, `ip_limit`, `disabled`, and optional `direction: "download" | "both"`. Rate zero is unlimited. The default is both directions; download mode charges only traffic sent to the client. All credentials under a user share one physical-node budget. Connection/IP reductions reject new admissions without closing existing ones. A disabled policy cancels tracked sessions and closes their inbound connection in either direction; keep revoked credentials explicitly mapped to a disabled policy so they never revert to an unconfigured identity. See the [core modification record](third_party/xray-core/ASWIRED_CHANGES.md).

Reports preserve missing metrics and collection errors. Interface cumulative traffic is not user billing. Xray counters remain raw and are never reset by a read. The controller must distinguish core generations and handle counter resets. Command duplicate results are remembered in process memory for up to 2,048 IDs and 32 MiB. Large results are split between reports to stay below the encrypted packet limit, and only acknowledged prefixes are removed; an individual oversized result explicitly fails. Crash-safe exactly-once command execution or zero-loss offline accounting is not claimed.

When a user has no active rate/connection/IP/disabled policy, Linux raw transfers retain the original unbounded `TCPConn.ReadFrom` splice path. A transfer entering this path registers with the policy controller atomically. Activating a policy closes only the registered unlimited raw sessions so reconnection applies the new limits; already bounded sessions update their policy in place. Removing a policy restores the original fast path at the next bounded-transfer boundary. This avoids leaving an old unlimited raw session outside a newly applied limit. Linux splice execution still requires real Linux verification.

## Online Agent updates

On Linux, start the service with `aswired-agent -supervise -config /etc/aswired-agent/agent.json`. The supervisor runs the active worker from `<data_dir>/agent-update/current` under the same service identity; it does not grant additional privileges. Newly generated installation commands enable this mode. Existing services must be updated once before they advertise `agent_update`.

The controller accepts an explicit version, SHA256 and HTTPS URL (loopback HTTP is permitted for isolated tests). The worker stages and verifies the artifact, and waits for an authenticated acknowledgement of its task result before restarting. A replacement must authenticate to the pinned controller within 90 seconds. Startup failure, missing confirmation or interrupted promotion restores the previous worker. A successful task means staging succeeded; the final `agentUpdate.status` must be `completed`. Configuration and historical accounting are retained, but active proxy connections reconnect. The root-owned bootstrap binary remains the supervisor; `deploy/manage.sh` uses the effective worker when saving a rollback version.

`observation.vision_splice` reports limited and unlimited download bytes observed in the actual Linux splice branch for the current process. These are diagnostics, not billable counters or a claim that every client path uses splice.

## Deployment

- Linux native: `sh deploy/install.sh BINARY CONFIG EXACT_VERSION SHA256` verifies the binary/configuration and installs systemd/OpenRC units or a nohup/rc.local fallback. The script is provided but is not run by the build; boot behavior of the fallback must be verified on the target distribution.
- Docker: `deploy/compose.yaml` uses host networking and embedded mode. Mount only the required configuration and data. Install Komari Agent separately for host monitoring.
- Windows/macOS: embedded runtime is supported by source. Linux service and Nginx lifecycle require corresponding installed tools. The separate home speed-test program supports Windows, Linux and macOS builds.

## Verification and remaining work

`go test ./...` verifies a real local SOCKS-to-HTTP proxy, same PID, invalid-config handling, restart/history, dynamic VLESS user persistence, authenticated VLESS traffic through the rate hook, certificate validation, occupied ports, Komari-only monitoring boundaries, encrypted WebSocket, replay rejection, duplicate command handling, and shared policy behavior.

With `ASWIRED_TEST_MIHOMO` set to the pinned v1.19.31 artifact, `TestRealMihomoHysteriaAndShadowsocksDynamicUsers` additionally starts real Hysteria2 QUIC/TLS and traditional Shadowsocks inbounds. Both independent credentials transfer actual HTTP data and have distinct Xray counters under the shared rate policy. Hot addition/removal keeps the core generation unchanged; a removed password cannot reach the target while the retained account still works. The self-signed certificate and disabled certificate verification are confined to that loopback fixture.

Linux splice/REALITY combinations, container measurements, local lifecycle scripts and WireGuard kernel lifecycle still require deployment tests. This Agent does not implement ACME issuance, DDNS provider APIs or automatic WARP account registration. Some of those workflows may be supplied by the controller. Unsupported Agent actions return `unsupported`; they do not return a simulated success.

### Mode migration and local releases

Only embedded Xray is supported. External Xray service control, gRPC clients, related configuration fields and runtime mode migration have been removed. Explicit external configuration and older external runtime-mode.json files fail validation; they are not silently converted. Maintain the old service separately, then reinstall with a fresh embedded configuration. Controller-generated Linux installation commands use scoped 30-minute tickets and SHA-256-checked artifacts hosted by the controller; see ASWired-Server/deploy/agent-installation.md.

Build `go build -o bin/aswired-maintain ./cmd/aswired-maintain`. The local maintenance CLI verifies an explicitly selected binary with `-verify /absolute/candidate -version 1.2.3 -sha256 HEX`, or downloads and verifies it with `-url https://YOUR_RELEASE_BINARY -output /absolute/new-file -version 1.2.3 -sha256 HEX`. Only an exact version and SHA256 are accepted. A checksum mismatch prevents executing even the binary's version command. This is a raw executable artifact, not an archive or a moving latest-release URL.

Set `ASWIRED_MAINTAIN` to that tool's path, then use `sh deploy/manage.sh install|upgrade agent|home BINARY CONFIG EXACT_VERSION SHA256`. `rollback agent|home` verifies and restores the previous saved executable/configuration. `uninstall agent|home` stops and removes that selected program while retaining configuration, data and independent system resources. Upgrades check the new process/service and try the previous executable if startup fails. They still require the operator/controller to verify reconnection and actual proxy or speed-test behavior; binary rollback does not guarantee compatibility with changed data formats. Script syntax is checked, but these scripts have not been executed against a real Linux init system in this workspace.

## Forwarding and network operations

`network.forward.apply` takes `{"rules":[{"id":"hop1","protocol":"tcp","listen":"127.0.0.1:9001","target":"127.0.0.1:9002"}]}`. TCP and UDP are supported; an empty array removes the managed rules. Every new listener must bind before the new desired state is saved. An occupied port leaves the old rules intact. TCP sessions already accepted retain their previous target when a rule changes; deleting a rule closes its sessions. UDP sessions are bounded to 1,024 per rule and expire after `udp_idle_seconds` (5–600, default 60). The controller builds multi-hop chains from these local hops. Forward byte counters describe socket traffic and are not automatically a user's billing ledger.

`network.wireguard.apply` and `network.warp.apply` accept `id`, `private_key`, `addresses` (CIDRs), optional `listen_port`/`mtu`/`route_table`, and `peers` with `public_key`, optional `preshared_key`, `endpoint`, `allowed_ips` and `persistent_keepalive`. Only supplied credentials are used; account registration, upgrade and cancellation are not fabricated. Each interface name is derived from its managed ID. Keys are written to mode-0600 configuration files, never process arguments or returned status. Generated files contain no script hooks or DNS modification commands. The defaults use MTU 1420 and isolated routing table 51820; explicitly arrange the intended business routing to that table. Creating the interface alone does not prove WARP Internet egress or replace the host's default route.

WireGuard operations use locally configured `wg_quick_binary`, `wg_binary` and `ip_binary`; defaults are `wg-quick`, `wg` and `ip`. The commands follow the official [wg interface](https://man7.org/linux/man-pages/man8/wg.8.html) and [wg-quick configuration](https://man7.org/linux/man-pages/man8/wg-quick.8.html). Activation checks the actual interface public key. Failed replacement restores the prior configuration and tries to rebuild the prior interface, reporting rollback failure explicitly. Agent startup restores enabled tunnels; stopping the Agent leaves kernel interfaces in place. `status` returns public peer endpoints, latest handshake times, raw byte counters and link state. `remove` removes only the identified owned interface and its saved keys, without pretending to unregister an account.

`network.quality` takes `method: "tcp" | "icmp"`, `target`, optional `count` (1–10) and `timeout_ms` (100–5000). TCP targets use `host:port`; ICMP uses an IP or hostname. ICMP first opens a raw socket, then falls back to an unprivileged ICMP echo (ping) socket if raw sockets are unavailable. Echo replies must match the source, random 128-bit payload and sample sequence; raw sockets also match the identifier, which ping sockets may rewrite in the kernel. If both socket types are unavailable, the result is `unsupported`. On Linux, permit the Agent's group through `net.ipv4.ping_group_range` or grant the Agent `CAP_NET_RAW`; container and service restrictions must also allow the chosen socket type. Only ICMP results label missing echo replies as packet loss; TCP results report connection failure percentage.

Tests verify real loopback TCP/UDP payload forwarding, failed-listener rollback, process restart persistence and real TCP reachability. WireGuard command execution, partial activation cleanup, old-interface recovery, key isolation and restart restoration use an injected command fixture; ICMP reply matching and permission rejection use socket fixtures. Those tests do not alter the development machine's routes or claim Linux kernel interoperability has been exercised.

## Scoped Agent federation

The `aswired-agent-share-v1` protocol terminates management encryption at the consuming controller and Agent. The owning controller relays an opaque envelope. An Ed25519 owner-signed ACL binds the Agent's persistent X25519 identity, the consumer's controller public key, a reserved namespace, explicit inbound aliases, allowed actions, revision and expiry. The Agent pins the owner signing key through its existing authenticated owner connection. The consumer proves possession of its own static key inside each encrypted request; knowing a consumer public key or relay token is insufficient.

The scoped actions are `status.get`, `inbound.users.get`, `inbound.users.sync` and `stats.get`. The consumer sees only its users/statistics and can replace only its namespace within explicitly shared inbounds. Global configuration, core lifecycle, host administration and arbitrary commands cannot be granted. Revoking management access retains existing inbounds and credentials. The owner rejects further forwarding immediately, including while the Agent is offline, and checks queued jobs again before dispatch. The Agent rejects revoked or older revisions after receiving the updated ACL. An operation already dispatched can finish; revocation does not undo a completed user change.

Owner reconciliation preserves consumer users in retained inbounds. Removing an entire owning inbound still removes that service. Namespace reservation persists after revocation to prevent identity reuse. The owner can administer the host and core; envelope encryption does not protect core configuration at rest from a privileged host administrator.

The Agent persists encrypted replies keyed by share/request ID and rejects another ciphertext under the same ID. The consumer persists its temporary channel private key and counters only in its encrypted controller database, then deletes them after decrypting the result. This permits recovery from a lost relay acknowledgement without reusing an AES-GCM nonce for another request. A crash exactly between a user mutation and durable reply persistence remains an uncertain result; exactly-once execution across that boundary is not claimed.

## Optional AnyTLS and Snell service

Set local Agent `mihomo_binary`, `mihomo_version` and `mihomo_sha256` to a separately installed, fixed-version executable. No mihomo source is linked or copied into the MIT adapter. The exact executable checksum is checked before execution. Current real-client validation uses v1.19.31 with **AnyTLS and Snell v3/v4 TCP**; other Snell versions and UDP are rejected. This verifies mihomo client/server interoperability, not certification against proprietary Snell clients.

`mihomo.config.apply` accepts `{listeners:[{name,type,listen,port,users:[{email,password,bridge:{port,id}}],certificate?,private_key?,version?,padding_scheme?}]}`. AnyTLS needs a certificate/key pair as PEM or paths within managed `data/certificates`. Each username maps to its own **loopback VLESS** outbound and Xray user identity. Snell has one PSK per listener, so multiple users require distinct ports. Unknown traffic is rejected instead of bypassing the bridge. Empty users disable that listener. `mihomo.users.sync` receives `{inbound:name,users:[...]}`.

Every candidate passes binary verification, strict validation, mihomo `-t` and port preflight. Applying a candidate restarts the auxiliary process, checks its private API, registered outbounds and listeners, persists only on success, and attempts to restore the previous process on failure. Auxiliary sessions reconnect; the Xray accounting process and generation remain running. The API uses a random loopback port and strong random secret; snapshots contain only process/listener summaries. Windows job ownership and Linux parent-death signals tie the child to the Agent. macOS currently supports graceful child shutdown only.

Both auxiliary service startup and Home measurement startup also wait for a synchronous private `PUT /configs {}` response. In the pinned mihomo version, API/proxy registration happens before the tunnel enters its running state; a reachable port alone can therefore return a premature 502. The configuration API serializes against initial loading and returns only after the tunnel is running. Tests verify that this barrier waits for configuration completion and rejects failures/redirects; actual measurement errors are not retried or hidden. See the pinned upstream [configuration loader](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/hub/executor/executor.go) and [configuration endpoint](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/hub/route/configs.go).

Actual billing, download rate and connection controls continue through Xray. The bridge does **not** preserve the original remote IP, so Agent and controller reject simultaneous-IP limits on these users. The desired configuration persists for restart recovery; restoration starts Xray before auxiliary listeners. Real tests cover independent AnyTLS credentials, Snell v3/v4, real proxy bytes/Xray counters, rate enforcement, revocation, occupied-port preflight and restart recovery. Controller integration additionally checks certificate deployment, automatic configuration/bridge sequencing and generated personal subscriptions against real clients.

Listener fields were checked against the official v1.19.31 source and [mihomo AnyTLS](https://wiki.metacubex.one/en/config/inbound/listeners/anytls/) / [mihomo Snell](https://wiki.metacubex.one/en/config/inbound/listeners/snell/) documentation. The independently installed executable retains its own license and is not included in this repository's MIT code.

## Home speed-test program

```sh
go build -o bin/aswired-speedtest ./cmd/aswired-speedtest
./bin/aswired-speedtest -config speedtest.json
# Or run one local task without a controller:
./bin/aswired-speedtest -config speedtest.json -command measurement.json
```

Start with `speedtest.example.json`, fill in its separate home endpoint identity/token and pin a locally installed mihomo binary by exact version and SHA256. It uses the same encrypted WebSocket transport but reports mode `speedtest`; it accepts only `speedtest.run` and the administrator-supplied `source.fetch`, never node service/configuration commands. One runner executes tasks serially. `source_mode` identifies an actual home or controller process; it does not simulate an offline home endpoint.

Alternatively configure the local pinned mihomo fields, obtain a one-use pairing code from the controller, then run `aswired-speedtest -config speedtest.json -pair-url https://controller.example.com -pair-code YOUR_CODE`. Pairing verifies the configured executable before consuming the code, refuses redirects and controller-origin changes, preserves machine settings, writes the received identity atomically with mode 0600, and starts the normal connection. HTTP pairing is permitted only for loopback tests. The controller's public `/api/home/pair` endpoint consumes the code; the CLI cannot mint an identity itself.

The encrypted control client handles `identity.rotate` for both Agent and Home before task dispatch. Parameters are `{token,agent_token,previous_expires_at?}` with at least 32-character new tokens and an optional Unix expiry no later than 15 minutes ahead. It updates the original JSON configuration while preserving unknown/local fields, then the same WebSocket's subsequent report uses the new token. Direct HTTP accepts the previous Agent Token only until the persisted grace expiry. Failed persistence keeps the current identity. Result payloads contain no tokens. The identity transition is tested over a real encrypted WebSocket, including disk persistence, old HTTP token expiry and failed-write behavior.

A task contains `{"id":"test-1","action":"speedtest.run","params":{"node":{"type":"socks5","server":"127.0.0.1","port":1080},"url":"https://YOUR_DOWNLOAD_TARGET/large-file","parallel":1,"duration_seconds":8}}`. Parallelism is 1 or 8. Each job tests a real single-proxy configuration, starts a private loopback mihomo listener, samples three proxied HTTP response-header latencies and measures actual downloaded bytes. Optional `ip_check_url` queries an IP service through the very same proxy and accepts a plain IP or JSON `ip`/`address`/`query`. The result exposes `ip`, `exit_ip_verified`, or a specific `exit_ip_error`. The result includes source, binary version/checksum, byte count, elapsed time and failures. No direct fallback is used and no local IP is substituted.

`source.fetch` accepts `{url,headers?}` from the authenticated controller administrator, with a 30-second timeout and 8 MiB limit. Home returns `body_base64`, HTTP `status`, fixed safe response `headers`, `final_url`, and provenance. Request headers are limited to Authorization, Cookie, Accept and User-Agent; all are removed on an origin-changing redirect. HTTPS downgrade, embedded URL credentials and non-HTTP(S) schemes are refused. Private/special local destinations are rejected unless the local configuration explicitly enables `source_allow_private`; optional `source_allowed_origins` further restricts origins including redirects. Source fetching uses the Home machine's own network and does not claim it traverses the measured proxy node.

The optional `ASWIRED_TEST_MIHOMO` integration test uses the official **v1.19.31 Windows amd64 compatible** artifact, executable SHA256 `1fa8055e03596fc35167f70e9ecd1890517d38d960a39177445746a1b0defc2b`. Its actual proxied download and offline-proxy rejection were tested locally. Test tools are excluded from source and release artifacts. Other platform binaries require their own checksum. The executable remains a separately installed upstream dependency.

Original Agent code is MIT; the bundled Xray-derived files retain MPL-2.0. Distributions must include the applicable notices and corresponding source for modified MPL files.
## 参考来源

本项目参考的公开资料及链接见 [参考来源](REFERENCES.md)。

## Routing datasets

Standard `geoip:` / `geosite:` rules prepare missing datasets on first validation/application. The Agent downloads `geoip.dat` / `geosite.dat` and their SHA-256 checksums from the HTTPS Loyalsoldier/v2ray-rules-dat release, enforces a 64 MiB limit and validates protobuf content before atomic installation. Existing datasets are reused. The executable defaults `XRAY_LOCATION_ASSET` to `<data_dir>/geo`; operators may override it or pre-provision files for offline use. Download or checksum failures leave the running configuration intact and are reported as failed tasks. `ext:` datasets remain operator-managed; there is no automatic periodic dataset refresh.

Local maintenance scripts support Agent upgrades with validation and rollback. Controller-triggered Agent self-update is not implemented.

## REALITY 目标扫描

Agent 声明 `reality_scan` 能力，并通过 WebSocket 接收管理员发起的 `reality.scan` 任务。扫描验证公网目标的 TLS 1.3、h2、X25519 和证书，IP 目标通过同一 IP 的 SNI 复测；最多 128 个目标、16 个并发连接、55 秒执行时间。任务须带未过期 expiresAt，结果由主控保存并由管理员选择导入，不自动修改目标池或 Xray。
