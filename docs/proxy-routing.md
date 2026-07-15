# Proxy Routing MVP

The proxy supports three configured routing decisions and a three-stage automatic fallback path:

1. `direct`: connect to the destination without another proxy.
2. Static `socks5`: domains from a configured list always use a named upstream.
3. Learned route: a previously learned exact hostname uses either `direct+bye` or its recorded SOCKS5 upstream.

For a direct policy with fallback enabled, a failed TCP connect is immediately retried through the fallback SOCKS5 upstream. If TCP connects but a TLS ClientHello receives no response, the proxy first probes `direct+bye`. It sends the same valid ClientHello in two writes split inside SNI. If that also receives no response, it probes the VPN SOCKS5 upstream. The successful route is learned, the silent connection is closed, and the browser performs the retry. A learned `direct+bye` route that later stops working is replaced by SOCKS5 after a successful VPN probe.

Static SOCKS5 policies take priority over learned entries. A direct policy can disable learning with `fallback: none`. Automatic probing is limited to a complete TLS ClientHello; arbitrary application requests are never replayed.

## Configuration

```yaml
proxy:
  address: "0.0.0.0"
  port: 1080
  shutdown-timeout: 15s

admin:
  address: "127.0.0.1"
  port: 9090

upstreams:
  vpn:
    address: "10.0.0.10:1080"
    connect-timeout: 5s
  segment-de:
    address: "172.31.1.100:8888"
    connect-timeout: 5s
    # username: user
    # password: secret

upstream-health:
  enabled: true
  interval: 30s
  timeout: 5s
  failure-threshold: 3
  cooldown: 30s

bye:
  mode: tcp-split       # or tlsrec
  split-offset: 3       # bytes after the beginning of the SNI hostname
  delay: 15ms

detection:
  first-response-timeout: 3s
  probe-timeout: 5s
  probe-failure-backoff: 5m
  fallback-upstream: vpn
  learned-domains-file: learned-domains.yml
  learned-max-entries: 10000
  learned-domain-ttl: 168h
  # learn-allow-list: list/learn-allow.txt
  # learn-deny-list: list/learn-deny.txt

default:
  egress: direct
  dpi: none

strategy:
  - name: fixed-segment
    list: list/list-de.txt
    egress: socks5
    upstream: segment-de
    fallback: none

  - name: fragmented-direct
    list: list/list-fragment.txt
    egress: direct
    dpi: fragment
    fallback: vpn
```

List entries are exact hosts (`www.example.com`) or domain suffixes (`.example.com`). A suffix matches the base domain and subdomains at any depth. Relative list and learned-store paths are resolved from the configuration file directory.

## Learned routing lifecycle

The proxy starts the response timer only after forwarding a TLS ClientHello. If direct traffic is silent, one probe per hostname is allowed at a time. The first probe opens another direct connection and replays only the ClientHello with the configured Bye split. The second performs a full upstream SOCKS5 CONNECT. Each waits for the first target byte. On success, the proxy atomically updates `learned-domains.yml` with `route: direct+bye` or `route: socks5` and closes the failed client connection. Version 1 learned files without `route` remain compatible and are interpreted as SOCKS5 routes.

Events are logged as `event=direct_connect_failed`, `event=block_candidate`, `event=bye_success`, `event=bye_probe_failed`, `event=fallback_success`, or a specific failure event. Learned hosts are exact matches and do not automatically expand to their parent domain.

Usage counters and `last-used-at` are batched to the learned-domain file every 30 seconds. When `learned-domain-ttl` is non-zero, age is measured from `learned-at`; expiration deliberately forces a new direct attempt and fallback probe. Entries can also be deleted from the dashboard.

Failed probes are suppressed per hostname for `probe-failure-backoff`, preventing browser retries from creating an upstream probe storm. `learned-max-entries` bounds memory and file growth; a new route evicts the least recently used entry when the limit is reached. Optional allow and deny lists use the same exact/suffix syntax as strategy lists, with deny taking priority. Filters apply only to automatic learning, so an operator can still add an explicit route through the API.

## Admin dashboard and metrics

Set `admin.port` to enable the local HTTP server. Keep it bound to `127.0.0.1`; it has no authentication. The endpoints are:

- `/` — live dashboard with sessions, bytes, routing decisions, fallback outcomes, and learned domains.
- `/api/status` — the dashboard data as JSON.
- `/api/learned` — learned entries as JSON; `DELETE /api/learned?host=example.com` removes one. `POST /api/learned` accepts either `{"host":"example.com","route":"direct+bye"}` or `{"host":"example.com","route":"socks5","upstream":"vpn"}`. Omitting `route` preserves the old SOCKS5 API behavior.
- `/api/upstreams` — current health and circuit-breaker state for every named upstream.
- `POST /api/reload` — validate and atomically apply routing, upstream, detection, and timeout changes.
- `/metrics` — Prometheus metrics, including Go process metrics.
- `/healthz` — lightweight process health check.

Counters are process-lifetime values and restart from zero. Learned routes and their usage counters persist in YAML.

The dashboard's **Reload config** button calls the same endpoint. On Linux, `SIGHUP` also reloads the file. New SOCKS sessions use the new configuration; sessions already in progress keep their original snapshot. Changing the SOCKS or admin listener, capture interface, or learned-domain file still requires a restart.

`SIGINT` and `SIGTERM` stop accepting new clients, shut down the admin server, wait up to `proxy.shutdown-timeout` for active sessions, and flush learned-domain usage before exit. Windows console shutdown supports `Ctrl+C`; use the admin endpoint for configuration reloads on Windows.

## Upstream health and circuit breaker

When `upstream-health.enabled` is true, the proxy periodically connects to each named upstream and completes only the SOCKS5 authentication handshake. It does not open a target connection. Real upstream dials also update health state.

After `failure-threshold` consecutive failures, the circuit opens and new requests fail immediately instead of waiting for another upstream timeout. After `cooldown`, one half-open request is allowed. A successful real request or active health check closes the circuit immediately. Dashboard and Prometheus expose health, circuit state, failures, and operation outcomes.
