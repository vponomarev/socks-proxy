# Proxy Routing MVP

The proxy supports three routing decisions:

1. `direct`: connect to the destination without another proxy.
2. Static `socks5`: domains from a configured list always use a named upstream.
3. Learned fallback: a direct TLS connection that receives no response is probed through a fallback SOCKS5 upstream. A successful probe stores the exact hostname so subsequent browser retries use that upstream.

Static SOCKS5 policies take priority over learned entries. A direct policy can disable learning with `fallback: none`. Automatic probing is limited to a complete TLS ClientHello; arbitrary application requests are never replayed.

## Configuration

```yaml
proxy:
  address: "0.0.0.0"
  port: 1080

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

detection:
  first-response-timeout: 3s
  probe-timeout: 5s
  fallback-upstream: vpn
  learned-domains-file: learned-domains.yml
  learned-domain-ttl: 168h

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

The proxy starts the response timer only after forwarding a TLS ClientHello. If direct traffic is silent, one probe per hostname is allowed at a time. The probe performs a full upstream SOCKS5 CONNECT, replays only the ClientHello, and waits for the first target byte. On success, it atomically updates `learned-domains.yml` and closes the failed client connection. The browser is expected to retry.

Events are logged as `event=block_candidate`, `event=fallback_success`, or a specific failure event. Learned hosts are exact matches and do not automatically expand to their parent domain.

Usage counters and `last-used-at` are batched to the learned-domain file every 30 seconds. When `learned-domain-ttl` is non-zero, age is measured from `learned-at`; expiration deliberately forces a new direct attempt and fallback probe. Entries can also be deleted from the dashboard.

## Admin dashboard and metrics

Set `admin.port` to enable the local HTTP server. Keep it bound to `127.0.0.1`; it has no authentication. The endpoints are:

- `/` — live dashboard with sessions, bytes, routing decisions, fallback outcomes, and learned domains.
- `/api/status` — the dashboard data as JSON.
- `/api/learned` — learned entries as JSON; `DELETE /api/learned?host=example.com` removes one.
- `/metrics` — Prometheus metrics, including Go process metrics.
- `/healthz` — lightweight process health check.

Counters are process-lifetime values and restart from zero. Learned routes and their usage counters persist in YAML.
