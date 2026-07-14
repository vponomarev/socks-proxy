# Repository Guidelines

## Project Structure & Module Organization

This is a Go module (`github.com/vponomarev/socks-proxy`) with several executable packages:

- `cmd/` contains the SOCKS5 proxy, packet capture/injection code, the sample `proxy.yml`, and domain lists under `cmd/list/`.
- `cmd-route/` provides the route and network-information HTTP service.
- `cmd-route-manager/` exposes an API and Prometheus metrics for managing BIRD routes.
- `cmd-bird-manager/` contains direct BIRD control-socket and configuration-update examples.
- `internal/config/` loads YAML configuration and domain patterns; `internal/libtls/` parses and rewrites TLS data.

Keep reusable code under `internal/`; keep executable wiring in its corresponding command directory. Do not commit generated binaries such as `*.exe` or `*-linux-arm64`.

## Build, Test, and Development Commands

- `go mod download` installs module dependencies.
- `go build ./...` compiles every command and internal package.
- `go test ./...` runs all package tests and performs a useful compile check.
- `go vet ./...` reports suspicious Go constructs.
- `gofmt -w ./cmd ./cmd-route ./cmd-route-manager ./cmd-bird-manager ./internal` formats source files.
- From `cmd/`, run `go run . -config proxy.yml` so relative paths such as `list/list-fake.txt` resolve correctly.
- `go run ./cmd-route -p 8800` starts the route inspection service.

Packet capture uses `gopacket/pcap`, so local builds may require CGO plus libpcap on Unix or Npcap development libraries on Windows. BIRD commands require Linux, `birdc`, and access to the configured control socket.

## Coding Style & Naming Conventions

Follow idiomatic Go and let `gofmt` define tabs and alignment. Use short, lower-case package names; exported identifiers use `PascalCase`, local identifiers use `camelCase`, and initialisms remain capitalized (`IP`, `TLS`, `CIDR`). Wrap errors with context using `%w` where callers may inspect them. Keep configuration keys consistent with the existing kebab-case YAML schema.

## Testing Guidelines

Tests use Go's standard `testing` and `httptest` packages and live beside the code in `*_test.go`. Use `TestXxx` names and table-driven cases where appropriate. End-to-end SOCKS tests are under `cmd/`; configuration, routing persistence, admin API, and metrics have focused tests under `internal/`. Run `go test ./...` before submitting; use `go test -race ./...` for concurrency changes when the local CGO toolchain supports it.

## Commit & Pull Request Guidelines

History currently uses brief `Updates` messages; prefer specific imperative subjects such as `Validate SOCKS5 target ports`. Keep commits focused. Pull requests should explain behavior changes, list verification commands, link relevant issues, and note OS, packet-capture, BIRD, or privilege requirements. Include sample requests or logs for API changes. Never commit credentials, `IPINFO_TOKEN`, local interface IDs, or machine-specific config.
