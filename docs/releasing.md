# Release Process

Pull requests and pushes to `main` run race-enabled tests, `go vet`, and portable Linux/Windows build checks on GitHub Actions.

Releases are created only from semantic version tags. After CI succeeds on `main`, create and push a tag such as:

```bash
git tag -a v0.2.0 -m "v0.2.0"
git push origin v0.2.0
```

The release workflow runs tests, builds CGO-disabled `linux/amd64` and `windows/amd64` SOCKS proxy binaries, generates `SHA256SUMS`, includes both example configurations, and publishes a GitHub Release with generated notes. CGO-disabled binaries support proxy routing and fallback but not packet-capture-dependent fake-SNI injection.
