# Fake-SNI Experimental Mode

Fake-SNI sends a valid decoy TLS ClientHello before the browser's original
ClientHello. The decoy uses a calibrated low TTL so DPI can inspect it while it
expires before reaching the destination. Provider behavior differs; keep this
mode opt-in and test every network independently.

## Linux build and run

Install Go, a C compiler, and libpcap headers. On Debian/Ubuntu:

```sh
apt-get install build-essential libpcap-dev
CGO_ENABLED=1 go build -o socks-proxy-pcap ./cmd
cd cmd
../socks-proxy-pcap -config fake-sni.example.yml
```

The release artifact named `socks-proxy-linux-amd64-pcap` includes packet
capture support but still requires the system libpcap runtime. Portable release
binaries use `CGO_ENABLED=0` and report that packet capture is unavailable.

Set `fake-sni.interface` to the outbound interface (`eth0`, `ens18`, or an Npcap
device identifier). Start with TTL 1 and increase carefully. A fake packet that
reaches the server intentionally conflicts with the real TLS transcript.

The proxy preserves a small client's TLS fingerprint and only generates a clean
X25519 ClientHello when the original would exceed MTU. Logs report `hello_source`,
payload size, MTU, TTL, and confirmed libpcap write errors.
