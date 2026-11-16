# odoh-go (fork)

[![Go](https://github.com/nam348tnh3gp/odoh-go/actions/workflows/go.yml/badge.svg)](https://github.com/nam348tnh3gp/odoh-go/actions/workflows/go.yml)
![coverage](https://img.shields.io/badge/coverage-86.8%25-brightgreen)

This is a fork of [`cloudflare/odoh-go`](https://github.com/cloudflare/odoh-go)
that uses [`github.com/jedisct1/go-hpke-compact`](https://github.com/jedisct1/go-hpke-compact)
instead of `github.com/cisco/go-hpke`.

It implements version `0x0001` of Oblivious DoH ([RFC 9230](https://www.rfc-editor.org/rfc/rfc9230)).

- **KEM**: X25519-HKDF-SHA256 only
- **KDF**: HKDF-SHA256
- **AEAD**: AES-128-GCM (default), AES-256-GCM, ChaCha20-Poly1305

![protocol overview](odoh-flow.png)

## Status

- Tests: unit tests, fuzz tests and examples (`go test ./...`)
- Coverage: 86.8% of statements in the library package (measured by the latest successful CI run); the programs in `examples/` have no tests
- CI: GitHub Actions (tidy check, gofmt, vet, build, race tests, coverage, short fuzz)
- Latest tag: `v0.0.3`

## Install

```sh
go get github.com/nam348tnh3gp/odoh-go@v0.0.3
```

The module path is `github.com/nam348tnh3gp/odoh-go`, so import it directly; no
`replace` directive is needed.

## Usage

Error handling is omitted for brevity.

```go
import odoh "github.com/nam348tnh3gp/odoh-go"

// Target: derive a key pair from a 32-byte seed and publish its config
// (serve it at /.well-known/odohconfigs).
kp, _ := odoh.CreateDefaultKeyPairFromSeed(seed)
configs := odoh.CreateObliviousDoHConfigs([]odoh.ObliviousDoHConfig{kp.Config}).Marshal()

// Client: encrypt a DNS query (wire format) for the target.
// The config normally comes from odoh.UnmarshalObliviousDoHConfigs(body).
query := odoh.CreateObliviousDNSQuery(dnsWire, 0)
msg, qctx, _ := kp.Config.Contents.EncryptQuery(query)
body := msg.Marshal() // POST as application/oblivious-dns-message

// Target: decrypt the query, then encrypt the answer.
in, _ := odoh.UnmarshalDNSMessage(body)
q, rctx, _ := kp.DecryptQuery(in) // q.DnsMessage is the DNS query
out, _ := rctx.EncryptResponse(odoh.CreateObliviousDNSResponse(answerWire, 0))

// Client: open the response.
resp, _ := odoh.UnmarshalDNSMessage(out.Marshal())
answer, _ := qctx.OpenAnswer(resp) // DNS answer in wire format
```

## Examples

`examples/client` sends one query through an ODoH proxy:

```sh
go run ./examples/client -proxy https://your-proxy/dns-query -domain example.com
```

`examples/target` is a **demo** target: it publishes its config at
`/.well-known/odohconfigs` and accepts queries at `/dns-query`, but it always
answers `NXDOMAIN` and does not resolve anything. Use it to try the library,
not as a real resolver.

```sh
openssl rand -hex 32                          # generate a 32-byte seed
go run ./examples/target -seed <64-hex-seed>  # optional: -port 8080
```

## Development

```sh
go test -count=1 -cover ./...
go test -race -count=1 ./...
go vet ./...
```

Fuzz:

```sh
go test -run='^$' -fuzz=FuzzUnmarshalDNSMessage -fuzztime=10s .
go test -run='^$' -fuzz=FuzzUnmarshalMessageBody -fuzztime=10s .
go test -run='^$' -fuzz=FuzzUnmarshalConfigs -fuzztime=10s .
go test -run='^$' -fuzz=FuzzDecodeLengthPrefixedSlice -fuzztime=10s .
```

### Test vectors

`TestVectorVerify` is skipped unless `ODOH_TEST_VECTORS_IN` is set. Generate and
verify vectors with:

```sh
ODOH_TEST_VECTORS_OUT=test-vectors.json go test -v -run TestVectorGenerate
ODOH_TEST_VECTORS_IN=test-vectors.json go test -v -run TestVectorVerify
```

## Differences from upstream

- HPKE comes from `go-hpke-compact`. Only X25519 with HKDF-SHA256 is supported;
  P-256, P-521, X448, SHA-384 and SHA-512 were removed.
- The module path is `github.com/nam348tnh3gp/odoh-go`.
- `KEMID`, `KDFID` and `AEADID` are aliases of the `go-hpke-compact` types, and
  `ObliviousDoHConfigContents.CipherSuite()` returns `*hpkecompact.Suite`.
- `CreateKeyPairFromSeed` requires a seed of exactly 32 bytes. Upstream accepted
  any length, so a key derived from a shorter seed will not be reproduced.
- Parsers are hardened: bounds checks, nil guards, copies of input slices and an
  overflow fix.
- `UnmarshalObliviousDoHConfigs` is lenient: it stops at a truncated config
  instead of returning an error.
- `DecryptQuery` and `DecryptResponse` reject messages that are too short to be
  valid.
- Length-prefixed fields longer than 65535 bytes make `Marshal()` panic.
- Added tests, fuzz targets, examples and CI.

## Security

See [SECURITY.md](SECURITY.md).

## License

MIT, see [LICENSE.md](LICENSE.md).
