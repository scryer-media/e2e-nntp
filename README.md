# e2e-nntp

`e2e-nntp` is a small, disk-backed NNTP server for deterministic integration
and benchmark tests. It is not a production Usenet service.

The project publishes Go source and version tags. It does not publish a server
container image. When a Compose topology is useful, the CLI builds a local
`scratch` image from an exact Go module version.

## Use from Go

```go
server, err := nntp.Start(context.Background(), nntp.Config{
    DataDir:    "./articles",
    ListenAddr: "127.0.0.1:119",
    Credentials: nntp.Credentials{
        Username: "fixture-user",
        Password: "fixture-password",
    },
})
if err != nil {
    return err
}
defer server.Close()
```

Each `Server` has independent listeners, article storage, metrics, synthetic
fault state, and credentials. `Start` accepts port `0` for test callers that
need an ephemeral address.

## Run from a script

Create a local password file with restrictive permissions, then run a pinned
version of the CLI:

```bash
go run github.com/scryer-media/e2e-nntp/cmd/e2e-nntp@v0.1.0 serve \
  --data-dir ./articles \
  --username fixture-user \
  --password-file ./nntp-password \
  --listen 127.0.0.1:119
```

TLS is disabled unless configured. For synthetic TLS, persist generated test
material in an ignored directory and declare every client hostname explicitly:

```bash
go run github.com/scryer-media/e2e-nntp/cmd/e2e-nntp@v0.1.0 serve \
  --data-dir ./articles \
  --username fixture-user \
  --password-file ./nntp-password \
  --listen 127.0.0.1:119 \
  --tls-listen 127.0.0.1:563 \
  --generate-test-tls \
  --tls-dir ./certs \
  --tls-dns-name nntp.bench.test
```

Use supplied certificate and key files instead of generated material whenever
the test environment already has a trusted CA.

## Build a local Docker image

The local builder cross-compiles a static Linux binary and loads it into the
current Docker daemon. It does not pull or publish an NNTP service image.

```bash
go run github.com/scryer-media/e2e-nntp/cmd/e2e-nntp@v0.1.0 image build \
  --version v0.1.0 \
  --tag e2e-nntp:v0.1.0 \
  --platform linux/arm64
```

It writes only a JSON provenance record to standard output. Store that record
with test artifacts; it includes the exact module version, target platform,
binary SHA-256, local tag, and Docker image ID. For a private development tree,
replace `--version` with `--source-dir /path/to/e2e-nntp`; the provenance uses
the neutral `source-directory` label and never emits the path.

Compose consumers must use the resulting local tag and `pull_policy: never`.
Provide the password through a mounted secret file, set
`NNTP_PASSWORD_FILE` to that file path, and pass `NNTP_ENABLE_TEST_CONTROL=1`
only to E2E suites that require the synthetic extensions.

The scratch image includes `e2e-nntp health --addr 127.0.0.1:119`, which
checks only the NNTP greeting and orderly `QUIT` response. Use it as the
Compose health check; it does not require credentials or test controls.

## Test controls

Standard NNTP operations are always available. `CHAOS`, `METRICS`, `DELETE`,
`DELETEID`, and `RELOAD` are nonstandard test controls. They are unavailable
unless `--enable-test-control` is set and require successful NNTP
authentication. Go callers have equivalent `Server` methods.

## Public-surface policy

Every retained commit is treated as public. Run the generic scanner before
review:

```bash
scripts/install-git-hooks
go run ./cmd/publiccheck --repo .
go run ./cmd/publiccheck --repo . --all
gitleaks git --redact --log-opts="--all"
```

Do not add real credentials, provider data, local names or paths, private
addresses, generated keys, captured articles, environment files, or benchmark
artifacts. See [SECURITY.md](SECURITY.md).
