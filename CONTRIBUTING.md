# Contributing

This repository is private during development but is designed to become public
without rewriting its retained history. Treat every commit as public.

Before staging changes:

```bash
scripts/install-git-hooks
go run ./cmd/publiccheck --repo .
gitleaks protect --staged --redact
go test -race ./...
```

Use synthetic test values only. Never add a provider account, local host or
user name, private address, source capture, generated certificate, or secret.
The final public-transition audit scans all reachable refs, not only `main`.
