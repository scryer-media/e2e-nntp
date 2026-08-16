# Contributing

This repository is public and its retained history is never rewritten. Treat
every commit as public.

Before staging changes:

```bash
scripts/install-git-hooks
go run ./cmd/publiccheck --repo .
gitleaks protect --staged --redact
go vet ./...
go test -race ./...
```

Use synthetic test values only. Never add a provider account, local host or
user name, private address, source capture, generated certificate, or secret.
CI re-runs the public-surface audit over all reachable refs, not only `main`,
so a finding in an earlier commit fails the build even after it is removed
from the tip.
