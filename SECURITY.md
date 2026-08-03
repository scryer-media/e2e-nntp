# Security policy

`e2e-nntp` is a synthetic test server. Do not expose it to untrusted networks
or use it with real provider credentials or article data.

Report vulnerabilities through GitHub private vulnerability reporting for this
repository. Do not include secrets or customer/provider data in public issues.

## Public-surface policy

Every retained commit is treated as eventually public. Contributors must not
commit credentials, tokens, private keys, certificate material, local paths,
private addresses, personal identifiers, captured articles, environment files,
or benchmark artifacts. Run `scripts/install-git-hooks` once per checkout and
ensure the required CI checks pass before review.

The tracked checker catches generic classes of sensitive data. A separate
organization-controlled DLP service checks private organization-specific
patterns; its rules and configuration are intentionally not stored here.
