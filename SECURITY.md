# Security policy

## Reporting a vulnerability

Please do **not** open a public issue for security problems. Use GitHub's
[private vulnerability reporting](../../security/advisories/new) instead and include:

- what an attacker can do and under which conditions,
- steps to reproduce,
- the version or commit you tested.

You will get an answer within a week. Fixes are released as soon as possible and credited unless you
prefer otherwise.

## Scope

In scope: this service's API authentication, admin UI, session storage and container image.

Out of scope: Apple's iCloud API and Bitwarden itself, problems that require access to the server or the
`/data` volume, and deployments without HTTPS or with the admin UI exposed using `HME_ADMIN_AUTH=proxy`
but no authenticating proxy.
