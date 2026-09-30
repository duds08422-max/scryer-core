# Security Policy — Scryer (Hartwell Labs)

## Supported versions

Scryer is distributed as signed builds to licensed customers. Always run the
latest build; security fixes are delivered out-of-band to active licensees.

## Reporting a vulnerability

**Preferred:** upload a private vulnerability disclosure via
[GitHub Security Advisories](https://github.com/duds08422-max/scryer-core/security/advisories/new).

**Alternative:** mail **contact@hartwell-labs.pl** (PGP available on request).
Include reproduction steps, affected version/build, and impact assessment.

## Scope

In scope:
- The `scryer-core` engine, its embedded DNS mini-client (`dnsmini`), scoring
  and enrichment pipeline, and the local web console (`serve`).
- The optional bearer-token auth (`SCRYER_TOKEN`) — bypass, timing, or
  token-leakage issues are treated as high severity.

Out of scope:
- The operator's misconfiguration (e.g. deliberately binding to `0.0.0.0`
  without `SCRYER_TOKEN`).
- Vulnerabilities in third-party dependencies: report upstream, CC us.

## Commitments

- **48h** initial response.
- **No legal action** for good-faith research (passive analysis only — do not
  scan third parties; see our rules: passive DNS by default).
- Credit in the release notes unless you prefer anonymity.
- Safe-harbor: we consider good-faith research compliant with this policy
  authorized activity.

## Design stance

Scryer is **localhost-first**: the console binds to `127.0.0.1` by default;
exposing it is an explicit operator decision that should always be paired with
`SCRYER_TOKEN`. The engine makes no network calls beyond passive public DNS
(equivalent to a normal resolver) and never phones home — zero telemetry.
