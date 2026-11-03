# Changelog

All notable changes to this project. Versions follow [semantic versioning](https://semver.org/).

## 1.0.1 — 2026-11-03

### Fixed
- Duplicate keys in a CBOR map are rejected instead of the last one silently winning.
- A CAR file whose header is not a map, or whose roots are not a list of CIDs, is rejected; proof
  verification reports it as a failed verdict instead of an error.

## 1.0.0 — 2026-11-03

### Added
- A verification API (`atproof serve`): `POST /v1/verify` checks one inclusion or absence proof,
  `POST /v1/deleted` checks that a record existed and was later removed, and
  `GET /v1/verifications[/{id}]` reads the log. Everything is verified offline; the API never
  fetches from the network. Proofs are not stored; each verification records its input SHA-256s,
  the URI, the verdict and who asked, in SQLite or Postgres with numbered migrations
  (`atproof migrate`).
- Settings from `ATPROOF_*` environment variables, checked at startup; production refuses to
  start without hashed API keys and a database. Roles on keys, rate limit, body cap, security
  headers, JSON logs with request IDs, `/healthz`, `/readyz` and Prometheus `/metrics`.
- `pyproject.toml` 1.0.0 (Python 3.12+), pinned lock files, a container image (slim, non-root,
  health check), CI with ruff, bandit, pip-audit and coverage (it replaces the old test workflow
  and keeps its import-order check and warnings-as-errors).
- `SECURITY.md`, `docs/threat-model.md`, `docs/runbook.md`, MIT licence.

### Changed
- `capture` refuses any URL that is not `https://`. The URLs it built were already https, but
  the fetch itself would have opened `file:` URLs.

### Unchanged
- The decoder, tree walk, signature checks and verdicts; the 29 original tests pass unchanged,
  including the real `@bsky.app` proofs.
