# Changelog

## BETA-1.4

### Added

- Multi-database backend support: `sqlite`, `mysql`, `postgresql`.
- Connection pool management with HikariCP runtime telemetry.
- Internal versioned schema migrations with startup tracking.
- New `/authadmin db` command group:
  - `status` / `health` for connection health and ping
  - `migrations` for schema version visibility
  - `import` flow for guided SQLite migration
- Guided SQLite import flow with preview + confirm/cancel safety step.
- Extended admin status metrics in `/authadmin status`:
  - average login/register/pre-login response times
  - DB query metrics and top operations
  - pool and executor runtime stats
  - online-user cache hit/miss counters
- Integration test suite for multi-db schema behavior (SQLite + Testcontainers MySQL/PostgreSQL).

### Changed

- Plugin version bumped to `BETA-1.4`.
- `lookup` moved under admin namespace: now `/authadmin lookup <player|ip>`.
- Improved console log readability with clearer security/auth/database scopes.
- Updated docs and command references to reflect new admin command layout.

### Fixed

- Strengthened pre-auth restrictions to reduce actions slipping through before login/register.
- Improved DB failure handling with timeout + retry/backoff for transient SQL errors.
- Removed outdated standalone `/lookup` command registration.

### Internal

- Added short-lived online user cache layer for faster repeated lookups.
- Expanded config options for DB timeout/retry and cache tuning.
