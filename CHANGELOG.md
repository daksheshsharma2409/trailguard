# Changelog

All notable changes to trailguard will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.5] - 2026-10-28

### Fixed
- Fixed hardcoded version in static scan orchestrator (`scanResult.version`), CLI banner, and reports: now dynamically resolves from `package.json` across all interfaces.
- Fixed outdated schema snippet types in `trailguard init` (`@db.LongText` -> `@db.Text`, `@db.DateTime` -> `@db.Timestamp(3)`).

### Added
- Added comprehensive section-by-section documentation and parameter comments to the starter `trailguard.config.ts` scaffolded by `trailguard init`.

## [0.1.4] - 2026-10-28

### Changed
- Streamlined README: eliminated duplicate route examples and repeated questions; added in-depth section on connecting authorization declarations to runtime audit records.
- Updated Prisma schema quickstart snippet in README to align with PostgreSQL 16 schema types (`@db.Text`, `@db.Timestamp(3)`, `ipAddress`).
- Refined Table of Contents and quickstart cross-references.

## [0.1.3] - 2026-10-28

### Changed
- Maintenance patch release.

## [0.1.2] - 2026-10-27

### Changed
- Migrated primary database engine from MySQL to PostgreSQL 16 across core runtime, Prisma schemas, integration test suites, demo application, and CI workflows.
- Quoted table and column identifiers (`"lastSeq"`, `"lastHash"`, `"trailguard_audit_head"`) in core append and service runtime queries to avoid PostgreSQL case folding.
- Converted attacker scripts and integration test queries to dialect-agnostic Prisma client methods.
- Updated exported `prisma/trailguard.prisma` to PostgreSQL provider and `@db.Text` / `@db.Timestamp(3)` types.

## [0.1.1] - 2026-10-27

### Added
- Lightweight stdlib-only `.env` loader for CLI commands (`trailguard ci`, `verify`, `drift`).
- Automatic Prisma schema resolution fallback in `trailguard drift`.

### Fixed
- Connection leak in `trailguard drift` by ensuring disconnect in `finally` block.

### Changed
- Streamlined audited write operations in runtime client into unified `runAuditedOp` helper (-630 lines of boilerplate).
- Shared Prisma connection between verification and drift check stages in `trailguard ci`.

## [0.1.0] - 2026-10-27

### Added
- Initial project scaffold (ESM TypeScript, tsup, Vitest, ESLint)
- GitHub Actions CI workflow (Node 18/20/22 matrix + PostgreSQL 16 integration job)
- Docker Compose for local PostgreSQL 16 development
- Config schema (`defineConfig`, `loadConfig`) with Zod validation
- Error hierarchy (`TrailguardError`, `AuditChainBrokenError`, `ScanConfigError`, etc.)
- Shared type definitions (`RouteNode`, `Finding`, `AuditEntry`, etc.)
- Docs skeleton (DECISIONS.md, THREAT_MODEL.md, ARCHITECTURE.md)

---

[0.1.5]: https://github.com/daksheshsharma2409/trailguard/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/daksheshsharma2409/trailguard/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/daksheshsharma2409/trailguard/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/daksheshsharma2409/trailguard/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/daksheshsharma2409/trailguard/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/daksheshsharma2409/trailguard/releases/tag/v0.1.0
