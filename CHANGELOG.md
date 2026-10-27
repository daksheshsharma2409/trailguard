# Changelog

All notable changes to trailguard will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- Initial project scaffold (ESM TypeScript, tsup, Vitest, ESLint)
- GitHub Actions CI workflow (Node 18/20/22 matrix + PostgreSQL 16 integration job)
- Docker Compose for local PostgreSQL 16 development
- Config schema (`defineConfig`, `loadConfig`) with Zod validation
- Error hierarchy (`TrailguardError`, `AuditChainBrokenError`, `ScanConfigError`, etc.)
- Shared type definitions (`RouteNode`, `Finding`, `AuditEntry`, etc.)
- Docs skeleton (DECISIONS.md, THREAT_MODEL.md, ARCHITECTURE.md)

### Changed
- Migrated primary database engine from MySQL to PostgreSQL 16 across core runtime, Prisma schemas, integration test suites, demo application, and CI workflows.

---

[Unreleased]: https://github.com/daksheshsharma2409/trailguard/compare/HEAD...HEAD
