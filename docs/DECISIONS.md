# Architecture Decision Records

This file documents architectural decisions made during trailguard's development.
Each ADR is immutable once closed — append only.

---

## Template

```
### ADR-NNN: <Title>

**Date:** YYYY-MM-DD  
**Status:** Proposed | Accepted | Rejected | Deprecated  
**Context:** Why this decision was needed.  
**Decision:** What was decided.  
**Consequences:** What trade-offs this introduces.
```

---

### ADR-001: ESM-only package

**Date:** 2026-10-26  
**Status:** Accepted  
**Context:** Node ≥18.18 supports native ESM. Mixed CJS/ESM packages add friction for
consumers and complicate the build pipeline. All modern tooling (Vite, Vitest, tsup,
modern Prisma) handles ESM natively.  
**Decision:** Ship `"type": "module"` with `moduleResolution: "NodeNext"` and a single
ESM output from tsup. No CJS fallback.  
**Consequences:** Consumers must use Node ≥18.18. CJS-only projects cannot use trailguard
without a bundler. This is acceptable per context.md §2 target audience.

---

### ADR-002: Prisma as peer dependency

**Date:** 2026-10-26  
**Status:** Accepted  
**Context:** Bundling Prisma's generated client would conflict with the consumer's own
Prisma version and generated types. The runtime API must accept the consumer's client
directly.  
**Decision:** `@prisma/client` and `prisma` are `peerDependencies`. The runtime API
accepts a generic `PrismaClient`-shaped object — not the Prisma-generated class itself —
so the dependency only applies at the type level.  
**Consequences:** Consumers must install Prisma separately. The trailguard Prisma schema
must stay in sync with what Prisma 5.x generates.

---

### ADR-003: HMAC-SHA256 for chain integrity (not a blockchain)

**Date:** 2026-10-26  
**Status:** Accepted  
**Context:** The audit log needs to be tamper-evident — a modified entry must be
detectable. A full Merkle tree or blockchain adds operational complexity with no benefit
for the threat model (single-tenant, trusted infrastructure).  
**Decision:** Each row's `hash` is `HMAC-SHA256(key, canonicalJSON(row))` where the
canonical JSON includes the `prevHash` of the previous row. The chain starts with a
genesis hash of 64 zeros. The key is rotated via the `keys` array; verification tries
all provided keys.  
**Consequences:** The log is tamper-evident, not tamper-proof. A DB admin with the HMAC
key can forge entries. The key must be stored out-of-band (e.g., in a secrets manager).
Rotating keys requires re-signing or accepting a chain break at the rotation point.

---

### ADR-004: ts-morph for static analysis

**Date:** 2026-10-26  
**Status:** Accepted  
**Context:** Parsing TypeScript ASTs at the correct semantic level (following imports,
resolving types) requires the TypeScript compiler API. Raw regex is fragile.  
**Decision:** Use `ts-morph` (a well-maintained wrapper over the TS compiler API) for
all static analysis. It is a direct dependency, not a peer dep, because consumers never
interact with it directly.  
**Consequences:** `dist/scan/index.js` is ~130 KB (the ts-morph bundle). This is
acceptable — scan is a dev-time tool, not shipped to production.

---
