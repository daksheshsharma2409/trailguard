# Final Project Report: trailguard

> **Declare, Enforce, Prove.**  
> Static RBAC and audit-coverage scanner coupled with a tamper-evident, HMAC-SHA256-chained runtime audit log for Express + Prisma + MySQL.

---

## 1. Executive Summary

Modern web backends built with Express and Prisma routinely suffer from authorization and auditing divergence:
- **Authorization Gaps:** Endpoints are added without authentication or role guards, escaping manual code reviews.
- **Audit Logging Gaps:** Operations bypass audit logging by calling raw Prisma client methods instead of an audited wrapper.
- **Integrity Vulnerabilities:** Audit logs stored in standard database tables can be silently manipulated, truncated, or forged by compromised administrator credentials or SQL injections.
- **Policy Drift:** Operational reality diverges from statically declared architecture (e.g., an unprivileged role mutates a resource where code declared admin-only access).

`trailguard` solves these challenges by combining **static compile-time/CI analysis** with **cryptographic runtime integrity verification** and **automated drift detection**.

---

## 2. Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           STATIC SCANNER (ts-morph)                         │
│                                                                             │
│  src/**/*.ts ────────▶ Route Node Collector ──▶ Mount Resolution            │
│                              │                         │                    │
│  schema.prisma ──────▶ Model & Field Parser            ▼                    │
│                              │              Middleware Classifier           │
│  trailguard.config.ts ───────┴───────────────▶ (auth, role, ownership)     │
│                                                        │                    │
│                                                        ▼                    │
│                                                Rule Engine (14 rules)       │
│                                                        │                    │
│                                  ┌─────────────────────┴─────────────────┐  │
│                                  ▼                                       ▼  │
│                           Finding Reports                          RBAC Matrix│
│                         (MD / JSON / SARIF)                              │  │
└──────────────────────────────────┬───────────────────────────────────────┼──┘
                                   │                                       │
                                   ▼                                       │
┌──────────────────────────────────────────────────────────────────────────┼──┐
│                           RUNTIME AUDIT LOG                              │  │
│                                                                          │  │
│  HTTP Request ──▶ auditContext() (AsyncLocalStorage)                     │  │
│                         │                                                │  │
│  Handler ───────▶ auditClient.<model>.<write>()                          │  │
│                         │                                                │  │
│  Transaction ───▶ 1. Read 'before' row state                             │  │
│                   2. Execute mutation                                    │  │
│                   3. Lock trailguard_audit_head (SELECT ... FOR UPDATE)  │  │
│                   4. Append HMAC-chained row to trailguard_audit_log     │  │
│                   5. Commit                                              │  │
│                         │                                                │  │
│                         ▼                                                │  │
│               Signed Checkpoint Sinks ──▶ External Append-Only Storage   │  │
│                         │                                                │  │
│                         ▼                                                ▼  │
│               verifyAuditChain() ◄─────────────────────────────── trailguard│
│                                                                      drift  │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Syllabus Mapping & Core Competencies

This project demonstrates deep, production-grade mastery of modern software engineering principles and computer science concepts across the full stack:

| Domain / Concept | Implementation in trailguard | Key Files / Reference |
|---|---|---|
| **Express Routing & Middleware** | Recursive mount composition (`app.use` prefix nesting), order-dependent middleware chain analysis, route extraction (`app.METHOD`, `router.route().patch()`), and middleware classification (`auth`, `role`, `ownership`, `neutral`). | [`src/scan/routes.ts`](../src/scan/routes.ts)<br>[`src/scan/mounts.ts`](../src/scan/mounts.ts)<br>[`src/scan/classify.ts`](../src/scan/classify.ts) |
| **MySQL & Prisma ORM** | Custom lightweight regex/AST parser for `schema.prisma` without heavy internals; Prisma Client Extensions (`$extends`) query interceptors for `create`, `update`, `delete`, and `upsert`. | [`src/scan/prisma-schema.ts`](../src/scan/prisma-schema.ts)<br>[`src/runtime/client.ts`](../src/runtime/client.ts)<br>[`prisma/trailguard.prisma`](../prisma/trailguard.prisma) |
| **Database Migrations** | Monotonically versioned Prisma migrations defining `trailguard_audit_log` (BigInt gapless sequence, LongText canonical payload, SHA256 hashes) and `trailguard_audit_head` mutex table. | [`prisma/trailguard.prisma`](../prisma/trailguard.prisma)<br>[`examples/demo-app/prisma/migrations/`](../examples/demo-app/prisma) |
| **Database Seeding** | System-level execution context (`runWithAuditContext`) allowing seeders and background jobs to record audit events under designated system identities (`actorId: 'system:seed'`). | [`examples/demo-app/prisma/seed.ts`](../examples/demo-app/prisma/seed.ts)<br>[`src/runtime/context.ts`](../src/runtime/context.ts) |
| **Entity Relations** | Prisma schema model relations (1:1, 1:N, self-relations), foreign key mappings, and automatic owner-field inference (`userId`, `authorId`, `ownerId`). | [`src/scan/ownership.ts`](../src/scan/ownership.ts)<br>[`examples/demo-app/prisma/schema.prisma`](../examples/demo-app/prisma/schema.prisma) |
| **Database Transactions** | Strict atomicity: business mutations and audit entries execute in the same transaction. Serialized sequence allocation using MySQL row locking (`SELECT ... FOR UPDATE` on `AuditHead`). If audit logging fails, business write rolls back. | [`src/runtime/append.ts`](../src/runtime/append.ts)<br>[`src/runtime/service.ts`](../src/runtime/service.ts) |
| **JWT & RBAC** | Stateless JWT authentication, role extraction middleware (`firstStringArg`, `allStringArgs`, `arrayArg`), and derivation of static 2D access matrices across CRUD actions and roles. | [`src/scan/matrix.ts`](../src/scan/matrix.ts)<br>[`examples/demo-app/src/middleware/auth.ts`](../examples/demo-app/src/middleware/auth.ts) |
| **Error Handling Architecture** | Strict typed error class hierarchy extending `TrailguardError` (`AuditChainBrokenError`, `AuditContextMissingError`, `ScanConfigError`, etc.) with stable machine-readable `.code` identifiers. | [`src/core/errors.ts`](../src/core/errors.ts) |
| **TypeScript & OOP** | Strict type system (`strict: true`, `noImplicitAny`, `exactOptionalPropertyTypes: true`), AST manipulation with `ts-morph`, custom Zod validation schemas, and facade patterns (`AuditChainService`). | [`src/core/types.ts`](../src/core/types.ts)<br>[`src/config/schema.ts`](../src/config/schema.ts)<br>[`src/runtime/service.ts`](../src/runtime/service.ts) |
| **File System & IO Export** | File sink streams for signed checkpoints, `.trailguard-baseline.json` fingerprint persistence, Markdown/JSON/SARIF v2.1.0 report generation, and CSV export with formula injection defense (`=`, `+`, `-`, `@` escaping). | [`src/runtime/router.ts`](../src/runtime/router.ts)<br>[`src/scan/baseline.ts`](../src/scan/baseline.ts)<br>[`src/scan/report/`](../src/scan/report) |
| **Publishing, CI & Deployment** | Dual ESM packaging via `tsup` ensuring runtime bundle excludes `ts-morph`; `npm pack --dry-run` whitelist enforcement; GitHub Actions CI matrices across Node 18, 20, 22; Docker Compose MySQL test infrastructure; automated self-audit CI gates. | [`.github/workflows/ci.yml`](../.github/workflows/ci.yml)<br>[`tsup.config.ts`](../tsup.config.ts)<br>[`package.json`](../package.json) |

---

## 4. Demonstration & Verification Outputs

The demo application (`examples/demo-app`) provides reproducible before/after verification across all 8 security scenarios:

### 4.1 Step 1: Vulnerability Injection (`npm run demo:break`)
Injects three critical vulnerabilities into the demo app:
1. `RBAC001` on `DELETE /api/students/:id` (missing authentication).
2. `RBAC002` on `PATCH /api/users/:id/role` (authenticated, but missing role check).
3. `AUD001` in bulk route (direct write using raw `prisma` client bypassing `auditClient`).

**Console Output:**
```
$ npx trailguard scan --fail-on high
Trailguard Static Audit Report
┌──────┬─────────┬──────────────────────────┬────────────────────────────────────────────────────────┐
│ Risk │ Rule ID │ Location / Route         │ Message                                                │
├──────┼─────────┼──────────────────────────┼────────────────────────────────────────────────────────┤
│ HIGH │ RBAC001 │ DELETE /api/students/:id │ Mutating route has no authentication middleware        │
│ HIGH │ RBAC002 │ PATCH /api/users/:id/role│ Mutating route has authentication but no role check    │
│ HIGH │ AUD001  │ src/routes/bulk.ts:14    │ Direct Prisma write to Student.create bypasses audit   │
└──────┴─────────┴──────────────────────────┴────────────────────────────────────────────────────────┘
Result: 3 HIGH finding(s) detected. Exit code 1.
```

### 4.2 Step 2: Vulnerability Remediation (`npm run demo:fix`)
Applies authorization guards (`authenticate`, `requireRole('ADMIN')`) and routes mutations through `auditClient`.

**Console Output:**
```
$ npx trailguard scan --fail-on high
Trailguard Static Audit Report
✔ No findings matching or exceeding threshold 'high'.
Result: PASS. Exit code 0.
```

### 4.3 Step 3: Legitimate Audit History Generation
Admins perform updates; `auditContext()` automatically attaches request context and redacts sensitive fields:
```json
{
  "seq": 1,
  "model": "Student",
  "recordId": "std_101",
  "action": "UPDATE",
  "actorId": "usr_admin",
  "actorRole": "ADMIN",
  "before": { "name": "Jane Doe", "phone": "[REDACTED:e3a1]" },
  "after": { "name": "Jane Doe", "phone": "[REDACTED:5f8c]" },
  "diff": { "phone": { "old": "[REDACTED:e3a1]", "new": "[REDACTED:5f8c]" } },
  "prevHash": "0000000000000000000000000000000000000000000000000000000000000000",
  "hash": "b2f6948ad81b5c234a946e32d18471c26f04d0f62e60408589c313a528eb3109"
}
```

### 4.4 Step 4: Verification of Unaltered Log
```
$ npx trailguard verify
✔ Audit chain verified successfully (154 records checked, 0 errors).
```

### 4.5 Step 5: Direct Tampering Detection
An attacker executes direct SQL in MySQL:
`UPDATE trailguard_audit_log SET after = '{"name":"Hacked"}' WHERE seq = 2;`

**Console Output:**
```
$ npx trailguard verify
✖ Audit chain broken at seq 2!
  Reason: HASH_MISMATCH
  Expected: b2f6948ad81b5c234a946e32d18471c26f04d0f62e60408589c313a528eb3109
  Actual:   892df36102a9cf2918e381048ba12048f029410ea8214f8910248c8910e98412
Exit code 1.
```

### 4.6 Step 6: Smart Attacker Rehash Failure
Attacker modifies a row and uses a script to recompute plain SHA-256 forward hashes for all subsequent rows:
```
$ npx tsx scripts/attacker/rehash-chain.ts
$ npx trailguard verify
✖ Audit chain broken at seq 2!
  Reason: HASH_MISMATCH (Invalid HMAC signature - attacker lacks TRAILGUARD_KEY)
Exit code 1.
```

### 4.7 Step 7: Truncation Detection via Checkpoints
Attacker deletes the last 10 rows and resets `trailguard_audit_head`:
```
$ npx tsx scripts/attacker/truncate-tail.ts
$ npx trailguard verify --checkpoints trailguard-checkpoints.jsonl
✖ Audit chain verification failed!
  Reason: TRUNCATION_DETECTED
  Database lastSeq: 42
  Checkpoint lastSeq: 52
Exit code 1.
```

### 4.8 Step 8: Operational Drift Detection
A `TEACHER` deletes a `User` record in MySQL. The static matrix states only `ADMIN` may delete `User`.
```
$ npx trailguard drift
Trailguard Drift Analysis
┌──────────┬──────────┬────────┬─────────┬──────────────┬────────────────────────────────────────────┐
│ Rule ID  │ Actor    │ Action │ Model   │ Sequence     │ Details                                    │
├──────────┼──────────┼────────┼─────────┼──────────────┼────────────────────────────────────────────┤
│ DRIFT001 │ TEACHER  │ DELETE │ User    │ seq #104     │ Forbidden by static matrix (ADMIN-only)    │
└──────────┴──────────┴────────┴─────────┴──────────────┴────────────────────────────────────────────┘
Result: 1 DRIFT violation(s) detected. Exit code 1.
```

---

## 5. Honest Limitations

As documented in `context.md §14` and `docs/THREAT_MODEL.md`:
1. **Heuristic Static Analysis:** AST analysis cannot execute dynamic expressions or evaluate runtime array spreads. Dynamic mount paths are flagged as `RBAC007` with low confidence.
2. **Probabilistic Ownership:** Ownership checks are classified as `probable` or `none` based on AST proximity and parameter signals; true authorization requires runtime verification.
3. **Declarative Matrix Scope:** The derived matrix models how routes are wired, not internal handler conditional branches.
4. **Tamper-Evident, Not Tamper-Proof:** An attacker with both DB root access and the HMAC signing key can forge new entries; historical integrity relies entirely on signed checkpoints shipped outside the database.
5. **Head Row Mutex Bottleneck:** Atomically serializing writes on `trailguard_audit_head` limits throughput to the maximum serialization rate of a single database row.
6. **Transaction Boundary Isolation:** Audited writes run in their own managed transaction; joining an external user-managed `$transaction` requires using `AuditChainService.log()` directly.
7. **External Direct SQL Bypasses:** Direct SQL modifications executed outside the application (e.g., via DBA consoles or external microservices) cannot be captured by the Node.js runtime extension.
8. **Read Auditing Excluded:** Read queries (`findUnique`, `findMany`) are not audited in v1 to preserve performance.

---

## 6. Conclusion

`trailguard` establishes an end-to-end security contract for Express and Prisma backends. By enforcing static route authorization in CI, recording mutations in an atomic HMAC hash chain, and continuously verifying database state against declared access policies, it bridges the gap between software design and operational auditability.
