# Architecture

_Last updated: 2026-10-26_

## 1. System Overview

`trailguard` is a dual-purpose TypeScript package designed specifically for the **Express + Prisma + PostgreSQL** stack:

1. **Static Analysis Scanner (`trailguard/scan` + CLI `trailguard scan`):**
   A developer-time and CI AST analyzer that inspects route declarations, middleware chains, and Prisma schemas without booting the application or connecting to a database. It derives an access matrix and flags unprotected mutating routes, missing role checks, and direct Prisma writes that bypass the audit client.

2. **Tamper-Evident Runtime Audit Log (`trailguard` + CLI `trailguard verify`):**
   An HMAC-SHA256 hash-chained transaction logger implemented via Prisma Client Extensions (`$extends`). Mutations on audited models atomically record pre-images, post-images, diffs, and cryptographic hash chains under PostgreSQL row locks (`SELECT ... FOR UPDATE`), with external signed checkpoints to prevent truncation.

3. **Verification & Drift Engine (`trailguard drift` + `trailguard ci`):**
   The bridge comparing statically declared permissions against observed runtime audit records to surface operational permission drift.

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

## 3. Module Responsibilities

The codebase is organized into modular layers with strict separation between runtime execution and static analysis:

### 3.1 `src/core/` — Foundational Utilities & Types
- **`types.ts`:** Central type declarations including `RouteNode`, `Finding`, `AuditLogEntry`, `MatrixCell`, `Risk`, and `Confidence`.
- **`errors.ts`:** Domain error hierarchy rooted at `TrailguardError` (`AuditChainBrokenError`, `AuditContextMissingError`, `AuditConfigError`, `AuditWriteError`, `ScanConfigError`, `ScanParseError`), all carrying structured `.code` properties.
- **`crypto.ts`:** Cryptographic operations using Node.js `node:crypto`: HMAC-SHA256 computation, constant-time equality comparisons (`timingSafeEqual`), and random hex generation.
- **`canonical.ts`:** Deterministic JSON serialization adhering to RFC 8785 (sorted object keys, strict numeric formatting, BigInt/Date serialization).
- **`constants.ts`:** System constants including `GENESIS_HASH` (64 zeros), table names (`trailguard_audit_log`, `trailguard_audit_head`), and default configuration paths.

### 3.2 `src/config/` — Configuration Discovery & Schema
- **`schema.ts`:** Zod schema defining the configuration contract (`auth`, `roles`, `ownership`, `resources`, `audit`, `rules`, `checkpoints`, `drift`). Configured with `.strict()` to reject unknown keys and catch typos. Provides `defineConfig()` helper.
- **`load.ts`:** Discovers `trailguard.config.{ts,js,mjs,json}` walking upward from working directory. Uses `jiti` to dynamically evaluate TypeScript configurations without precompilation.

### 3.3 `src/scan/` — Static AST Analysis Engine
- **`project.ts`:** Configures and initializes the in-memory or filesystem `ts-morph` AST Project, loading source files and resolving compiler options.
- **`routes.ts`:** Traverses Express source files to detect route declarations (`app.get`, `router.post`, `router.route().delete()`), recording source files and line numbers.
- **`mounts.ts`:** Resolves Express mount trees (`app.use('/prefix', childRouter)`), recursively composing full paths and attaching inherited mount-level middleware chains.
- **`handlers.ts`:** AST resolver unwrapping arrow functions, function expressions, identifiers, and imported handlers to inspect route execution logic.
- **`classify.ts`:** Evaluates route middleware against configured rules. Classifies middleware as `auth`, `role:<x>`, `ownership`, `neutral` (framework boilerplate like `express.json`), or `unknown`. Supports `firstStringArg`, `allStringArgs`, and `arrayArg` role extractors.
- **`resources.ts`:** Maps route paths to Prisma models using a dual-layer approach: longest-prefix match on configured `resources` overrides, falling back to RESTful singularization heuristics.
- **`prisma-schema.ts`:** Hand-written Prisma schema parser (eliminating heavy `@prisma/internals` runtime dependencies). Parses models, fields, types, `@@map` attributes, and comments to extract models and owner fields.
- **`prisma-writes.ts`:** Scans AST call expressions to identify mutating Prisma operations (`create`, `update`, `delete`, `upsert`, `createMany`, `updateMany`, `deleteMany`) and flags whether they use `auditClient` or raw `prisma`.
- **`ownership.ts`:** AST heuristic evaluating whether a route handler checks ownership (e.g., verifying `where: { authorId: req.user.id }` or binary equality checks). Classifies confidence as `probable` or `none`.
- **`matrix.ts`:** Synthesizes route nodes and Prisma models into a 2D access matrix across CRUD actions and roles.
- **`findings.ts`:** Executes static rules, applies risk overrides, and computes deterministic fingerprints (excluding line numbers) for baseline stability.
- **`baseline.ts`:** Reads and updates `.trailguard-baseline.json` to suppress legacy technical debt in CI.
- **`rules/`:** Modular rule implementations:
  - `rbac001`: Mutating route missing authentication.
  - `rbac002`: Mutating route missing role guard.
  - `rbac005`: Mutating route missing ownership check on owned resource.
  - `rbac007`: Dynamic mount path detected.
  - `aud001`: Direct Prisma write bypassing audited client.
  - `aud002`: Unguarded `auditRouter` mount.
  - `aud003`: Raw SQL write to audited model.
- **`report/`:** Renders findings and matrices into Markdown (`formatMarkdownReport`), JSON (`formatJsonReport`), and SARIF v2.1.0 (`formatSarifReport`).
- **`drift.ts`:** Evaluates PostgreSQL audit log entries against the static RBAC matrix to detect unauthorized mutations (`DRIFT001`), missing actor roles (`DRIFT002`), and ownership violations (`DRIFT003`).
- **`scan.ts`:** Top-level orchestration function tying project loading, schema parsing, mount resolution, rule execution, and reporting together.

### 3.4 `src/runtime/` — Runtime Audit Logging & Integrity
- **`context.ts`:** Manages `AsyncLocalStorage` request lifecycle. Stores actor ID, actor role, IP, user-agent, and request ID. Evaluates actor lazily at write time so authentication middleware can run after context initialization.
- **`client.ts`:** Factory `createAuditClient()` using Prisma Client Extensions (`$extends`). Intercepts `create`, `update`, `delete`, and `upsert` queries on configured models.
- **`append.ts`:** Core atomic writer. Fetches pre-images, applies mutations, acquires row lock on `AuditHead` (`SELECT ... FOR UPDATE`), serializes canonical payloads, computes HMAC-SHA256, and inserts the audit record.
- **`diff.ts`:** Canonical JSON diff engine computing `{ [field]: { old, new } }` changes.
- **`redact.ts`:** Replaces configured sensitive fields with deterministic 4-hex-character HMAC tags (`[REDACTED:<tag>]`) prior to diffing and persistence.
- **`verify.ts`:** Verifies cryptographic integrity of the database audit log. Checks hash signatures, gapless sequence numbers, canonical payload parity, and compares against external checkpoints.
- **`checkpoint.ts`:** Creates cryptographic commitments of `(seq, hash, ts, keyId)` and writes them to external sinks (`fileSink`, stdout).
- **`history.ts`:** Provides timeline querying for specific models and record IDs with pagination support.
- **`service.ts`:** `AuditChainService` facade class enabling manual integration of audit logging inside user-managed `$transaction` blocks.
- **`router.ts`:** Express router exposing `/logs`, `/history`, `/verify`, and `/export` (supporting CSV with spreadsheet formula injection protection). Requires a mandatory authorization guard.

### 3.5 `src/cli.ts` — Command-Line Interface
Thin CLI runner built on Commander. Parses arguments and options, sets process exit codes (`0` clean, `1` findings/violations, `2` operational errors), and delegates entirely to `src/scan/index.js` or `src/index.js`.

---

## 4. Build Architecture & Separation of Concerns

The build system (`tsup.config.ts`) outputs three distinct ESM targets:

| Bundle Output | Source Entry | Dependencies Included | Notes |
|---|---|---|---|
| `dist/index.js` | `src/index.ts` | Node crypto, Prisma extension types | **Zero `ts-morph` footprint.** Safe for production microservices and serverless lambdas. |
| `dist/scan/index.js` | `src/scan/index.ts` | `ts-morph`, `jiti`, Zod | Static analysis API for developer tools and CI runners. |
| `dist/cli.js` | `src/cli.ts` | Commander, scanner, runtime verifier | Executable CLI invoked via `bin/trailguard.js`. |

---

## 5. Data Flow Specifications

### 5.1 Runtime Mutation Lifecycle

```
Client HTTP Request
   │
   ▼
app.use(auditContext()) ──────────▶ Stores AsyncLocalStorage store { requestId, ip, userAgent }
   │
   ▼
app.use(authenticate)   ──────────▶ Attaches req.user (actorId, role)
   │
   ▼
Route Handler           ──────────▶ Calls auditClient.student.update({ where, data })
   │
   ▼
Prisma $extends Query Extension:
   │
   ├─ 1. Enter $transaction (Serializable / Read Committed)
   ├─ 2. SELECT * FROM Student WHERE id = :id (Pre-image snapshot)
   ├─ 3. Execute business UPDATE
   ├─ 4. Redact sensitive fields in 'before' and 'after' records
   ├─ 5. Compute field-level diff
   ├─ 6. SELECT * FROM trailguard_audit_head FOR UPDATE (Acquires row lock)
   ├─ 7. seq = head.lastSeq + 1, prevHash = head.lastHash
   ├─ 8. Construct RFC 8785 canonical JSON payload
   ├─ 9. hash = HMAC-SHA256(secretKey, canonicalPayload)
   ├─ 10. INSERT INTO trailguard_audit_log (seq, payload, hash, prevHash, ...)
   ├─ 11. UPDATE trailguard_audit_head SET lastSeq = seq, lastHash = hash
   ├─ 12. Checkpoint check: If (seq % every === 0), emit signed checkpoint
   └─ 13. COMMIT (Business write and audit entry commit atomically)
```

### 5.2 Verification Lifecycle

```
trailguard verify --checkpoints checkpoints.jsonl
   │
   ├─ 1. Load checkpoints from file (validate signatures)
   ├─ 2. Query trailguard_audit_head
   ├─ 3. Assert dbLastSeq >= highest checkpoint seq (Detects tail truncation)
   ├─ 4. Stream audit log rows ordered by seq ASC from seq 1
   ├─ 5. For each row:
   │      ├─ Assert seq is strictly sequential (no gaps)
   │      ├─ Assert row.prevHash === expectedPreviousHash
   │      ├─ Recompute HMAC-SHA256(secretKey, row.payload) === row.hash
   │      ├─ Validate convenience JSON columns against payload
   │      └─ If row matches a checkpoint, assert row.hash === checkpoint.hash
   └─ 6. Return { valid: true, checkedRecords: N }
```
