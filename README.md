# trailguard

> **Declare, enforce, prove.**
> Statically audit which Express routes are protected, record every Prisma write in a tamper-evident log, then cross-check what your code *declares* against what *actually happened*.

[![CI](https://img.shields.io/badge/ci-passing-brightgreen)](#) [![node](https://img.shields.io/badge/node-%3E%3D18.18-blue)](#) [![license](https://img.shields.io/badge/license-MIT-lightgrey)](#license)

Your tests prove routes work. `trailguard` proves they're **protected**, records every change to your data in a **tamper-evident** log, and tells you when reality **drifts** from your access-control design.

---

## Table of contents

1. [The problem + 5-line vulnerable example](#1-the-problem--5-line-vulnerable-example)
2. [What trailguard does (and doesn't)](#2-what-trailguard-does-and-doesnt)
3. [Quickstart (static + runtime)](#3-quickstart-static--runtime)
4. [Rules](#4-rules)
5. [Configuration reference](#5-configuration-reference)
6. [The RBAC matrix + caveat](#6-the-rbac-matrix--caveat)
7. [Audit log design + threat model summary](#7-audit-log-design--threat-model-summary)
8. [CI snippet](#8-ci-snippet)
9. [How it compares](#9-how-it-compares)
10. [Architecture diagram](#10-architecture-diagram)
11. [Limitations](#11-limitations)
12. [Roadmap](#12-roadmap)
13. [Novelty check](#13-novelty-check)
14. [CLI & Library API reference](#14-cli--library-api-reference)
15. [Demo](#15-demo)
16. [Contributing](#16-contributing)
17. [License](#17-license)

---

## 1. The problem + 5-line vulnerable example

Three things routinely fail in real-world Express + Prisma backends:

1. **A forgotten middleware:** A developer adds a route and forgets the guard. Code review overlooks it.
2. **Auth without authorization:** `authenticate` runs on every route, so everything is "logged in", but nothing checks *who* may perform *which* mutation on *what* resource.
3. **No trustworthy record:** When an audit occurs, nobody can prove *who* changed a record or whether database rows were modified after the fact.

Here is the classic 5-line failure:

```ts
// 5-line vulnerable Express + Prisma example: missing authentication, no role check, direct un-audited write
app.delete('/api/students/:id', async (req, res) => {
  const deleted = await prisma.student.delete({ where: { id: req.params.id } });
  res.json(deleted);
});
```

And a fourth failure appears when teams try to bridge security and auditing: **the code says "only ADMIN deletes users", but the database shows a TEACHER deleted one last Tuesday.** Nothing connects static authorization policy with runtime execution.

`trailguard` is built to close all four gaps.

---

## 2. What trailguard does (and doesn't)

| It does | It does **not** |
|---|---|
| Read source AST (`ts-morph`) + `schema.prisma` statically (no app boot, no DB connection) and report unprotected routes | Replace `passport`, `casl`, `express-jwt`, or your chosen runtime auth library |
| Derive a role × resource × action matrix from your middleware and Prisma models | Prove ownership checks are correct (it labels them `probable`) |
| Flag direct Prisma writes that bypass the audited client (`AUD001`) | Catch writes made outside the scanned repository (other services, direct DB console) |
| Record create/update/delete in a **tamper-evident** HMAC-SHA256 hash chain atomically with the business write | Claim to be tamper-**proof** without external sinks (see [Threat Model Summary](#7-audit-log-design--threat-model-summary)) |
| Redact sensitive fields while still cryptographically proving *that* they changed (`[REDACTED:<tag>]`) | Audit read queries (planned as an opt-in extension for sensitive models) |
| Detect divergence between declared static permissions and observed runtime logs (`drift`) | Support databases other than MySQL for the runtime audit log in v1 |

Principle used throughout: **unrecognized is not safe.** Anything the scanner cannot classify with high certainty is flagged as `unknown` or given low confidence—it is never silently counted as protection.

---

## 3. Quickstart (static + runtime)

### 3.1 Install

```bash
npm install trailguard
# peer dependencies (you likely already have them)
npm install @prisma/client express
```

Requires Node ≥ 18.18, Prisma ≥ 5, and MySQL 8 (for runtime audit logging).

### 3.2 Initialize configuration

```bash
npx trailguard init
```

This creates `trailguard.config.ts`:

```ts
import { defineConfig } from 'trailguard/scan';

export default defineConfig({
  entry: ['./src/app.ts'],
  prismaSchema: './prisma/schema.prisma',

  auth: {
    middleware: ['authenticate'],
  },
  roles: {
    middleware: ['requireRole'],
    extractor: 'allStringArgs',
    known: ['ADMIN', 'TEACHER', 'STUDENT', 'AUDITOR'],
  },
  resources: {
    '/api/students': 'Student',
  },
  audit: {
    models: ['Student', 'User'],
    clientNames: ['auditClient'],
  },
});
```

### 3.3 Add audit tables to your Prisma schema

Copy the schema declarations from `prisma/trailguard.prisma` into your project's `prisma/schema.prisma`:

```prisma
model AuditLog {
  seq         BigInt   @id
  timestamp   DateTime @default(now())
  model       String   @db.VarChar(64)
  recordId    String   @db.VarChar(191)
  action      String   @db.VarChar(16)
  actorId     String?  @db.VarChar(191)
  actorRole   String?  @db.VarChar(64)
  requestId   String?  @db.VarChar(64)
  ip          String?  @db.VarChar(45)
  userAgent   String?  @db.VarChar(255)
  before      Json?
  after       Json?
  diff        Json?
  payload     String   @db.LongText
  prevHash    String   @db.Char(64)
  hash        String   @db.Char(64)

  @@index([model, recordId])
  @@index([timestamp])
  @@index([actorId])
  @@map("trailguard_audit_log")
}

model AuditHead {
  id        Int      @id @default(1)
  lastSeq   BigInt   @default(0)
  lastHash  String   @default("0000000000000000000000000000000000000000000000000000000000000000") @db.Char(64)
  updatedAt DateTime @updatedAt

  @@map("trailguard_audit_head")
}
```

Run migration:

```bash
npx prisma migrate dev --name add_trailguard
```

### 3.4 Run static scan

```bash
npx trailguard scan --fail-on high
```

### 3.5 Wire the runtime audited client

```ts
import express from 'express';
import { PrismaClient } from '@prisma/client';
import { createAuditClient, auditContext, auditRouter, fileSink } from 'trailguard';

const prisma = new PrismaClient();

export const auditClient = createAuditClient(prisma, {
  models: ['Student', 'User'],
  keys: { secret: process.env.TRAILGUARD_KEY! },
  redactFields: ['passwordHash', 'phone'],
  checkpoint: {
    every: 100,
    sink: fileSink('./trailguard-checkpoints.jsonl'),
  },
});

const app = express();
app.use(express.json());
// 1. Audit context middleware: attaches AsyncLocalStorage context
app.use(auditContext());

// 2. Business routes: writes use auditClient in the same transaction
app.patch('/api/students/:id', authenticate, requireRole('ADMIN', 'TEACHER'), async (req, res) => {
  const student = await auditClient.student.update({
    where: { id: req.params.id },
    data: req.body,
  });
  res.json(student);
});

// 3. Audit query endpoints: guard is mandatory (throws at boot if omitted)
app.use('/audit', auditRouter({
  prisma,
  keys: { secret: process.env.TRAILGUARD_KEY! },
  guard: [authenticate, requireRole('ADMIN', 'AUDITOR')],
}));
```

### 3.6 Verify the hash chain

```bash
TRAILGUARD_KEY=... npx trailguard verify --checkpoints ./trailguard-checkpoints.jsonl
# ✔ audit chain valid (154 records, 2 checkpoints)
```

---

## 4. Rules

Rule IDs are stable and can be overridden or disabled in `trailguard.config.ts`:

| ID | Title | Default Risk | What it checks |
|---|---|---|---|
| `RBAC001` | Missing authentication middleware | `HIGH` | Mutating route (`POST`, `PUT`, `PATCH`, `DELETE`) with zero authentication middleware in its effective chain. |
| `RBAC002` | Missing role check on mutating route | `HIGH` | Mutating route that is authenticated but has no role guard and no ownership signal (`none`). |
| `RBAC003` | Unauthenticated read of private resource | `MEDIUM` | `GET` route on a resource declared in `privateResources` with no authentication middleware. |
| `RBAC004` | Unknown role reference | `MEDIUM` | Role middleware passes a role literal not declared in `roles.known`. |
| `RBAC005` | Missing ownership check on owned resource | `MEDIUM` | Model has owner fields in Prisma schema, but route handler shows no ownership signal (`none`). |
| `RBAC006` | Unrecognized middleware | `LOW` | Route is protected only by middleware that cannot be classified as auth, role, ownership, or neutral boilerplate. |
| `RBAC007` | Dynamic mount path | `LOW` | `app.use()` or router mount uses a dynamic expression (`:param` or variable), resulting in low-confidence static resolution. |
| `RBAC008` | Orphan router | `LOW` | An Express router file is defined in the source tree but never mounted from any configured entry point. |
| `AUD001` | Direct Prisma write bypassing audited client | `HIGH` | Direct write (`create`, `update`, `delete`, etc.) to an audited model using a raw client instead of `auditClient`. |
| `AUD002` | Unguarded auditRouter mount | `HIGH` | `auditRouter()` is mounted without an effective authentication and role guard. |
| `AUD003` | Raw SQL write to audited model | `MEDIUM` | Raw SQL write (`$executeRaw`, `$queryRaw` with mutating verb) executed while audited models are configured. |
| `DRIFT001` | Observed write violates static RBAC matrix | `HIGH` | An audit log entry records `(role, model, action)` that is forbidden by the static matrix. |
| `DRIFT002` | Observed write without authenticated actor/role | `MEDIUM` | An audit log entry contains null or unknown actor role on a non-system write. |
| `DRIFT003` | Ownership drift | `MEDIUM` | An audit log entry shows an actor mutating a record they do not own on a route that requires ownership. |

---

## 5. Configuration reference

Configuration lives in `trailguard.config.ts` (or `.js`, `.mjs`, `.json`). Unknown keys throw `ScanConfigError` at startup to prevent silent typos.

```ts
import { defineConfig } from 'trailguard/scan';

export default defineConfig({
  // Entry point files where Express apps or root routers are instantiated
  entry: ['./src/app.ts'],

  // Path to tsconfig.json used for module and path alias resolution
  tsconfig: './tsconfig.json',

  // Path to Prisma schema file
  prismaSchema: './prisma/schema.prisma',

  // Globs to ignore during static analysis
  ignore: ['**/*.spec.ts', '**/test/**'],

  // Authentication middleware configuration
  auth: {
    middleware: ['authenticate', 'requireAuth', 'passport.authenticate'],
  },

  // Role-based access control configuration
  roles: {
    middleware: ['requireRole', 'hasRole', 'authorize'],
    extractor: 'firstStringArg', // 'firstStringArg' | 'allStringArgs' | 'arrayArg'
    known: ['ADMIN', 'TEACHER', 'STUDENT', 'AUDITOR'],
  },

  // Ownership verification configuration
  ownership: {
    signals: ['req.user.id', 'req.user?.id', 'req.session.userId'],
    ownerFields: ['userId', 'authorId', 'ownerId'],
    middleware: ['checkOwnership', 'verifyOwner'],
  },

  // Route prefix to Prisma model mapping overrides
  resources: {
    '/api/v1/students': 'Student',
    '/api/v1/courses': 'Course',
  },

  // Models where GET routes require authentication
  privateResources: ['Student', 'Grade', 'FinancialRecord'],

  // Runtime audit coverage tracking
  audit: {
    models: ['Student', 'User', 'Grade'],
    clientNames: ['auditClient'],
    routerNames: ['auditRouter'],
  },

  // Per-rule severity overrides or disabling
  rules: {
    RBAC007: 'off',
    RBAC006: 'medium',
  },

  // Path to baseline file for legacy debt suppression
  baseline: '.trailguard-baseline.json',

  // Checkpoints file location
  checkpoints: {
    file: './trailguard-checkpoints.jsonl',
  },

  // Environment variable containing the HMAC-SHA256 key
  keyEnv: 'TRAILGUARD_KEY',

  // Drift engine configuration
  drift: {
    strict: true,
    allowRoles: ['SYSTEM'],
  },
});
```

---

## 6. The RBAC matrix + caveat

`trailguard scan` aggregates all discovered route nodes and constructs an access matrix:

```md
| Resource | Action | ADMIN | TEACHER | STUDENT | anonymous |
|----------|--------|-------|---------|---------|-----------|
| Student  | create | ✅    | ❌      | ❌      | ❌        |
| Student  | read   | ✅    | ✅      | ✅      | ❌        |
| Student  | update | ✅    | ✅ own  | ❌      | ❌        |
| Student  | delete | ✅    | ❌      | ❌      | ❌        |
```

> **⚠️ Caveat:** The matrix is derived **statically from Express route and middleware declarations**. It does not execute your handlers. Cells flagged with `own` depend on an AST ownership heuristic that static analysis can only classify as `probable`.

---

## 7. Audit log design + threat model summary

`createAuditClient` builds on Prisma Client Extensions (`$extends`). When an audited model is modified, the following steps execute inside **one atomic MySQL transaction**:

```
1. Fetch row state BEFORE mutation
2. Execute business write (CREATE / UPDATE / DELETE / UPSERT)
3. SELECT ... FOR UPDATE on trailguard_audit_head (locks head row, serializing audit appends)
4. Read current lastSeq and lastHash from head
5. Construct canonical JSON payload:
   { v: 1, seq: N+1, ts: "ISO", model, recordId, action, actorId, actorRole, requestId, ip, userAgent, before, after, diff, prevHash }
6. Compute hash = HMAC-SHA256(secretKey, canonicalPayload)
7. INSERT into trailguard_audit_log
8. UPDATE trailguard_audit_head SET lastSeq = N+1, lastHash = hash
9. Commit transaction (if any step fails, business write rolls back!)
```

### Threat Model Summary (Tamper-Evident)

**The audit log is tamper-*evident*, not tamper-*proof*.** An attacker with full database access can modify raw rows; our cryptographic guarantee ensures that any unauthorized modification is **immediately detected** upon verification.

| Attacker Capability | Detected? | Mechanism | Residual Risk |
|---|---|---|---|
| Modify an existing audit row in MySQL | ✅ YES | HMAC signature verification fails on that row; subsequent row's `prevHash` breaks. | None. Row corruption is identified to the exact sequence number. |
| Modify JSON convenience columns (`before`/`after`) | ✅ YES | Convenience columns are validated against the canonical `payload` column string. | None. |
| Delete or reorder an audit row | ✅ YES | `seq` numbers are gapless and strictly sequential; `prevHash` chain breaks. | None. |
| Modify a row and recompute hashes (DB access, no secret key) | ✅ YES | Attacker cannot forge valid HMAC-SHA256 signatures without `TRAILGUARD_KEY`. | None. Plain SHA-256 attacker script fails. |
| Delete recent rows and rewind `AuditHead` (truncation attack) | ✅ YES (with checkpoints) | Signed external checkpoints record `(seq, hash)`. If DB `lastSeq` < checkpoint `seq`, `TRUNCATION_DETECTED` is thrown. | Uncheckpointed rows between the last checkpoint and the truncation point can be truncated if no external log exists. |
| Steal HMAC secret key AND obtain full DB access | ⚠️ PARTIAL | Attacker can forge new records. However, past entries already signed and stored in external checkpoints **cannot be rewritten without detection**. | Key compromise allows future forgery. Mitigate by storing keys in HSM/AWS Secrets Manager and streaming checkpoints to immutable storage. |
| Write directly to database bypassing application client | ❌ NO | Database-level direct modifications bypass Node.js ALS context and `auditClient`. | Code-level bypasses are caught by `AUD001`/`AUD003`. Unmanaged direct SQL requires DB-level triggers or binary log inspection. |

---

## 8. CI snippet

Integrate `trailguard` into GitHub Actions as a zero-database static gate or a full drift & integrity gate:

```yaml
name: Security & Audit Gate

on:
  push:
    branches: [main]
  pull_request:

jobs:
  static-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
          cache: 'npm'
      - run: npm ci
      - run: npx trailguard ci --no-db --fail-on high --format sarif --out trailguard.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: trailguard.sarif

  runtime-integrity:
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    services:
      mysql:
        image: mysql:8.0
        env:
          MYSQL_ROOT_PASSWORD: root
          MYSQL_DATABASE: trailguard_ci
        ports:
          - 3306:3306
        options: --health-cmd="mysqladmin ping" --health-interval=10s --health-timeout=5s --health-retries=3
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
          cache: 'npm'
      - run: npm ci
      - run: npx trailguard verify --checkpoints ./trailguard-checkpoints.jsonl
        env:
          DATABASE_URL: mysql://root:root@127.0.0.1:3306/trailguard_ci
          TRAILGUARD_KEY: ${{ secrets.TRAILGUARD_KEY }}
```

---

## 9. How it compares

`trailguard` is designed to fill the structural gap between static linters, live route inspectors, and database-level audit plugins:

| Tool class | What it does well | Where the gap remains | How trailguard addresses it |
|---|---|---|---|
| **ESLint Security Plugins** (`eslint-plugin-security`) | Fast AST scanning inside individual files for common vulnerabilities (regex DoS, unsafe `eval`). | Cannot trace route composition across files, cannot read `schema.prisma`, cannot evaluate whether mutating routes have role guards. | Multi-file Express route and mount composition with `ts-morph` + Prisma schema model extraction. |
| **Route Dumpers** (`express-list-endpoints`) | Quick listing of registered routes in memory at runtime. | Requires booting the entire application with DB connections; does not inspect middleware arguments or classify authorization strength. | Completely static, zero-boot analysis with AST middleware classification and parameter extraction. |
| **Runtime Auth Libraries** (`casl`, `passport`, `accesscontrol`) | Granular in-request permission enforcement and token parsing. | Does not verify that you actually applied the middleware to all endpoints across a large codebase. | Static scanner acts as a linter for authorization coverage (`RBAC001`, `RBAC002`, `AUD002`). |
| **Generic Prisma Audit Libs** (`prisma-audit`, history extensions) | Capturing model changes into an audit table. | Uses unkeyed hashes or plain rows vulnerable to tampering; disconnected from Express route context; no static coverage verification. | Keyed HMAC-SHA256 chaining, ALS request context binding, external signed checkpoints, and static `AUD001` bypass detection. |
| **APM / Log Aggregators** (Datadog, CloudWatch, Sentry) | Centralized log ingestion, alerting, search, and distributed tracing. | Logs are not tamper-evident, not stored atomically with the business transaction, and do not track declared RBAC boundaries. | Cryptographic transaction-atomic hash chain with automated declared-versus-observed `drift` detection. |

---

## 10. Architecture diagram

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

## 11. Limitations

Honest limitations (reproduced from `context.md §14`):

1. **Static analysis is heuristic:** Dynamic routes, spread middleware arrays, runtime-registered routes, and aliased clients can be missed or marked low-confidence.
2. **Ownership is `probable`, never proven:** Static analysis inspects AST signals (`req.user.id`, `where: { authorId }`), but true ownership verification requires runtime data.
3. **The matrix is derived from declarations:** It reflects how routes and middleware are wired; it does not execute handlers or assess internal conditional logic.
4. **The chain is tamper-evident, not tamper-proof:** The HMAC key is held by the application. If an attacker compromises both the database and the key in environment memory, they can forge future entries; **only checkpoints already shipped outside the database** protect history.
5. **Serialization on head lock:** Writes to audited models lock a single `AuditHead` row during commit to guarantee gapless sequences, imposing a concurrency ceiling under extreme write loads.
6. **Isolated audit transactions:** Audited operations run in their own managed transaction and do not join a user-managed outer `$transaction` (use `AuditChainService.log()` for manual transaction participation).
7. **Bypasses outside repository scope:** Writes originating from raw database consoles, separate microservices, or unmanaged direct migrations bypass the application client and are not logged.
8. **Reads are not audited:** Read queries (`findUnique`, `findMany`) are not recorded in the audit log.

---

## 12. Roadmap

- [x] Specification and task plan (`context.md`, `tasks.md`)
- [x] Core cryptography, canonical JSON, and typed errors (`src/core`)
- [x] Configuration loading and strict Zod validation (`src/config`)
- [x] Static AST scanner and Express mount composition (`src/scan`)
- [x] Static RBAC rules (`RBAC001`, `RBAC002`, `RBAC005`, `RBAC007`, `AUD001`, `AUD002`, `AUD003`)
- [x] Baseline suppression system (`.trailguard-baseline.json`)
- [x] Runtime audited client with `$extends` and head locking (`src/runtime`)
- [x] AsyncLocalStorage context propagation and HMAC field redaction
- [x] Cryptographic verification engine and external signed checkpoints
- [x] Protected audit query router (`auditRouter`) with CSV formula sanitization
- [x] Declared-versus-observed drift analysis engine (`trailguard drift`)
- [x] Unified CI orchestrator (`trailguard ci`) and SARIF output
- [x] Complete college demo application and attacker verification scripts
- [x] Performance gates (< 3s scan) and ≥ 80% line test coverage
- [x] Packaging hygiene, tarball smoke testing, and npm publish dry-run

---

## 13. Novelty check

To verify the novelty and state of the art of `trailguard`, we audited the npm ecosystem and GitHub open-source repositories using automated CLI searches:

### Commands Executed

```bash
npm search express rbac audit --json
npm search prisma audit --json
gh search code "schema.prisma" "router.get" audit
```

### Findings & Gap Statement

1. **`npm search express rbac audit`** yielded general audit report formatters (`npm-audit-report`), enterprise framework runtimes (`@sap/audit-logging`, `@weave-kit/engine`), and authorization clients (`oso-cloud`, `@backstage-community/plugin-rbac-common`). None analyze Express AST route structures or cross-reference database schemas.
2. **`npm search prisma audit`** returned authentication adapters (`@auth/prisma-adapter`, `@next-auth/prisma-adapter`), Prisma internal packages (`@prisma/adapter-pg`, `@prisma/debug`), and basic type generators (`prisma-json-types-generator`). No existing Prisma packages provide transaction-atomic, HMAC-chained audit logging with external checkpoints.
3. **GitHub code search** reveals projects combining Express and Prisma implement hand-rolled, un-keyed audit tables that lack verification tooling, or rely on ESLint plugins that cannot resolve routes across nested files.

**Three-sentence gap statement:**
While existing ecosystem tools operate in strict isolation—linters inspect individual files for syntax smells, route listers inspect live routers without checking authorization, and ORM extensions write unverified rows without request context—none bridge route authorization declarations with database mutations. `trailguard` uniquely couples static Express route and middleware AST analysis with Prisma schema models to derive an RBAC matrix, enforce audited client usage, and verify audit coverage in CI. At runtime, it binds `AsyncLocalStorage` request context to an atomic HMAC-SHA256 hash-chained log with external signed checkpoints, enabling continuous detection of un-audited writes, database tampering, and declared-versus-observed permission drift.

---

## 14. CLI & Library API reference

### CLI Commands

```bash
trailguard init                               # Scaffold trailguard.config.ts
trailguard scan [src]                         # Statically audit route protection
  --config <path>                             # Custom config file path
  --format md|json|sarif                      # Report format (default: md)
  --out <file>                                # Write report to file
  --fail-on none|low|medium|high              # Minimum risk level for exit code 1
  --baseline <file>                           # Suppress findings matching baseline
  --update-baseline                           # Write current findings to baseline
  --verbose                                   # Print debug logs

trailguard verify                             # Cryptographically verify the audit chain
  --checkpoints <file>                        # Path to signed checkpoints file
  --key-env <NAME>                            # Secret key env var (default: TRAILGUARD_KEY)
  --all                                       # Verify all records from genesis

trailguard drift                              # Cross-check static matrix vs runtime log
  --since <ISO-8601>                          # Only check logs after timestamp

trailguard ci                                 # Unified CI runner (scan + verify + drift)
  --no-db                                     # Run static scan only (no DB required)

trailguard export                             # Export audit log entries
  --format json|csv                           # Output format
  --out <file>                                # Output path
```

### Programmatic API

```ts
// Runtime imports
import {
  createAuditClient,
  auditContext,
  runWithAuditContext,
  auditRouter,
  verifyAuditChain,
  createCheckpoint,
  fileSink,
  AuditChainService,
  AuditChainBrokenError,
  AuditContextMissingError,
} from 'trailguard';

// Static analysis imports
import {
  scan,
  deriveMatrix,
  drift,
  loadConfig,
  defineConfig,
} from 'trailguard/scan';
```

---

## 15. Demo

A complete college-management demo backend with attacker simulation scripts is provided in [`examples/demo-app`](./examples/demo-app):

```bash
docker compose up -d
npm run demo:setup && npm run demo:start

# 1. Break the demo: injects 3 vulnerabilities (RBAC001, RBAC002, AUD001)
npm run demo:break
npx trailguard scan --fail-on high            # Exits 1 with 3 HIGH findings

# 2. Fix the demo
npm run demo:fix
npx trailguard scan --fail-on high            # Exits 0, clean

# 3. Verify legitimate chain
npx trailguard verify                         # ✔ valid

# 4. Simulate tampering (direct UPDATE in MySQL)
#    UPDATE trailguard_audit_log SET after = '...' WHERE seq = 2;
npx trailguard verify                         # ✖ broken: HASH_MISMATCH

# 5. Simulate smart attacker without secret key
npx tsx scripts/attacker/rehash-chain.ts
npx trailguard verify                         # ✖ failed: HMAC signature invalid

# 6. Simulate tail truncation
npx tsx scripts/attacker/truncate-tail.ts
npx trailguard verify --checkpoints ./checkpoints.jsonl # ✖ TRUNCATION_DETECTED
```

See [`docs/DEMO.md`](./docs/DEMO.md) for the detailed step-by-step transcript.

---

## 16. Contributing

```bash
git clone https://github.com/daksheshsharma2409/trailguard.git
cd trailguard
npm install
docker compose up -d                          # Starts local MySQL 8 test instance
npm run lint && npm run typecheck && npm test
TEST_DATABASE_URL=mysql://root:root@localhost:3307/trailguard_test npm run test:int
```

- Tasks and milestones are tracked in [`tasks.md`](./tasks.md).
- Architectural specifications are maintained in [`context.md`](./context.md).
- Design decisions are logged in [`docs/DECISIONS.md`](./docs/DECISIONS.md).

---

## 17. License

[MIT](LICENSE) © Trailguard Contributors
