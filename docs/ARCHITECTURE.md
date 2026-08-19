# Architecture

_Last updated: 2026-10-26_

## Overview

trailguard is a dual-purpose npm package for Express + Prisma + MySQL:

1. **Static scanner** — a dev-time AST analyser that walks your route tree and flags
   routes with missing auth, missing role checks, or missing audit instrumentation.
2. **Runtime audit log** — an HMAC-SHA256-chained log writer + Express router for
   tamper-evident recording of sensitive mutations.

---

## Package Structure

```
trailguard/
├── src/
│   ├── index.ts              # Runtime public API (no ts-morph)
│   ├── scan/
│   │   └── index.ts          # Static analysis public API
│   ├── cli.ts                # Commander CLI (thin wrapper only)
│   ├── config/
│   │   ├── schema.ts         # Zod config schema + defineConfig()
│   │   └── load.ts           # Config discovery + jiti loader
│   ├── core/
│   │   ├── types.ts          # Shared types (RouteNode, Finding, AuditEntry…)
│   │   ├── errors.ts         # Error hierarchy (TrailguardError, …)
│   │   └── constants.ts      # GENESIS_HASH, table names, etc.
│   ├── scan/                 # Static analyser internals (T1–T2)
│   │   ├── router/           # Express route walker
│   │   ├── rules/            # RBAC001–RBAC007, AUDIT001–AUDIT005
│   │   ├── matrix.ts         # Coverage matrix builder
│   │   └── report/           # Formatters (md, json, sarif)
│   └── runtime/              # Runtime internals (T3–T5)
│       ├── hmac.ts           # HMAC-SHA256 + canonical JSON
│       ├── writer.ts         # appendAuditLog()
│       ├── middleware.ts     # auditLog() Express middleware
│       ├── verify.ts         # Chain verification
│       └── router.ts         # /audit Express router
├── bin/
│   └── trailguard.js         # ESM shim → dist/cli.js
├── dist/                     # tsup output (gitignored)
│   ├── index.js + .d.ts      # Runtime entry
│   ├── scan/index.js + .d.ts # Scanner entry
│   └── cli.js                # CLI bundle
└── test/
    ├── unit/                 # Vitest unit tests (no DB)
    ├── scan/                 # Scan rule tests (fixture projects)
    └── integration/          # Vitest integration tests (MySQL required)
```

---

## Build System

**tsup** compiles three entry points from a single `tsconfig.json`:

| Entry | Output | Notes |
|-------|--------|-------|
| `src/index.ts` | `dist/index.js` | Runtime API; no ts-morph |
| `src/scan/index.ts` | `dist/scan/index.js` | Scanner; includes ts-morph |
| `src/cli.ts` | `dist/cli.js` | CLI; externalises commander |

All output is ESM (`"type": "module"`), targeting Node 18.

---

## Public API Surface

### Runtime (`import 'trailguard'`)

```ts
// Setup
createAuditClient(prisma, options): AuditClient

// Middleware factory
auditLog(client, options?): RequestHandler

// Router factory (GET /entries, GET /verify)
createAuditRouter(client, options?): Router

// Verification
verifyChain(client, options?): Promise<VerifyResult>

// Checkpoints
signCheckpoint(client, options?): Promise<Checkpoint>
```

### Scanner (`import 'trailguard/scan'`)

```ts
scan(options?): Promise<ScanResult>
defineConfig(config: UserConfig): UserConfig
loadConfig(configPath?: string): Promise<Config>
```

---

## Audit Log Chain Mechanics

```
Row N-1:
  seq:      N-1
  hash:     H(N-1) = HMAC(key, canonical({ seq, action, model, ... prevHash: H(N-2) }))

Row N:
  seq:      N
  prevHash: H(N-1)
  hash:     H(N) = HMAC(key, canonical({ seq, action, model, ... prevHash: H(N-1) }))
```

- **Genesis row** (seq=1): `prevHash = "0".repeat(64)`
- **Canonical JSON**: keys sorted, no whitespace, `null` for absent optional fields
- **Key rotation**: `keys` array; verification tries all provided keys in order

---

## Data Flow

```
HTTP Request
    │
    ▼
Express route handler
    │
    ├─ auditLog() middleware (wraps res.json / captures body)
    │       │
    │       ▼
    │  appendAuditLog(prisma, entry)
    │       │
    │       ├─ Lock AuditHead row (SELECT ... FOR UPDATE)
    │       ├─ Compute seq = head.seq + 1
    │       ├─ Compute prevHash = head.hash
    │       ├─ Compute hash = HMAC-SHA256(key, canonicalJSON(row))
    │       ├─ INSERT AuditLog row
    │       └─ UPDATE AuditHead (seq, hash)
    │
    └─ Response sent to client
```

---

## Configuration Resolution

1. CLI `--config <path>` → explicit path
2. Auto-discovery: walk from `process.cwd()` upward searching for
   `trailguard.config.{ts,js,mjs,json}`
3. Load via **jiti** (TS configs) or JSON.parse
4. Validate with **Zod** (strict schema, typo protection)
5. Resolve relative paths against config file's directory

---

## Key Design Constraints

- No `process.exit` outside `src/cli.ts`
- No `console.log` in library code (use structured return values)
- Runtime entry (`src/index.ts`) must never import `ts-morph`
- All errors extend `TrailguardError` and carry a `code` string
- `exactOptionalPropertyTypes: true` — conditional property assignment throughout
