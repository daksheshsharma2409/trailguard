# context.md — `trailguard`

> Single source of truth for the project. Read this fully before writing code.
> If this file and a task in `tasks.md` disagree, **stop and ask**; do not guess.
> If you make a design decision not covered here, append it to `docs/DECISIONS.md` (one short entry: date, decision, why).

---

## 0. One-paragraph summary

`trailguard` is a single npm package (TypeScript, ESM) for **Express + Prisma + PostgreSQL** backends. It has two halves that talk to each other:

1. **Static side (pre-deployment):** `trailguard scan` reads source with `ts-morph` + `schema.prisma` (no app boot, no DB) and reports which Express routes are unprotected (no auth / no role check / no ownership signal), derives a **role × resource × action matrix**, and finds Prisma writes that **bypass the audited client**.
2. **Runtime side (post-deployment):** an audited Prisma client (`$extends`) records every create/update/delete in a **tamper-evident, HMAC-chained, append-only audit log**, with actor context from `AsyncLocalStorage`, redaction, diffs, signed external checkpoints, a verify function, and a guarded Express router.
3. **Bridge:** `trailguard drift` compares what the code *declares* (static matrix) against what *actually happened* (audit log). `trailguard ci` runs scan → verify → drift with one exit code.

Tagline: **Declare, enforce, prove.**

---

## 1. Goals and non-goals

### Goals
- Real, publishable npm package with a library API **and** a CLI (CLI is a thin wrapper over the library).
- Honest, deterministic, fixture-tested static analysis. **Unrecognized ≠ safe.**
- Tamper-*evident* audit log that survives a "smart attacker" who has DB write access (HMAC + external checkpoints).
- Atomic business-write + audit-write (one DB transaction).
- Excellent demo: vulnerable → fix → audit → tamper → detect → drift.

### Non-goals (do NOT build)
- Runtime auth library (not competing with passport/casl).
- VS Code extension, web dashboard, `--fix` auto-patching, OpenAPI diff, webhooks.
- Support for databases other than PostgreSQL (runtime side). Static side only reads `schema.prisma`, so any provider parses.
- Support for frameworks other than Express 4/5.
- Full automatic proof of ownership checks (impossible statically; we label `probable`).
- Composite-primary-key perfection (basic support only, see §7.7).

---

## 2. Tech stack and constraints

| Concern | Choice |
|---|---|
| Language | TypeScript 5.x, `strict: true`, `noUncheckedIndexedAccess: true` |
| Module system | ESM only. `"type": "module"`, `moduleResolution: "NodeNext"`; relative imports use `.js` extension |
| Node | `>=18.18` (CI matrix: 18, 20, 22) |
| Build | `tsup` (entries: `src/index.ts`, `src/scan/index.ts`, `src/cli.ts`), emit `.d.ts` |
| Tests | `vitest`; `supertest` for HTTP; PostgreSQL 16 via `docker-compose.yml` for integration tests |
| AST | `ts-morph` |
| CLI | `commander` |
| Validation | `zod` |
| TS/JS config loading | `jiti` (so `trailguard.config.ts` works without compiling) |
| Hashing | Node built-in `node:crypto` only (HMAC-SHA256). No third-party crypto |
| ORM | Prisma `>=5.0` (peer dep, `@prisma/client`). Uses `$extends` |
| Lint/format | `eslint` + `prettier` (basic config), `tsc --noEmit` in CI |

### Dependency rules
- `dependencies`: `ts-morph`, `commander`, `zod`, `jiti`. **Nothing else** without a `docs/DECISIONS.md` entry.
- `peerDependencies`: `@prisma/client >=5`, `express >=4` (**both optional via `peerDependenciesMeta`**; static-only users don't need them at runtime; `express` types only needed for `auditRouter`/`auditContext`).
- Runtime entry (`trailguard`) must **not import `ts-morph`** (keeps app startup light). Static entry (`trailguard/scan`) may.
- `devDependencies`: everything for tests/build, including `express`, `@prisma/client`, `prisma`, `supertest`.

---

## 3. Repository layout

```
trailguard/
├── src/
│   ├── index.ts                    # RUNTIME public API (no ts-morph)
│   ├── cli.ts                      # commander wiring only; no logic
│   ├── core/
│   │   ├── errors.ts               # error class hierarchy
│   │   ├── canonical.ts            # stableStringify (canonical JSON)
│   │   ├── crypto.ts               # hmac(), deriveKey(), timingSafeEqualHex()
│   │   ├── constants.ts            # GENESIS_HASH, PAYLOAD_VERSION, table names
│   │   └── types.ts                # shared types (see §10)
│   ├── config/
│   │   ├── schema.ts               # zod schema + inferred Config type + defineConfig()
│   │   └── load.ts                 # loads .ts/.js/.mjs/.json via jiti; applies defaults
│   ├── runtime/
│   │   ├── client.ts               # createAuditClient (Prisma $extends)
│   │   ├── context.ts              # AsyncLocalStorage, auditContext() middleware, runWithAuditContext()
│   │   ├── append.ts               # lock head + append HMAC-chained row (inside tx)
│   │   ├── redact.ts               # redaction w/ truncated HMAC tag
│   │   ├── diff.ts                 # createDiff()
│   │   ├── checkpoint.ts           # create/sign/emit/verify checkpoints
│   │   ├── verify.ts               # verifyAuditChain()
│   │   ├── history.ts              # query helpers: logs, history, restore preview
│   │   ├── export.ts               # JSON / CSV serialization (CSV-injection safe)
│   │   └── router.ts               # auditRouter() (guard mandatory)
│   ├── scan/
│   │   ├── index.ts                # STATIC public API: scan(), deriveMatrix(), drift(), loadConfig, defineConfig
│   │   ├── project.ts              # ts-morph Project setup
│   │   ├── routes.ts               # route + use() extraction
│   │   ├── mounts.ts               # mount-path + middleware-chain composition
│   │   ├── handlers.ts             # resolve handler identifiers/members to declarations
│   │   ├── classify.ts             # middleware classification
│   │   ├── ownership.ts            # ownership heuristic
│   │   ├── prisma-schema.ts        # hand-written schema.prisma parser
│   │   ├── resources.ts            # route → model mapping
│   │   ├── prisma-writes.ts        # find prisma.<model>.<writeOp> + raw SQL calls
│   │   ├── matrix.ts               # role × resource × action matrix
│   │   ├── drift.ts                # declared vs observed
│   │   ├── findings.ts             # Finding model, fingerprinting, baseline
│   │   ├── rules/
│   │   │   ├── index.ts            # registry
│   │   │   └── <ruleid>.ts         # one file per rule (rbac001.ts, aud001.ts, ...)
│   │   └── report/
│   │       ├── markdown.ts
│   │       ├── json.ts
│   │       └── sarif.ts            # stretch
├── prisma/
│   └── trailguard.prisma           # AuditLog + AuditHead snippet users copy into their schema
├── bin/trailguard.js               # shim: import('../dist/cli.js')
├── test/
│   ├── unit/                       # pure-function tests
│   ├── fixtures/                   # tiny Express apps (static analysis targets), see §13
│   ├── scan/                       # tests that run scan() over fixtures
│   └── integration/                # needs PostgreSQL; own prisma schema + generated client
├── examples/
│   └── demo-app/                   # Express + Prisma + JWT demo (§12)
├── scripts/
│   └── attacker/                   # rehash-chain.ts, truncate-tail.ts (demo scripts)
├── docs/
│   ├── DECISIONS.md
│   ├── THREAT_MODEL.md
│   └── ARCHITECTURE.md
├── .github/workflows/ci.yml
├── docker-compose.yml              # postgres:16 for tests/demo
├── trailguard.config.ts            # self-config used by the demo
├── README.md  CHANGELOG.md  LICENSE
└── package.json  tsconfig.json  tsup.config.ts  vitest.config.ts
```

---

## 4. Public surface

### 4.1 Package exports (`package.json` `exports`)
```
"."        → runtime API  (dist/index.js)
"./scan"   → static API   (dist/scan/index.js)
"./package.json"
```
`bin`: `{ "trailguard": "./bin/trailguard.js" }`.

### 4.2 Runtime API (`import ... from 'trailguard'`)
```ts
createAuditClient(prisma, options): ExtendedPrismaClient
auditContext(options?): express.RequestHandler          // ALS middleware
runWithAuditContext(ctx, fn): Promise<T>                // for jobs/seeds/scripts
getAuditContext(): AuditContext | undefined
auditRouter(options): express.Router                    // options.guard REQUIRED
verifyAuditChain(prisma, options): Promise<VerifyResult>
createCheckpoint(prisma, options): Promise<Checkpoint>
exportAuditLogs(prisma, options): AsyncIterable<string> | ...
AuditChainService                                       // class façade over the above (OOP showcase)
TrailguardError, AuditChainBrokenError, AuditContextMissingError, AuditConfigError, AuditWriteError
types: AuditContext, AuditEntry, AuditOptions, VerifyResult, Checkpoint, ...
```

### 4.3 Static API (`import ... from 'trailguard/scan'`)
```ts
defineConfig(config): Config
loadConfig(path?): Promise<Config>
scan(options): Promise<ScanResult>        // findings + routes + matrix + stats
deriveMatrix(routes): MatrixCell[]
drift(options): Promise<DriftResult>      // needs prisma (reads AuditLog) + scan result
```

### 4.4 CLI
```
trailguard init                       # writes trailguard.config.ts + prints/writes prisma snippet
trailguard scan    [src] [options]
trailguard verify  [options]
trailguard drift   [options]
trailguard ci      [options]          # scan → verify → drift
trailguard export  --format json|csv --out <file>
trailguard checkpoint                 # emit a signed checkpoint now
```
Common options: `--config <path>`, `--format md|json|sarif`, `--out <file>`, `--fail-on none|low|medium|high` (default `high`), `--baseline <file>`, `--update-baseline`, `--verbose`, `--version`.
`verify`/`drift`/`ci` also: `--checkpoints <file>`, `--no-db` (ci only: skip verify+drift, warn loudly), `--key-env <NAME>` (default `TRAILGUARD_KEY`).

### 4.5 Exit codes (all commands)
- `0` — clean / below threshold
- `1` — findings ≥ threshold, or chain invalid, or drift violations
- `2` — tool/config/usage error (bad path, unparseable schema, missing key, DB unreachable)

---

## 5. Concepts and terminology

- **Route node:** one concrete (method, composed path) with its effective middleware chain and handler.
- **Effective middleware chain:** all middleware that run before the handler, in order: app-level `use()` before it, mount-level middleware, router-level `use()` before it, then route-level args.
- **Classification:** each middleware → `auth` | `role:<value>` | `role:unknown` | `ownership` | `unknown`.
- **Audited client:** the Prisma client returned by `createAuditClient`. **Raw client:** the plain `PrismaClient`.
- **Audited model:** a Prisma model listed in `audit.models` / `createAuditClient({ models })`.
- **Chain:** sequence of `AuditLog` rows where `row.prevHash === previous.hash` and `hash = HMAC(key, canonicalPayload)`.
- **Genesis hash:** constant `'0'.repeat(64)`. Used as `prevHash` of seq 1. **Never** use `null`/string concat of null.
- **Checkpoint:** signed `{seq, hash, ts, keyId}` emitted to a sink *outside the DB*.
- **Declared behavior:** what the static matrix says. **Observed behavior:** what AuditLog says. **Drift:** observed ∉ declared.

---

## 6. STATIC SIDE specification

### 6.1 Pipeline
```
loadConfig → createProject(entry files) → extractRoutes(per file) → composeMounts → classifyChains
          → parsePrismaSchema → mapResources → findPrismaWrites → run rules → apply baseline → report
```
Read-only. Never executes user code. Must work without DB or env vars.

### 6.2 Route extraction (`routes.ts`)
Detect, per source file, variables that hold an Express app/router:
`const app = express()`, `const router = express.Router()`, `const router = Router()` (import from `express`). Track by variable symbol, not name.

Recognized call shapes (receiver is a tracked app/router symbol):
```ts
app.get('/x', a, b, handler)        // methods: get post put patch delete head options all
router.post('/', createPost)
router.route('/:id').get(h).patch(authenticate, h)   // chain; each verb = separate route node
app.use('/api/posts', postRouter)                    // mount (router identifier or imported router)
app.use(authenticate)                                // path-less middleware
router.use(authenticate)                             // router-scoped middleware
app.use('/api', authenticate, router)                // mount with middleware chain
app.use(express.json())                              // classified unknown but ignored for RBAC006 noise (see §6.6)
```
Arguments may be arrays (`[a, b]`) → flatten. Path arg may be string literal, no-substitution template, or template with expressions (→ dynamic, §6.3). RegExp/array paths → mark `confidence: 'low'`, path rendered as `<regex>`.

For each route record: `method`, `rawPath`, `file`, `line`, `routerSymbol`, `middlewareArgs[]` (AST nodes), `handlerArg` (last arg), `order` (source position within file).

### 6.3 Mount composition (`mounts.ts`)
1. Build a graph: `routerSymbol → [{ parentSymbol, mountPath, mountMiddleware[], order, dynamic }]`.
2. Resolve imports: `import { router as postRouter } from './routes/posts'`, default imports, `require()` of a file exporting a router, re-exports. Follow to the declaring symbol with ts-morph symbol resolution (`getAliasedSymbol`, definitions). Cache by symbol.
3. For every route in a router, walk up to each root app, producing concrete route nodes: `composedPath = join(mountPaths..., rawPath)`; normalize slashes; `/` suffix handling; route params preserved (`:id`).
4. Effective chain = for each ancestor in order: ancestor-level `use()` middleware registered **before** the mount/route (by `order`) whose path prefix matches, + mount middleware, then router-level `use()` before route, then route args.
5. **Order matters:** `router.use(authenticate)` declared *after* a route does NOT protect that route.
6. Cycle detection: if a router is (transitively) mounted into itself → stop, emit warning, mark `confidence: 'low'`.
7. Dynamic mount (`` `/api/${v}` ``): path segment emitted as `:dynamic` (e.g. `/api/:dynamic/posts/:id`), `confidence: 'low'`, triggers `RBAC007`. Never silently guess.
8. A router never mounted from a configured entry → `orphan: true` (`RBAC008`, stretch).

### 6.4 Middleware classification (`classify.ts`)
Identify the middleware's *reference name*:
- Identifier `authenticate` → `authenticate`
- Call `requireRole('admin')` → callee `requireRole`, args `['admin']`
- Property access `auth.required` → `auth.required`
- Inline arrow/function → analyze body text

Config-driven (see §9). Table:

| Signal | Class |
|---|---|
| name ∈ `auth.middleware` | `auth` |
| callee ∈ `roles.middleware` + extractor yields string literals | `role:<v>` (one entry per literal) |
| callee ∈ `roles.middleware` but args not literal | `role:unknown` |
| inline fn body mentions `req.user.role` / `req.user?.role` | `role:unknown` (review) |
| name ∈ `ownership.middleware` (optional config) | `ownership` |
| anything else | `unknown` |

Extractors: `firstStringArg` (`requireRole('admin')`), `allStringArgs` (`requireRole('admin','editor')`), `arrayArg` (`requireRole(['admin','editor'])`).
**Unknown middleware is never counted as protection.** Known-noise middleware (`express.json()`, `cors()`, `helmet()`, `morgan()`, `express.urlencoded()`, `express.static()`, `compression()`) are classified `neutral` and excluded from `RBAC006`.

### 6.5 Prisma schema parser (`prisma-schema.ts`)
Hand-written line parser over `schema.prisma` text. Do **not** depend on `@prisma/internals`.
- Extract `model Name { ... }` blocks (handle `@@map`, comments `//`, `///`).
- Fields: name, type, optional `?`, list `[]`, attributes (`@id`, `@unique`, `@relation(fields:[x],references:[y])`, `@default`).
- Output: `Map<ModelName, { fields, idField(s), relations, ownerFields }>`.
- `ownerFields`: fields whose name ∈ `ownership.ownerFields` (default `authorId, userId, ownerId, tenantId, createdById`) **and** appear in a `@relation(fields:[...])` or are `*Id` scalar. Report which.
- Parse failure → throw `ScanConfigError` (exit 2) with file + line.

### 6.6 Resource mapping (`resources.ts`)
Two layers; record the source:
1. `config.resources` prefix map (`'/api/posts': 'Post'`) — longest-prefix wins → `source: 'config'`.
2. Heuristic: first non-`api`/non-version path segment, singularize (strip trailing `ies→y`, `s`), PascalCase, case-insensitively match a model name → `source: 'heuristic'`. No match → `resource: null`.

### 6.7 Ownership heuristic (`ownership.ts`)
For a route whose handler resolves (§6.2/`handlers.ts`: identifier → function body; `controller.method` → import → object/class member → body; follow one level of service call optional):
- Search handler body text/AST for any `ownership.signals` (default `req.user.id`, `req.user?.id`, `req.user.userId`, `user.id`) appearing **within or near** an object literal containing a `where` or owner field key.
- Result: `probable` (signal near where/owner field) | `none`. Never `verified`.
- Unresolvable handler → `unknown` (do not claim `none`; lowers finding confidence).

### 6.8 Prisma write discovery (`prisma-writes.ts`)
Find `CallExpression`s of the shape `<receiver>.<modelDelegate>.<op>(...)` where:
- `modelDelegate` (lower-camel) matches an audited model, and
- `op ∈ {create, createMany, update, updateMany, upsert, delete, deleteMany}`, and
- `<receiver>` is **not** one of `audit.clientNames` (default `['auditClient','audited','db']` – user-configurable). Receiver may also be a `$transaction` callback parameter (`tx`) — treat as raw unless config says otherwise.

Also find `$executeRaw`, `$executeRawUnsafe`, and `$queryRaw`/`$queryRawUnsafe` whose static template text matches `/\b(insert|update|delete|replace|truncate|alter|drop)\b/i` (→ `AUD003`).
Record: file, line, receiver text, model, op, enclosing function name, and (if inside a route handler) the route node.

### 6.9 Matrix (`matrix.ts`)
Verb → action: `GET/HEAD→read`, `POST→create`, `PUT/PATCH→update`, `DELETE→delete`, `OPTIONS` ignored.
Per (resource, action) cell, union over all route nodes mapped to that resource:
- No `auth` in chain → `anonymous` allowed.
- Auth, no role middleware → `any-authenticated`.
- Auth + `role:x` → roles `{x}` (union across routes).
- Ownership `probable` → cell flagged `own` (⚠️).
- Any `unknown`/low-confidence contribution → cell flagged `uncertain`.
Report header must state: *"This matrix is derived statically from middleware declarations. It does not execute your handlers."*

### 6.10 Rules catalogue
Rule IDs are stable API. One file per rule; each exports `{ id, title, defaultRisk, run(ctx): Finding[] }`.

| ID | Meaning | Default |
|---|---|---|
| `RBAC001` | Mutating route (POST/PUT/PATCH/DELETE) with no `auth` in effective chain | HIGH |
| `RBAC002` | Mutating route with auth but no role AND no ownership signal | HIGH |
| `RBAC003` | Read route on a private-looking resource (resource mapped, config says private / has owner field) with no auth | MEDIUM |
| `RBAC004` | `role:x` where `x ∉ roles.known` | MEDIUM |
| `RBAC005` | Model has owner field; update/delete route on it has no ownership signal (confidence medium) | MEDIUM |
| `RBAC006` | Route's only non-neutral middleware is `unknown` | LOW |
| `RBAC007` | Dynamically mounted path / low-confidence composition | LOW |
| `RBAC008` | Orphan router (never mounted from entry) | LOW (stretch) |
| `AUD001` | Direct Prisma write on an audited model bypassing the audited client | HIGH |
| `AUD002` | `auditRouter()` mounted without auth + role in effective chain | HIGH |
| `AUD003` | Raw SQL write (`$executeRaw*` etc.) when audited models exist | MEDIUM |
| `DRIFT001` | Observed (role, model, action) not allowed by static matrix | HIGH |
| `DRIFT002` | Observed write with no/unknown actor role | MEDIUM |
| `DRIFT003` | (stretch) Observed write where `actorId ≠` owner field value and role not privileged, but matrix says `own` | MEDIUM |

Config can override risk per rule or set `'off'`. MVP rules: `RBAC001, RBAC002, RBAC005, RBAC007, AUD001, AUD002`.
Rule precedence: a route with `RBAC001` does not also emit `RBAC002`.

### 6.11 Findings, fingerprints, baseline
```ts
interface Finding {
  ruleId: string; risk: 'high'|'medium'|'low'; confidence: 'high'|'medium'|'low';
  message: string; file: string; line: number;
  route?: { method: string; path: string; handler?: string };
  resource?: { model: string | null; source: 'config'|'heuristic' };
  fingerprint: string;   // stable: sha256(ruleId|method|composedPath) or (ruleId|relativeFile|model.op|enclosingFn) — NO line numbers
  suppressed?: boolean;
}
```
Baseline file `.trailguard-baseline.json`: `{ version:1, entries:[{ fingerprint, ruleId, note? }] }`. Baseline-matching findings are marked `suppressed` and excluded from exit-code threshold; report shows suppressed count. `--update-baseline` rewrites it from current findings.

### 6.12 Reporters
- **Markdown:** header (tool version, date, config path, "derived statically" caveat), stats, findings table (`# | Risk | Rule | Route/Location | Auth | Role | Ownership | Resource | Handler | Confidence`), RBAC matrix table (✅ ❌ ⚠️ own, `(public)` for anonymous), suppressed count, limitations footer. Deterministic output (sorted by risk, rule, path) so snapshot tests are stable; **no timestamps in snapshot-tested output** (inject clock).
- **JSON:** full `ScanResult` (stable key order).
- **SARIF 2.1.0 (stretch):** one `rule` per ID, `results` with `physicalLocation` and `partialFingerprints`.

---

## 7. RUNTIME SIDE specification

### 7.1 Prisma models (shipped as `prisma/trailguard.prisma`; users copy into their schema)
```prisma
model AuditLog {
  seq         BigInt   @id                      // assigned in app from AuditHead; gapless
  model       String   @db.VarChar(191)
  recordId    String   @db.VarChar(191)
  action      String   @db.VarChar(16)          // CREATE | UPDATE | DELETE
  actorId     String?  @db.VarChar(191)
  actorRole   String?  @db.VarChar(64)
  requestId   String?  @db.VarChar(64)
  ipAddress   String?  @db.VarChar(64)
  userAgent   String?  @db.VarChar(512)
  payload     String   @db.LongText             // CANONICAL string that is hashed. Source of truth.
  before      Json?                             // convenience copy (redacted)
  after       Json?                             // convenience copy (redacted)
  diff        Json?                             // convenience copy
  prevHash    String   @db.Char(64)
  hash        String   @unique @db.Char(64)
  keyId       String   @db.VarChar(32)
  createdAt   DateTime @default(now()) @db.DateTime(3)   // informational ONLY; never hashed

  @@index([model, recordId])
  @@index([actorId])
  @@index([createdAt])
  @@map("trailguard_audit_log")
}

model AuditHead {
  id        Int    @id                          // always 1
  lastSeq   BigInt
  lastHash  String @db.Char(64)
  @@map("trailguard_audit_head")
}
```
Rules: AuditLog is **append-only** (the library never updates/deletes it). Docs recommend a DB user with `INSERT, SELECT` only on `trailguard_audit_log`.

### 7.2 Canonical payload and hash
`payload = stableStringify({ v:1, seq:string, ts:ISO8601, model, recordId, action, actorId, actorRole, requestId, ipAddress, userAgent, before, after, diff, prevHash })`
- `seq` serialized as **string** (BigInt-safe).
- `ts` generated **in app code** (`new Date().toISOString()`), lives inside the payload. `createdAt` is never used in hashing.
- `hash = HMAC_SHA256(key[keyId], payload)` → lowercase hex (64 chars).
- Genesis: seq 1 has `prevHash = GENESIS_HASH`.
- **Why a payload string column:** PostgreSQL/MySQL `JSON` normalizes key order/number formats, so re-serializing `before/after` from the DB can change bytes. Verify hashes the stored `payload` string only. It then also cross-checks that the convenience columns match the parsed payload (§7.9).

### 7.3 `stableStringify` (canonical JSON) — `core/canonical.ts`
- Object keys sorted (codepoint order), recursively. Arrays keep order.
- `undefined` properties omitted; `null` kept.
- `Date` → ISO string; `BigInt` → decimal string; `Buffer/Uint8Array` → base64 string; Prisma `Decimal` (has `toFixed`/`toString` & `d` field) → string.
- Reject `NaN`/`Infinity`/functions/symbols/circular refs with `AuditWriteError`.
- No whitespace. Property-based tests: key-order permutation invariance.

### 7.4 Append algorithm — `runtime/append.ts`
Runs **inside an interactive `$transaction`** (the same one as the business write):
1. Ensure head row exists once per process (`INSERT IGNORE` equivalent: `createMany({ data:[{id:1,lastSeq:0n,lastHash:GENESIS}], skipDuplicates:true })`) — outside the lock path, cached flag.
2. After the business write, **lock the head last**: `SELECT lastSeq, lastHash FROM trailguard_audit_head WHERE id = 1 FOR UPDATE` via `tx.$queryRaw`.
3. For each entry to append (usually 1; bulk ops N): `seq = lastSeq+1`, `prevHash = lastHash`, build payload, compute HMAC, insert row, advance in-memory `lastSeq/lastHash`.
4. Update `AuditHead` to final values. Commit.
5. If checkpoints enabled and `seq % checkpoint.every === 0` → after commit, emit checkpoint (failure to emit must not fail the request; log via `onError` hook).
Locking head **last** keeps lock-hold time short and avoids lock-order cycles. Tx options configurable: `maxWait` (default 5000ms), `timeout` (default 10000ms). Document throughput limitation (writes to audited models serialize at the head lock).

### 7.5 Audited client — `runtime/client.ts`
```ts
createAuditClient(prisma, {
  models: ['Student','User'],             // required, non-empty
  keys: { current: 'k1', secrets: { k1: process.env.TRAILGUARD_KEY! } },  // or { secret } shorthand → keyId 'default'
  redactFields?: string[],                // global
  redact?: Record<Model, string[]>,       // per-model
  ignoreFields?: Record<Model, string[]>, // excluded entirely (e.g. big blobs)
  idFields?: Record<Model, string|string[]>, // default 'id'; composite joined with ':'
  onMissingContext?: 'throw'|'system',    // default 'throw'
  maxBulkRows?: number,                   // default 1000
  checkpoint?: { every: number, sink: CheckpointSink },
  tx?: { maxWait?: number, timeout?: number },
  onError?: (e: Error) => void,
  testHooks?: { beforeAppend?: () => void|Promise<void> }  // internal, for atomicity tests only
}): ExtendedClient
```
Implementation: `prisma.$extends({ query: { $allModels: { create, update, delete, upsert, [createMany, updateMany, deleteMany] } } })`. For non-audited models → pass through (`query(args)`).
For audited models, each op runs on the **base** client in `prisma.$transaction(async tx => {...})` (use the closed-over base client / `tx`, never the extended one — avoids recursion):

- **create:** write with `select/include` stripped → row = `after`. If user passed `select/include`, return a re-read shaped by them; else return row. `before = null`.
- **update:** `before = tx[model].findUnique({where})` (full row; if null let Prisma throw its normal P2025 by running the write). Write (stripped). `after` = write result. Return shaped re-read if needed.
- **delete:** if `select/include` given, read shaped copy first for the return value. `before = findUnique({where})`, delete, `after = null`.
- **upsert:** `before = findUnique({where})`; action = `before ? 'UPDATE' : 'CREATE'`.
- **createMany:** (tier 2) loop individual `create` inside the tx (so ids are known); returns `{count}`. `skipDuplicates` unsupported → throw `AuditConfigError`.
- **updateMany/deleteMany:** (tier 2) `findMany({where})` first (cap `maxBulkRows`, else throw), then apply, one entry per affected row.
Then redact → diff → append (§7.4) → return result.
**Known limitation (document it):** each audited op opens its own transaction; ops invoked inside a *user-managed* `$transaction` on the extended client are not part of that outer transaction. v1 does not solve this; tier-3 task adds `auditClient.$auditedTransaction(fn)`.
Model key: Prisma delegate is lower-camel (`Student` → `student`); build model-name helper, don't assume.

### 7.6 Context — `runtime/context.ts`
- `AsyncLocalStorage<AuditContext>` singleton (module-level; guard against duplicate package copies via `Symbol.for('trailguard.als')` on `globalThis`).
- `auditContext({ getActor?, trustProxy? })` middleware: creates store `{ requestId: crypto.randomUUID(), ipAddress: req.ip, userAgent, req }` and calls `als.run(store, next)`. Actor is resolved **lazily at write time** (because `authenticate` runs after this middleware): default `getActor = req => ({ id: req.user?.id, role: req.user?.role })`.
- `runWithAuditContext({ actorId, actorRole, requestId? }, fn)` for non-HTTP code (`'system:seed'`).
- No context at write time: `onMissingContext: 'throw'` → `AuditContextMissingError`; `'system'` → actor `system`, role `SYSTEM`.
- Never read client-supplied headers for identity. `requestId` may honor `x-request-id` only if `trustRequestIdHeader: true`.

### 7.7 Redaction & diff
- `redactFields` matched by **exact field name** (case-sensitive) at top level of row; nested JSON fields supported via dotted path (`profile.ssn`) as a nice-to-have.
- Redacted value → `"[REDACTED:" + tag + "]"` where `tag = hmac(deriveKey(key,'redact'), model + '.' + field + ':' + stableStringify(value)).slice(0,4)`. Same value ⇒ same tag ⇒ proves "changed vs unchanged" without revealing it. 4 hex chars = 16 bits, so not invertible.
- Redaction happens **before** diff and hashing; the payload never contains raw secrets.
- `ignoreFields` removed entirely before redaction.
- Diff: `{ field: { old, new } }` for fields where canonical values differ (compare via `stableStringify`, not `!==`). CREATE: diff = null; DELETE: diff = null.
- Composite ids: `recordId = parts.join(':')`.

### 7.8 Checkpoints — `runtime/checkpoint.ts`
`Checkpoint = { v:1, seq:string, hash, ts, keyId, sig }`, `sig = HMAC(key, "trailguard.checkpoint:"+seq+":"+hash+":"+ts+":"+keyId)`.
Sinks: `fileSink(path)` (append JSONL; `fs.appendFile`), `stdoutSink()`, `callbackSink(fn)`. Create on cadence (§7.4) or on demand (`trailguard checkpoint`). The sink should live **outside** the DB admin's reach (CI artifact, remote log, WORM bucket); docs must say so.

### 7.9 Verify — `runtime/verify.ts`
Stream rows ordered by `seq` in batches (default 1000, cursor by seq). For each row, in order:
1. `seq === expectedSeq` else `SEQ_GAP` (missing/reordered/duplicate).
2. `prevHash === expectedPrev` (genesis for first) else `PREV_HASH_MISMATCH`.
3. `keyId` known else `UNKNOWN_KEY`.
4. `HMAC(key, payload) === hash` (timing-safe compare) else `HASH_MISMATCH`.
5. Parse payload; its `seq/model/recordId/action/actorId/actorRole/requestId/prevHash` match the row's columns, and `before/after/diff` deep-equal (canonical compare) the JSON columns, else `COLUMN_PAYLOAD_MISMATCH`.
After the loop:
6. `AuditHead.lastSeq/lastHash` equals the last row else `HEAD_MISMATCH`.
7. If checkpoints provided: each checkpoint's `sig` valid (`CHECKPOINT_BAD_SIGNATURE`); its `seq` exists and `hash` equal (`CHECKPOINT_MISMATCH`); if `checkpoint.seq > lastSeq` → `TRUNCATION_DETECTED`.
Return:
```ts
VerifyResult { valid: boolean; checkedRecords: number; head?: {seq:string,hash:string};
  checkpointsChecked: number; problems: VerifyProblem[]; brokenAt?: string; reason?: string }
```
`brokenAt/reason` = first problem. Default: stop at first problem; `--all` collects all (cap 100).

### 7.10 `auditRouter(options)` — `runtime/router.ts`
`options.guard` (middleware or array) is **required**; omitting it throws `AuditConfigError` at construction time (runtime twin of `AUD002`). Also require `prisma`, `keys`.
```
GET /logs?model=&recordId=&actorId=&action=&from=&to=&page=&pageSize=   (pageSize ≤ 200)
GET /logs/:seq
GET /history/:model/:recordId
GET /verify                    → VerifyResult (HTTP 200 either way; body.valid tells truth)
GET /export?format=json|csv    → streamed; CSV cells starting with = + - @ \t \r are prefixed with '
GET /restore-preview/:model/:recordId   (tier 2) → last known `after` (or `before` if last action DELETE)
```
Validate query input with zod (reject unknown `model` values not in audited models). Redacted values stay redacted everywhere. Errors via `next(err)` with typed errors.

### 7.11 Errors — `core/errors.ts`
`TrailguardError` (base, has `code`) → `AuditChainBrokenError`, `AuditContextMissingError`, `AuditConfigError`, `AuditWriteError`, `ScanConfigError`, `ScanParseError`. CLI maps `ScanConfigError`/`AuditConfigError`/DB-connect errors to exit `2`.

### 7.12 `AuditChainService` (class façade)
Class wrapping `{prisma, options}` with methods `log(entry)`, `verify()`, `getHistory(model, recordId)`, `exportLogs(opts)`, `checkpoint()`. Lets users do **manual logging** (`log()` inside their own transaction `tx`) — this is the escape hatch for the §7.5 transaction limitation. Also demonstrates OOP.

---

## 8. DRIFT specification (`scan/drift.ts`)
Inputs: `ScanResult.matrix`, AuditLog rows (optionally `--since <ISO>`), model→resource mapping.
For each distinct (`actorRole`, `model`, `action`) observed:
- Look up matrix cell (resource = model, action lowercased: create/update/delete).
- Cell missing → `DRIFT002`-style "undeclared" (LOW info) unless config `drift.strict`.
- Cell allows `{role}` or `any-authenticated` → OK. Cell `anonymous` → OK.
- Else → `DRIFT001` with sample (up to 3 `seq`s, actorId, requestId).
- `actorRole` null/`SYSTEM` → `DRIFT002` unless role in `drift.allowRoles` (default allows `SYSTEM`).
- (stretch) Cell flagged `own` and entry has owner field mismatch → `DRIFT003`.
Output uses the same `Finding` shape (route-less; location is `audit:seq=N`). Fingerprint: `DRIFT001|role|model|action`. Baseline applies.

---

## 9. Config reference (`trailguard.config.ts`)
```ts
import { defineConfig } from 'trailguard/scan';
export default defineConfig({
  entry: ['./src/app.ts'],
  tsconfig: './tsconfig.json',
  prismaSchema: './prisma/schema.prisma',
  ignore: ['**/*.test.ts', '**/node_modules/**'],

  auth:  { middleware: ['authenticate', 'requireAuth'] },
  roles: { middleware: ['requireRole', 'authorize'], extractor: 'allStringArgs',
           known: ['ADMIN', 'TEACHER', 'STUDENT', 'AUDITOR'] },
  ownership: { signals: ['req.user.id', 'req.user?.id'],
               ownerFields: ['authorId','userId','ownerId','tenantId','createdById'],
               middleware: [] },
  resources: { '/api/students': 'Student', '/api/users': 'User' },
  privateResources: ['User', 'Student'],       // used by RBAC003

  audit: { models: ['Student', 'User'],
           clientNames: ['auditClient'],       // receivers considered safe
           routerNames: ['auditRouter'] },      // factory names to check for AUD002
  rules: { RBAC005: 'medium', RBAC007: 'off' },
  baseline: './.trailguard-baseline.json',
  checkpoints: { file: './trailguard-checkpoints.jsonl' },
  keyEnv: 'TRAILGUARD_KEY',
  drift: { strict: false, allowRoles: ['SYSTEM'] },
});
```
Validated with zod; unknown keys are an error (typo protection). Paths resolve relative to the config file. Defaults applied in `load.ts`. Config errors → exit 2 with a readable message listing the zod path.

---

## 10. Core types (authoritative shapes)
```ts
type Risk = 'high' | 'medium' | 'low';
type Confidence = 'high' | 'medium' | 'low';
type HttpMethod = 'GET'|'POST'|'PUT'|'PATCH'|'DELETE'|'HEAD'|'OPTIONS'|'ALL';
type Action = 'read' | 'create' | 'update' | 'delete';
type MiddlewareClass =
  | { kind: 'auth' } | { kind: 'role'; value: string | 'unknown' }
  | { kind: 'ownership' } | { kind: 'neutral' } | { kind: 'unknown' };

interface MiddlewareRef { text: string; name: string; args: string[]; class: MiddlewareClass; file: string; line: number }

interface RouteNode {
  method: HttpMethod; path: string; rawPath: string; confidence: Confidence;
  chain: MiddlewareRef[]; handler?: { name: string; file?: string; line?: number; resolved: boolean };
  file: string; line: number; resource?: { model: string | null; source: 'config' | 'heuristic' };
  ownership: 'probable' | 'none' | 'unknown';
}

interface MatrixCell { resource: string; action: Action;
  anonymous: boolean; anyAuthenticated: boolean; roles: string[]; own: boolean; uncertain: boolean }

interface ScanResult { version: string; routes: RouteNode[]; findings: Finding[]; matrix: MatrixCell[];
  models: string[]; stats: { routes: number; protectedRoutes: number; unprotectedRoutes: number; byRisk: Record<Risk, number>; suppressed: number } }

interface AuditContext { requestId?: string; actorId?: string; actorRole?: string; ipAddress?: string; userAgent?: string }
type AuditAction = 'CREATE' | 'UPDATE' | 'DELETE';
```

---

## 11. Demo app (`examples/demo-app`)
Blog-less, **college** scenario. Express + TS + Prisma + PostgreSQL (docker-compose) + JWT.
- Models: `User { id, email, passwordHash, role(ADMIN|TEACHER|STUDENT|AUDITOR), phone? }`, `Student { id, name, email, phone, marks, teacherId? }`, plus `AuditLog`, `AuditHead`.
- Auth: `POST /auth/register`, `POST /auth/login` (bcrypt hash — use `bcryptjs`; access JWT 15m via `jsonwebtoken`; refresh token optional).
- Middleware named exactly as in config: `authenticate`, `requireRole`.
- Routes: `GET/POST /api/students`, `PATCH/DELETE /api/students/:id` (ADMIN/TEACHER), `PATCH /api/users/:id/role` (ADMIN), `GET /api/users` (ADMIN), `/audit/*` via `auditRouter({ guard:[authenticate, requireRole('ADMIN','AUDITOR')] })`.
- `redactFields: ['passwordHash','phone']`.
- Seed (`prisma/seed.ts`): uses `runWithAuditContext({actorId:'system:seed', actorRole:'SYSTEM'})`.
- **`vulnerable.patch`**: `npm run demo:break` applies it (`git apply`), `demo:fix` reverses it. It introduces exactly 3 HIGH findings: (1) `DELETE /api/students/:id` loses `requireRole` → `RBAC002`; (2) `PATCH /api/users/:id/role` loses `authenticate` → `RBAC001`; (3) a `POST /api/students/bulk-reset` handler calls `prisma.student.updateMany` on the raw client → `AUD001`.
- `npm run audit` → `trailguard ci`.
- `scripts/attacker/rehash-chain.ts`: edits a row, then recomputes the whole chain forward using plain SHA-256 / a guessed key and rewrites all rows (+head). `truncate-tail.ts`: deletes the last N rows and sets AuditHead back. Both must be **detected** by `verify` (HMAC failure / checkpoint truncation).

---

## 12. Testing strategy

### 12.1 Unit (no DB)
`canonical` (permutation invariance, BigInt/Date/Decimal, rejects NaN/cycles), `crypto`, `redact` (tag stable, raw value absent), `diff`, `config` (valid, unknown key error, defaults), `prisma-schema` (models, owner fields, @@map, comments), `classify`, `resources`, `matrix`, `findings` fingerprint stability/baseline, markdown reporter snapshot.

### 12.2 Static fixtures (`test/fixtures/<name>/` each a mini app + `expected.json`)
| Fixture | Expect |
|---|---|
| `clean` | 0 findings |
| `missing-auth` | `RBAC001` on `DELETE /api/posts/:id` |
| `auth-no-role` | `RBAC002` |
| `ownership-ok` / `ownership-missing` | `RBAC005` absent / present |
| `nested-routers` | composed `/api/v1/posts/:id`; mount middleware applied |
| `router-use-order` | route declared **before** `router.use(authenticate)` is flagged |
| `route-chain` | `router.route('/:id').get().patch()` yields two nodes |
| `dynamic-mount` | `/api/:dynamic/...`, `RBAC007`, confidence low |
| `unknown-mw` | `RBAC006`; not counted as protection |
| `bypass-audit-client` | `AUD001` for `prisma.student.update`, not for `auditClient.student.update` |
| `raw-sql` | `AUD003` |
| `audit-router-unguarded` / `-guarded` | `AUD002` present / absent |
| `baseline` | suppressed finding absent from exit threshold |
| `import-resolution` | default/named/re-exported routers resolve |
Each test asserts: ruleIds, composed paths, counts, exit code, and (for 2–3 fixtures) a markdown snapshot.

### 12.3 Integration (PostgreSQL; skipped unless `TEST_DATABASE_URL` set)
- CREATE/UPDATE/DELETE produce correct before/after/diff and a valid chain.
- Redaction: raw password string never appears in any column (`SELECT ... LIKE`).
- Tamper: edit a row → `HASH_MISMATCH`; edit `before` column only → `COLUMN_PAYLOAD_MISMATCH`; delete a middle row → `SEQ_GAP`; swap two rows' seq → fails; delete **last** row + reset head → only checkpoint detects (`TRUNCATION_DETECTED`).
- Smart attacker: `rehash-chain` script without key → `HASH_MISMATCH`.
- **Concurrency:** 50 parallel updates (and mixed create/update/delete) → chain valid, 50 contiguous seqs, no duplicates.
- **Atomicity:** `testHooks.beforeAppend` throws → business row unchanged (rolled back), no audit row.
- Missing context → `AuditContextMissingError` (and `'system'` mode works).
- Router: guard required (throws without); non-admin → 403; export CSV escapes `=cmd`; pagination caps.
- Perf sanity: `scan()` on demo app < 3s.

Coverage target: ≥ 80% lines on `scan/**` (excluding reporters), `runtime/**`, `core/**`.

---

## 13. Coding conventions
- Small pure functions; side effects (fs, DB, process.exit) only at edges (`cli.ts`, `runtime/*` DB calls, `checkpoint` sinks). `process.exit` only in `cli.ts`.
- No `any` (use `unknown` + narrowing). No non-null `!` except in tests. No default exports in `src/` (except config files).
- Every public function has TSDoc. Every rule has a doc comment with a bad/good code example.
- Deterministic output: sort everything; inject clock/`version` for tests.
- Errors: throw typed errors; never `throw 'string'`.
- Do not log secrets; never print the HMAC key, even with `--verbose`.
- Commits: one task = one commit, message `T<id>: <title>`. Update `tasks.md` checkbox in the same commit.
- If a task's acceptance criteria can't be met, **stop and write what blocked you** in `docs/DECISIONS.md` rather than weakening the test.

---

## 14. Honest limitations (must appear in README + `docs/THREAT_MODEL.md`)
1. Static analysis is heuristic: dynamic routes, spread middleware, runtime-registered routes, and aliased clients can be missed or marked low-confidence.
2. Ownership is `probable`, never proven.
3. The matrix is derived from declarations; it does not execute handlers.
4. The chain is **tamper-evident**, not tamper-proof. HMAC key held by the app means an attacker who steals the key *and* the DB can forge future entries; **only checkpoints already shipped outside the DB** protect history, and only if that sink is itself protected.
5. Writes to audited models serialize on one head row (throughput ceiling).
6. Audited ops don't join a user-managed outer transaction (use `AuditChainService.log()` there).
7. Writes that bypass the audited client (other services, raw SQL, DB console) are not logged — `AUD001/AUD003` help only for code in the scanned repo.
8. Reads are not audited (stretch: read auditing for sensitive models).

---

## 15. Fixed decisions (do not relitigate)
- Single package, two entry points (runtime / scan). No monorepo packages.
- HMAC-SHA256 (not plain SHA-256); `payload` LongText column is the hashed source of truth.
- `seq` assigned by app under head lock (not `autoincrement`) → gapless.
- Head row + `SELECT … FOR UPDATE`; head locked last.
- ALS for context; lazy actor resolution.
- Redaction tag = truncated HMAC, 4 hex chars.
- Hand-written Prisma schema parser (no `@prisma/internals`).
- Config via `jiti`; strict zod (unknown keys rejected).
- PostgreSQL for runtime; docker-compose for tests.
- Name: `trailguard` (check availability at publish time; scoped fallback `@<user>/trailguard`).

---

## 16. Glossary
**RBAC** role-based access control · **ALS** AsyncLocalStorage · **HMAC** keyed hash · **Genesis** the fixed prevHash for the first row · **Checkpoint** externally stored signed (seq, hash) · **Bypass** a write that skips the audited client · **Drift** observed behavior outside declared behavior · **Fingerprint** stable ID of a finding used for baselines.
