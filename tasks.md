# tasks.md — `trailguard`

Read `context.md` first. It is the spec; this file is the work queue.

## How to work through this file
1. Take the **first unchecked task** whose dependencies are all checked. Do not skip ahead.
2. Implement it, write/adjust tests, run `npm run lint && npm run typecheck && npm test`.
3. Only when **every acceptance criterion** passes: tick the box, commit as `T<id>: <title>`.
4. If blocked or if the spec is ambiguous, stop and record it in `docs/DECISIONS.md`, then ask. Never weaken a test to make it pass.
5. Tags: **[MVP]** must ship · **[T2]** do after MVP is complete · **[T3]** stretch, only if everything else is done.
6. Integration tests need MySQL: `docker compose up -d` and `TEST_DATABASE_URL=mysql://root:root@localhost:3307/trailguard_test`.

Legend: `dep:` = prerequisite task IDs · `files:` = main files touched.

---

## Phase 0 — Scaffold

- [x] **T0.1 [MVP] Repo + tooling**
  - dep: none · files: `package.json`, `tsconfig.json`, `tsup.config.ts`, `vitest.config.ts`, `.eslintrc`, `.prettierrc`, `.gitignore`, `LICENSE` (MIT)
  - Do: init ESM TS project per `context.md §2`; scripts `build`, `dev`, `test`, `test:int`, `lint`, `typecheck`; `exports` map for `.` and `./scan`; `bin/trailguard.js` shim; empty `src/index.ts`, `src/scan/index.ts`, `src/cli.ts`.
  - Accept: `npm run build` emits `dist/index.js`, `dist/scan/index.js`, `dist/cli.js` + `.d.ts`; `node bin/trailguard.js --version` prints version; `npm run typecheck` passes with strict flags.

- [x] **T0.2 [MVP] CI + docker-compose**
  - dep: T0.1 · files: `.github/workflows/ci.yml`, `docker-compose.yml`
  - Do: CI matrix Node 18/20/22 running lint, typecheck, unit tests; separate job with MySQL 8 service for `test:int`. `docker-compose.yml` exposes MySQL on 3307 (user root/root, db `trailguard_test`).
  - Accept: workflow YAML valid; `docker compose up -d` gives a reachable MySQL.

- [x] **T0.3 [MVP] Docs skeleton**
  - dep: T0.1 · files: `docs/DECISIONS.md`, `docs/THREAT_MODEL.md`, `docs/ARCHITECTURE.md`, `README.md` (stub), `CHANGELOG.md`
  - Accept: files exist; DECISIONS has an entry template; README contains the positioning line and a "Limitations" heading.

---

## Phase 1 — Shared core

- [x] **T1.1 [MVP] Errors**
  - dep: T0.1 · files: `src/core/errors.ts`, `test/unit/errors.test.ts`
  - Do: hierarchy from `context.md §7.11` with `code` string field; `instanceof` works after build.
  - Accept: each error class has name, code, message; unit test covers inheritance.

- [x] **T1.2 [MVP] Constants + types**
  - dep: T1.1 · files: `src/core/constants.ts`, `src/core/types.ts`
  - Do: `GENESIS_HASH`, `PAYLOAD_VERSION=1`, table names, shared types from `context.md §10`.
  - Accept: typechecks; types re-exported from `src/index.ts` / `src/scan/index.ts` appropriately.

- [x] **T1.3 [MVP] Canonical stringify**
  - dep: T1.1 · files: `src/core/canonical.ts`, `test/unit/canonical.test.ts`
  - Do: per `context.md §7.3`.
  - Accept: key-order permutation invariance (property-style test with random objects); BigInt/Date/Buffer handled; `undefined` omitted, `null` kept; throws `AuditWriteError` on NaN/Infinity/cycles/functions; output has no whitespace.

- [x] **T1.4 [MVP] Crypto helpers**
  - dep: T1.3 · files: `src/core/crypto.ts`, `test/unit/crypto.test.ts`
  - Do: `hmacHex(key, data)`, `deriveKey(key, label)`, `timingSafeEqualHex(a,b)` using `node:crypto`.
  - Accept: known HMAC-SHA256 test vectors pass; `timingSafeEqualHex` returns false for different lengths without throwing.

- [x] **T1.5 [MVP] Config schema + loader**
  - dep: T1.1 · files: `src/config/schema.ts`, `src/config/load.ts`, `test/unit/config.test.ts`
  - Do: zod schema per `context.md §9` (`.strict()`), `defineConfig`, `loadConfig(path?)` using `jiti` for `.ts/.js/.mjs`, plus `.json`; auto-discover `trailguard.config.{ts,js,mjs,json}` from cwd upward; resolve relative paths against config dir; apply defaults.
  - Accept: valid TS config loads; unknown key → `ScanConfigError` naming the key path; missing file → `ScanConfigError`; defaults present (`ownerFields`, `clientNames`, etc.).

---

## Phase 2 — Static analysis core

- [x] **T2.1 [MVP] ts-morph project + fixture harness**
  - dep: T1.5 · files: `src/scan/project.ts`, `test/fixtures/README.md`, `test/helpers/fixture.ts`
  - Do: `createProject({entry, tsconfig, ignore})` adding entry files and following imports; support `.ts` and `.js` (`allowJs`). Test helper that loads `test/fixtures/<name>` with its own `trailguard.config.ts` + `expected.json`.
  - Accept: loads a fixture entry and its transitively imported files; ignores globs; missing entry → `ScanConfigError`.

- [x] **T2.2 [MVP] Route extraction**
  - dep: T2.1 · files: `src/scan/routes.ts`, fixtures `route-chain`, `clean`
  - Do: `context.md §6.2`. Track app/router by symbol. Support verbs + `all`, arrays of middleware, `router.route().get().patch()` chains, `use()` with/without path, template-literal paths.
  - Accept: unit tests over fixtures assert method, raw path, middleware arg text, handler arg, and `order` for every call shape listed in §6.2.

- [x] **T2.3 [MVP] Import/handler resolution**
  - dep: T2.2 · files: `src/scan/handlers.ts`, fixture `import-resolution`
  - Do: resolve imported routers (named, default, aliased, re-exported, `require`) and handler references (`fn`, `controller.method`, class static/instance member) to declarations; cache by symbol.
  - Accept: fixture proves each import style resolves; unresolvable handler returns `{resolved:false}` without throwing.

- [x] **T2.4 [MVP] Mount composition + effective middleware chain**
  - dep: T2.2, T2.3 · files: `src/scan/mounts.ts`, fixtures `nested-routers`, `router-use-order`, `dynamic-mount`
  - Do: `context.md §6.3` including ordering, cycle detection, dynamic mounts → `:dynamic` + `confidence:'low'`, path normalization.
  - Accept: `/api/v1` + `/posts` + `/:id` composes correctly (3 levels deep); app-level `use(authenticate)` before a mount protects children; `router.use(authenticate)` placed **after** a route does not; a cycle terminates with a warning; dynamic mount marks confidence low.

- [x] **T2.5 [MVP] Middleware classification**
  - dep: T2.4 · files: `src/scan/classify.ts`, fixtures `unknown-mw`
  - Do: `context.md §6.4`, all three extractors, neutral list, inline-function body analysis.
  - Accept: table-driven unit tests for every row of the classification table; unknown is never classified as auth/role; `express.json()` is `neutral`.

- [x] **T2.6 [MVP] Prisma schema parser**
  - dep: T1.2 · files: `src/scan/prisma-schema.ts`, `test/unit/prisma-schema.test.ts`
  - Do: `context.md §6.5`.
  - Accept: parses models, optional/list fields, `@id`, `@unique`, `@relation`, `@@map`, comments; detects owner fields; malformed input throws `ScanConfigError` with line number.

- [x] **T2.7 [MVP] Resource mapping**
  - dep: T2.4, T2.6 · files: `src/scan/resources.ts`
  - Do: `context.md §6.6` (config longest-prefix, then heuristic singularization).
  - Accept: `/api/v1/students/:id` → `Student` (heuristic); config override wins; unmatched → `null`; `source` recorded.

- [x] **T2.8 [MVP] Ownership heuristic**
  - dep: T2.3, T2.6 · files: `src/scan/ownership.ts`, fixtures `ownership-ok`, `ownership-missing`
  - Do: `context.md §6.7`.
  - Accept: `where: { id, authorId: req.user.id }` → `probable`; handler without signals → `none`; unresolved handler → `unknown`.

- [x] **T2.9 [MVP] Findings model, rule registry, RBAC rules**
  - dep: T2.5, T2.7, T2.8 · files: `src/scan/findings.ts`, `src/scan/rules/index.ts`, `rbac001.ts`, `rbac002.ts`, `rbac005.ts`, `rbac007.ts`
  - Do: `Finding`, fingerprints (no line numbers), risk override via config, precedence (`RBAC001` suppresses `RBAC002` for same route).
  - Accept: fixtures `missing-auth`, `auth-no-role`, `ownership-missing`, `dynamic-mount`, `clean` produce exactly the expected rule IDs; fingerprint unchanged when unrelated lines are added above the route (test).

- [ ] **T2.10 [T2] Remaining RBAC rules**
  - dep: T2.9 · files: `rbac003.ts`, `rbac004.ts`, `rbac006.ts`, `rbac008.ts`
  - Accept: fixtures for each; `RBAC006` ignores `neutral` middleware.

- [x] **T2.11 [MVP] Baseline**
  - dep: T2.9 · files: `src/scan/findings.ts` (baseline part), fixture `baseline`
  - Do: `context.md §6.11`; `--update-baseline` rewrite.
  - Accept: baselined finding is `suppressed`, excluded from exit threshold, counted in stats; update writes sorted, stable JSON.

- [x] **T2.12 [MVP] Matrix derivation**
  - dep: T2.9 · files: `src/scan/matrix.ts`, `test/unit/matrix.test.ts`
  - Do: `context.md §6.9`.
  - Accept: unit tests for anonymous, any-authenticated, role union, ownership `own`, `uncertain` propagation; verb→action mapping correct.

- [x] **T2.13 [MVP] Markdown + JSON reporters**
  - dep: T2.11, T2.12 · files: `src/scan/report/markdown.ts`, `json.ts`, snapshots
  - Do: `context.md §6.12`; deterministic; injectable clock/version.
  - Accept: snapshot tests on 3 fixtures; report contains the "derived statically" caveat and limitations footer; JSON validates against its TS type.

- [x] **T2.14 [MVP] `scan()` API + `trailguard scan` command**
  - dep: T2.13 · files: `src/scan/index.ts`, `src/cli.ts`
  - Do: wire the pipeline; `--format --out --fail-on --baseline --update-baseline --config --verbose`; exit codes 0/1/2; CLI contains no logic beyond arg parsing and calling `scan()`.
  - Accept: e2e test spawns the built CLI on fixtures: `clean` → exit 0, `missing-auth` → exit 1 with `--fail-on high`, bad config path → exit 2; `--fail-on none` always 0.

---

## Phase 3 — Runtime audit log

- [x] **T3.1 [MVP] Prisma snippet + test schema**
  - dep: T0.2 · files: `prisma/trailguard.prisma`, `test/integration/prisma/schema.prisma`, `test/integration/setup.ts`
  - Do: `context.md §7.1` models; test schema includes `Student` (id, name, email, phone, marks, teacherId?) + the two audit models; generated client output to `test/integration/generated`; setup does `prisma migrate reset`/`db push` against `TEST_DATABASE_URL`.
  - Accept: `npm run test:int` connects, pushes schema, and a trivial test inserts a `Student`.

- [x] **T3.2 [MVP] Redaction + diff**
  - dep: T1.4 · files: `src/runtime/redact.ts`, `src/runtime/diff.ts`, unit tests
  - Do: `context.md §7.7`.
  - Accept: redacted output contains `[REDACTED:xxxx]`, raw value absent; same value → same tag, different value → (almost certainly) different tag; diff compares canonically (`{a:1,b:2}` vs reordered = no diff); `ignoreFields` removed.

- [x] **T3.3 [MVP] Audit context (ALS)**
  - dep: T1.1 · files: `src/runtime/context.ts`, tests
  - Do: `context.md §7.6`; lazy actor resolution; `runWithAuditContext`; `onMissingContext`.
  - Accept: unit/supertest test: middleware before `authenticate` still sees `req.user` at write-time; context isolated across concurrent requests; no context + `'throw'` → `AuditContextMissingError`.

- [x] **T3.4 [MVP] Append (head lock + HMAC chain)**
  - dep: T3.1, T3.2, T1.3, T1.4 · files: `src/runtime/append.ts`, integration test
  - Do: `context.md §7.2`, `§7.4`; seq assigned from head; head locked last; payload built from canonical string.
  - Accept: appended rows have seq 1..N gapless, `prevHash` links, `hash` equals recomputed HMAC; first row uses `GENESIS_HASH`; payload JSON parses and matches columns.

- [x] **T3.5 [MVP] `createAuditClient` (create/update/delete/upsert)**
  - dep: T3.3, T3.4 · files: `src/runtime/client.ts`, integration tests
  - Do: `context.md §7.5` (tier-1 ops only). Non-audited models pass through untouched. Respect `select/include` on return values.
  - Accept: create/update/delete/upsert each produce exactly one audit row with correct `before/after/diff/action/actor`; returned objects match what raw Prisma would return (incl. with `select`); non-audited model writes create no audit row; business write and audit row roll back together when `testHooks.beforeAppend` throws.

- [x] **T3.6 [MVP] Verify**
  - dep: T3.4 · files: `src/runtime/verify.ts`, integration tests
  - Do: `context.md §7.9` steps 1–6 (checkpoint steps come in T3.7).
  - Accept: valid chain → `valid:true, checkedRecords:N`; edit `payload` → `HASH_MISMATCH`; edit only `before` column → `COLUMN_PAYLOAD_MISMATCH`; delete middle row → `SEQ_GAP`; swap seq of two rows → fails; head mismatch → `HEAD_MISMATCH`; batches correctly over >1000 rows (use small batch size in test).

- [x] **T3.7 [MVP] Checkpoints**
  - dep: T3.6 · files: `src/runtime/checkpoint.ts`, integration tests
  - Do: `context.md §7.8` + verify steps 7; `fileSink`, `stdoutSink`, `callbackSink`; cadence hook in append; `createCheckpoint()` on demand.
  - Accept: delete the last rows **and** reset `AuditHead` → plain verify says valid but verify-with-checkpoints returns `TRUNCATION_DETECTED`; forged checkpoint signature → `CHECKPOINT_BAD_SIGNATURE`; checkpoint sink failure does not fail the business write (`onError` called).

- [x] **T3.8 [MVP] Concurrency + atomicity tests**
  - dep: T3.5, T3.6 · files: `test/integration/concurrency.test.ts`
  - Accept: 50 parallel updates and a mixed 60-op create/update/delete burst → chain valid, seqs contiguous, no duplicate seq, no deadlock errors; run the suite 5× in CI loop without flake.

- [x] **T3.9 [MVP] `AuditChainService` class + history queries**
  - dep: T3.6 · files: `src/runtime/index parts`, `src/runtime/history.ts`, `src/index.ts`
  - Do: `context.md §7.12`; `log()` usable with a caller-provided `tx`.
  - Accept: manual `service.log()` inside the user's own `$transaction` commits/rolls back with it; `getHistory(model, recordId)` ordered by seq.

- [ ] **T3.10 [MVP] `auditRouter`**
  - dep: T3.9 · files: `src/runtime/router.ts`, integration/supertest tests
  - Do: `context.md §7.10` (logs, logs/:seq, history, verify; export in T3.11). zod-validated query; pagination caps.
  - Accept: constructing without `guard` throws `AuditConfigError`; unauthenticated → guard's response; ADMIN gets data; `pageSize=100000` is capped; unknown `model` query → 400; responses never contain raw redacted values.

- [ ] **T3.11 [T2] Export JSON/CSV**
  - dep: T3.10 · files: `src/runtime/export.ts`
  - Do: streamed export; CSV escaping + formula-injection prefix; `trailguard export --out file` uses `fs`.
  - Accept: CSV cell `=HYPERLINK(...)` is exported as `'=HYPERLINK(...)`; commas/quotes/newlines correctly quoted; large export doesn't load all rows into memory (cursor batches).

- [ ] **T3.12 [T2] Bulk ops (`createMany`, `updateMany`, `deleteMany`)**
  - dep: T3.5 · files: `src/runtime/client.ts`
  - Accept: one audit row per affected record, same tx; `maxBulkRows` exceeded → `AuditWriteError` and nothing written; `skipDuplicates` → `AuditConfigError`.

- [ ] **T3.13 [T2] Restore preview**
  - dep: T3.10 · Accept: `GET /restore-preview/:model/:recordId` returns last known state (uses `before` of the last DELETE); redacted fields remain redacted; 404 when never seen.

- [ ] **T3.14 [T3] `$auditedTransaction(fn)` on the audited client**
  - dep: T3.5 · Accept: ops inside `fn` share one transaction; all audit rows appended once at commit under a single head lock; rollback removes everything.

- [ ] **T3.15 [T3] Read-access auditing for configured sensitive models**
  - dep: T3.5 · Accept: `findUnique/findMany` on listed models append `READ` entries (action union extended; docs warn about volume).

---

## Phase 4 — The bridge (static ⇄ runtime)

- [ ] **T4.1 [MVP] Prisma write discovery**
  - dep: T2.9 · files: `src/scan/prisma-writes.ts`, fixtures `bypass-audit-client`, `raw-sql`
  - Do: `context.md §6.8`.
  - Accept: `prisma.student.update()` found; `auditClient.student.update()` not flagged; `tx.student.delete()` inside `$transaction(async tx => …)` found; non-audited model ignored; raw SQL detection catches `UPDATE`/`DELETE` text in tagged templates and strings.

- [ ] **T4.2 [MVP] Rule `AUD001` (bypass)**
  - dep: T4.1 · files: `src/scan/rules/aud001.ts`
  - Accept: fixture `bypass-audit-client` → exactly one `AUD001` HIGH with file/line/model.op in message; fingerprint stable across line shifts; includes route info when inside a handler.

- [ ] **T4.3 [MVP] Rule `AUD002` (audit router guarded)**
  - dep: T2.9 · files: `src/scan/rules/aud002.ts`, fixtures `audit-router-unguarded`, `audit-router-guarded`
  - Do: find `app.use(path, ...mw, auditRouter(...))` (factory names from `audit.routerNames`); require `auth` **and** a `role:*` in the effective chain.
  - Accept: unguarded → `AUD002` HIGH; guarded → none; guard supplied only via `auditRouter({ guard })` option (static literal containing a classified auth+role) also counts as guarded.

- [ ] **T4.4 [T2] Rule `AUD003` (raw SQL writes)**
  - dep: T4.1 · Accept: `raw-sql` fixture → `AUD003` MEDIUM; no finding when `audit.models` is empty.

- [ ] **T4.5 [T2] Drift engine + `trailguard drift`**
  - dep: T2.12, T3.6 · files: `src/scan/drift.ts`, integration tests
  - Do: `context.md §8`; `--since`; uses same `Finding` + baseline.
  - Accept: seeded audit rows where a `TEACHER` deleted a `User` while matrix says ADMIN-only → one `DRIFT001` with sample seqs; allowed activity → none; role `SYSTEM` → no `DRIFT002` by default; exit code 1 on violations.

- [ ] **T4.6 [T3] `DRIFT003` ownership drift** · dep: T4.5 · Accept: owner-field mismatch on an `own`-flagged cell raises `DRIFT003`.

---

## Phase 5 — CLI completion

- [ ] **T5.1 [MVP] `trailguard verify`**
  - dep: T3.7 · files: `src/cli.ts`, `src/cli/prisma-client.ts`
  - Do: load user's `@prisma/client` resolved **from cwd** (`createRequire(cwd)`); key from `process.env[keyEnv]`; `--checkpoints`; `--all`; human output `✔ valid (N records)` / `✖ broken at seq X: reason`.
  - Accept: valid DB → exit 0; tampered → exit 1 with seq + reason; missing key env or unreachable DB → exit 2 with clear message; key never printed.

- [ ] **T5.2 [MVP] `trailguard ci`**
  - dep: T2.14, T5.1 · Accept: runs scan → verify → (drift if available), prints one summary table, exit = max(sub-exit codes); `--no-db` skips verify/drift with a visible warning; `--format` and `--out` apply to scan part.

- [ ] **T5.3 [T2] `trailguard drift` + `trailguard export` + `trailguard checkpoint` commands**
  - dep: T4.5, T3.11, T3.7 · Accept: each works end to end with exit codes per spec.

- [ ] **T5.4 [T2] `trailguard init`**
  - dep: T1.5 · Accept: writes `trailguard.config.ts` (refuses to overwrite without `--force`), prints/copies the Prisma snippet, prints a 5-line "next steps".

- [ ] **T5.5 [T2] SARIF reporter**
  - dep: T2.13 · Accept: output validates against SARIF 2.1.0 schema (vendor the schema in test fixtures); `partialFingerprints` set from our fingerprints.

---

## Phase 6 — Demo app + e2e

- [ ] **T6.1 [MVP] Demo app (fixed state)**
  - dep: T3.10, T2.14 · files: `examples/demo-app/**`
  - Do: `context.md §11`: auth (register/login/JWT), `authenticate`, `requireRole`, student CRUD via audited client, users admin routes, `auditContext()` first, `auditRouter({guard})`, redaction of `passwordHash`/`phone`, seed under `runWithAuditContext`, `README` with run steps; `trailguard.config.ts` for it.
  - Accept: `npm run demo:setup && npm run demo:start` works; login → create student → update marks → `GET /audit/history/Student/:id` shows before/after/diff and actor; `phone` shows `[REDACTED:xxxx]`; `trailguard scan` on it = **0 findings**.

- [ ] **T6.2 [MVP] `vulnerable.patch` + break/fix scripts**
  - dep: T6.1, T4.2 · files: `examples/demo-app/vulnerable.patch`, root `package.json` scripts
  - Accept: `npm run demo:break` applies cleanly; `trailguard scan` then reports **exactly 3 HIGH**: `RBAC002` (DELETE student), `RBAC001` (role patch), `AUD001` (bulk-reset raw write); exit 1. `npm run demo:fix` reverses; scan exit 0.

- [ ] **T6.3 [MVP] Attacker scripts**
  - dep: T3.7 · files: `scripts/attacker/rehash-chain.ts`, `truncate-tail.ts`
  - Accept: after `rehash-chain` (plain SHA-256 or wrong key, rewrites all rows + head) `trailguard verify` → exit 1 `HASH_MISMATCH`; after `truncate-tail` (deletes last rows + resets head) `verify` passes alone but `verify --checkpoints` → `TRUNCATION_DETECTED`.

- [ ] **T6.4 [MVP] End-to-end demo test + `docs/DEMO.md`**
  - dep: T6.2, T6.3 · Accept: a vitest e2e (skipped without DB) executes the seven-step demo from `context.md`/README programmatically (break → scan fails → fix → scan passes → write → verify ok → tamper → verify fails → rehash → fails → truncate → checkpoint catches → drift catches); `docs/DEMO.md` has the human script with exact commands and expected output snippets.

- [ ] **T6.5 [T2] Drift demo step**
  - dep: T4.5, T6.4 · Accept: seed an entry where a TEACHER deletes a User (via script) → `trailguard drift` reports `DRIFT001`; documented in `DEMO.md`.

---

## Phase 7 — Hardening, docs, publish

- [ ] **T7.1 [MVP] Coverage + perf gates**
  - dep: Phases 2–4 · Accept: coverage ≥ 80% lines on `scan/**` (excl. reporters), `runtime/**`, `core/**`; `scan()` on demo app < 3s in a test; coverage threshold enforced in vitest config.

- [ ] **T7.2 [MVP] README (full)**
  - dep: T6.4 · Accept: sections in order — problem + 5-line vulnerable example · what it does/doesn't · quickstart (static + runtime) · rules table · config reference · matrix explanation + caveat · audit log design + threat model summary (tamper-**evident**) · CI snippet · comparison table (ESLint security plugins, route dumpers, generic Prisma audit-log libs/extensions, APM — list what *they* do well, state the gap honestly) · architecture diagram · limitations (all 8 from `context.md §14`) · roadmap. Includes a **novelty check** subsection: commands you ran (`npm search express rbac audit`, `npm search prisma audit`, GitHub code search) and a 3-sentence gap statement with findings.

- [ ] **T7.3 [MVP] `docs/THREAT_MODEL.md` + `docs/ARCHITECTURE.md`**
  - dep: T7.2 · Accept: threat model table (attacker capability → detected? → by what mechanism → residual risk) covering: DB write only, DB admin, key theft, truncation, app-level bypass, replay; architecture doc has the diagram and module responsibilities.

- [ ] **T7.4 [MVP] Package hygiene + publish dry-run**
  - dep: T7.1 · Accept: `files` whitelist (`dist`, `bin`, `prisma`, `README.md`, `LICENSE`); `npm pack --dry-run` lists only intended files; installing the tarball into a scratch project then `npx trailguard --version` and `import 'trailguard'` / `'trailguard/scan'` both work; runtime entry does not import `ts-morph` (assert via a test that inspects `dist/index.js` import graph); `.d.ts` audit passes (`tsc --noEmit` on a consumer snippet).

- [ ] **T7.5 [T2] Self-audit in CI**
  - dep: T6.1, T5.2 · Accept: CI job runs `trailguard ci --no-db` on the fixed demo app and fails the build if findings ≥ high; second CI job proves the **vulnerable** branch fails (expected-failure assertion).

- [ ] **T7.6 [T2] Final report assets**
  - dep: T7.3 · Accept: `docs/REPORT.md` skeleton with architecture diagram, before/after demo screenshots/outputs placeholders, syllabus-mapping table (Express routing/middleware, MySQL/Prisma, migrations, seeding, relations, **transactions**, JWT/RBAC, error handling, TypeScript/OOP, `fs` export, npm publish/CI/deployment), limitations.

---

## Definition of done (whole project)
- [ ] All **[MVP]** tasks ticked; `npm run lint && npm run typecheck && npm test && npm run test:int` green.
- [ ] `trailguard ci` on the fixed demo app → exit 0; after `demo:break` → exit 1 with exactly 3 HIGH findings.
- [ ] Tamper, rehash, and truncation demos all detected.
- [ ] README, THREAT_MODEL, DEMO docs complete and consistent with behavior.
- [ ] `npm publish --dry-run` clean.
