# Contributing to trailguard

Thanks for your interest. Bug reports, ideas, docs fixes and code are all welcome. By taking part you agree to follow the [Code of Conduct](./CODE_OF_CONDUCT.md).

## Ways to help

- **Report a bug** or a false positive/negative from the scanner (use the bug report template).
- **Suggest a feature or a new rule.**
- **Improve the docs**, README or examples.
- **Fix an issue** or pick one labelled `good first issue`.

For anything bigger than a small fix, please open an issue first so we can agree on the approach before you spend time on it.

## Setup

Requirements: Node.js 18.18 or newer, Docker (for the PostgreSQL integration tests).

```bash
git clone https://github.com/daksheshsharma2409/trailguard.git
cd trailguard
npm install
docker compose up -d        # PostgreSQL on port 5433 for integration tests
```

## Before you open a pull request

Run all of these and make sure they pass:

```bash
npm run lint
npm run typecheck
npm test
TEST_DATABASE_URL=postgresql://postgres:postgres@localhost:5433/trailguard_test npm run test:int
npm run build
```

## Project layout

| Folder | What lives there |
|---|---|
| `src/scan` | Static analysis: routes, middleware classification, rules, reports |
| `src/runtime` | Audited Prisma client, audit context, hash chain, verify, router |
| `src/core` | Errors, canonical JSON, crypto helpers |
| `src/cli.ts` | CLI argument parsing only; logic belongs in the library |
| `test/fixtures` | Small fake Express apps used to test the scanner |
| `docs/` | Design decisions, threat model, architecture |

Read [`context.md`](./context.md) for the full specification.

## Guidelines

- **Tests are required.** New behavior needs a test. A new scanner rule needs a fixture app with the expected findings.
- **Never weaken a test to make it pass.** If a test seems wrong, explain why in the pull request.
- **TypeScript strict mode, no `any`.** Use `unknown` and narrow it.
- **The CLI stays thin.** Put logic in the library and call it from `src/cli.ts`.
- **Be honest in wording.** The audit log is *tamper-evident*, not *tamper-proof*. Unrecognized middleware is *unknown*, never assumed safe.
- **Never print or log secrets**, including the HMAC key.
- **Rule IDs are stable.** Don't rename or renumber existing ones.
- Record non-obvious design choices in `docs/DECISIONS.md`.

## Commit messages

Short, imperative, and specific, for example:

```text
fix: handle router.use() declared after a route
feat: add RBAC008 orphan router rule
docs: clarify checkpoint setup in README
```

## Pull request process

1. Fork the repo and create a branch from `main`.
2. Make your change with tests and docs.
3. Fill in the pull request template.
4. A maintainer will review. Expect some back-and-forth, which is normal.

## Reporting security issues

Please do **not** open a public issue for vulnerabilities. See [SECURITY.md](./SECURITY.md).