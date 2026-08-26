# Static Analysis Test Fixtures

This directory contains standalone miniature Express applications used to test `trailguard`'s static analysis engine (`trailguard scan`).

## Fixture Structure

Each sub-directory in `test/fixtures/<name>` represents a self-contained Express codebase:

```
test/fixtures/<name>/
├── trailguard.config.ts    # Fixture configuration (entry, auth, roles, audit models)
├── tsconfig.json           # TypeScript configuration for the fixture
├── src/                    # Source files (Express app, routers, controllers)
│   ├── app.ts
│   └── ...
├── prisma/                 # Optional Prisma schema for the fixture
│   └── schema.prisma
└── expected.json           # Asserted findings, routes, and exit codes
```

## Fixture Catalog

The following fixtures correspond to the testing specification in `context.md §12.2`:

| Fixture | Description / Target Assertion | Expected Result |
|---|---|---|
| `clean` | Well-architected Express app with complete auth and role checks | 0 findings |
| `missing-auth` | Route `DELETE /api/posts/:id` missing authentication | `RBAC001` on `DELETE /api/posts/:id` |
| `auth-no-role` | Authenticated route missing role check on state-changing endpoint | `RBAC002` |
| `ownership-ok` | Route correctly implements ownership checks on records | `RBAC005` absent |
| `ownership-missing` | Mutating route lacks ownership validation | `RBAC005` present |
| `nested-routers` | 3-level deep router mount (`/api/v1` → `/posts` → `/:id`) | Composed `/api/v1/posts/:id`, mount middleware applied |
| `router-use-order` | Middleware declared after route (`router.post(...)` then `router.use(authenticate)`) | Unprotected route flagged; order preserved |
| `route-chain` | Route chaining `router.route('/:id').get().patch()` | Two distinct route nodes with individual chains |
| `dynamic-mount` | Dynamic path parameter in mount (e.g. `` `/api/${version}` ``) | Path segment `:dynamic`, `RBAC007`, confidence low |
| `unknown-mw` | Unknown third-party middleware | `RBAC006`, never counted as authentication/authorization |
| `bypass-audit-client` | Raw `prisma.model.update` used instead of audited client | `AUD001` flagged for raw client calls |
| `raw-sql` | Unaudited `$executeRaw` or `$queryRaw` usage | `AUD003` |
| `audit-router-unguarded` | `auditRouter` mounted without required guard | `AUD002` present |
| `audit-router-guarded` | `auditRouter` mounted with proper admin guard | `AUD002` absent |
| `baseline` | Known findings suppressed via baseline file | Suppressed finding absent from exit threshold |
| `import-resolution` | Multiple import forms (named, default, aliased, re-exported) | All routers and handlers resolve correctly |

## Harness Usage

Load fixtures in tests using `test/helpers/fixture.ts`:

```ts
import { loadFixture } from '../helpers/fixture.js';

const { project, config, expected } = await loadFixture('clean');
```
