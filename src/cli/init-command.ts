/**
 * CLI command runner for `trailguard init`.
 *
 * Scaffolds a starter `trailguard.config.ts`, prints the required Prisma
 * schema models (AuditLog and AuditHead), and provides 5-line next steps.
 *
 * @see tasks.md T5.4, context.md §1.5
 */

import * as fs from 'node:fs/promises';
import * as path from 'node:path';

export interface InitCommandOptions {
  force?: boolean | undefined;
  cwd?: string | undefined;
}

export interface InitOutcome {
  exitCode: number;
  message: string;
  configPath?: string | undefined;
}

export const STARTER_CONFIG_CONTENT = `import { defineConfig } from 'trailguard/scan';

/**
 * Trailguard Configuration
 *
 * Configures static AST route analysis and runtime audit log rules.
 * Customize these parameters to match your Express routes and Prisma models.
 */
export default defineConfig({
  // ── 1. Entry Points & Project Files ──────────────────────────────────────────
  // Entry point files where your Express app or root routers are instantiated.
  // Trailguard traces route trees starting from these files.
  entry: ['./src/app.ts'],

  // Path to your tsconfig.json (used to resolve import path aliases like '@/...').
  tsconfig: './tsconfig.json',

  // Path to your Prisma schema (used to extract models, fields, and relations).
  prismaSchema: './prisma/schema.prisma',

  // Globs to ignore during static analysis (e.g. test suites, build outputs).
  ignore: ['**/*.spec.ts', '**/*.test.ts', '**/test/**', '**/dist/**'],

  // ── 2. Authentication Middleware ─────────────────────────────────────────────
  // Names of middleware functions that authenticate requests (e.g. verify JWT/session).
  // Any mutating route (POST, PUT, PATCH, DELETE) lacking these triggers RBAC001.
  auth: {
    middleware: ['authenticate'],
  },

  // ── 3. Role-Based Access Control (RBAC) ──────────────────────────────────────
  // Configures how Trailguard detects and validates role restrictions on routes.
  roles: {
    // Middleware function names that check user roles (e.g. requireRole, hasRole).
    middleware: ['requireRole'],

    // How role arguments are passed to the middleware:
    // - 'allStringArgs':   requireRole('ADMIN', 'TEACHER')
    // - 'firstStringArg':  requireRole('ADMIN')
    // - 'arrayArg':        requireRole(['ADMIN', 'TEACHER'])
    extractor: 'allStringArgs',

    // All valid role names recognized by your application.
    // Trailguard flags RBAC004 if a route uses an unknown or typo'd role literal.
    known: ['ADMIN', 'USER'],
  },

  // ── 4. Resource & Route Mapping ──────────────────────────────────────────────
  // Explicit mapping between API URL prefixes and Prisma models.
  // Trailguard auto-guesses models from path segments (e.g. /api/users -> User),
  // but you can provide manual overrides here if your paths differ.
  resources: {
    '/api/users': 'User',
  },

  // Prisma models whose GET (read) endpoints MUST require authentication.
  // If an unauthenticated GET endpoint serves one of these models, RBAC003 is flagged.
  privateResources: ['User'],

  // ── 5. Runtime Audit Coverage ────────────────────────────────────────────────
  // Configures which Prisma models require tamper-evident audit logging.
  audit: {
    // Prisma model names that MUST be modified using auditClient.
    // If raw prisma.<model>.create/update/delete is used, AUD001 is flagged.
    models: ['User'],

    // Variable names used in your code for the audited Prisma client instance.
    clientNames: ['auditClient'],

    // Variable or function names used when mounting the audit query router.
    routerNames: ['auditRouter'],
  },

  // ── 6. Environment & Secret Keys ─────────────────────────────────────────────
  // Name of the environment variable that holds your HMAC-SHA256 signing secret key.
  keyEnv: 'TRAILGUARD_KEY',
});
`;

export const PRISMA_SCHEMA_SNIPPET = `// ── Add to your prisma/schema.prisma ─────────────────────────────────────────

model AuditLog {
  seq         BigInt   @id
  model       String   @db.VarChar(191)
  recordId    String   @db.VarChar(191)
  action      String   @db.VarChar(16)          // CREATE | UPDATE | DELETE
  actorId     String?  @db.VarChar(191)
  actorRole   String?  @db.VarChar(64)
  requestId   String?  @db.VarChar(64)
  ipAddress   String?  @db.VarChar(64)
  userAgent   String?  @db.VarChar(512)
  payload     String   @db.Text                 // CANONICAL string that is hashed. Source of truth.
  before      Json?                             // convenience copy (redacted)
  after       Json?                             // convenience copy (redacted)
  diff        Json?                             // convenience copy
  prevHash    String   @db.Char(64)
  hash        String   @unique @db.Char(64)
  keyId       String   @db.VarChar(32)
  createdAt   DateTime @default(now()) @db.Timestamp(3)

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
`;

export const NEXT_STEPS_TEXT = `Next steps:
1. Add the AuditLog and AuditHead models above to your prisma/schema.prisma
2. Run \`npx prisma db push\` (or \`npx prisma migrate dev\`) to create the audit tables
3. Set your secret HMAC key: export TRAILGUARD_KEY="$(openssl rand -hex 32)"
4. Update trailguard.config.ts with your route prefixes, roles, and audited models
5. Run \`npx trailguard scan\` to analyze your Express routes and Prisma mutations`;

/**
 * Runs the `trailguard init` workflow.
 */
export async function runInitCommand(opts: InitCommandOptions = {}): Promise<InitOutcome> {
  const cwd = opts.cwd ?? process.cwd();
  const targetFile = path.resolve(cwd, 'trailguard.config.ts');

  // Check if file already exists
  let exists = false;
  try {
    await fs.access(targetFile);
    exists = true;
  } catch {
    exists = false;
  }

  if (exists && !opts.force) {
    return {
      exitCode: 1,
      message: `Error: ${targetFile} already exists. Pass --force to overwrite.`,
    };
  }

  await fs.writeFile(targetFile, STARTER_CONFIG_CONTENT, 'utf8');

  return {
    exitCode: 0,
    configPath: targetFile,
    message: `Created ${targetFile}\n\n${PRISMA_SCHEMA_SNIPPET}\n${NEXT_STEPS_TEXT}`,
  };
}
