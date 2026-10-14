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

export default defineConfig({
  entry: ['./src/app.ts'],
  tsconfig: './tsconfig.json',
  prismaSchema: './prisma/schema.prisma',
  auth: {
    middleware: ['authenticate'],
  },
  roles: {
    middleware: ['requireRole'],
    extractor: 'allStringArgs',
    known: ['ADMIN', 'USER'],
  },
  resources: {
    '/api/users': 'User',
  },
  privateResources: ['User'],
  audit: {
    models: ['User'],
    clientNames: ['auditClient'],
    routerNames: ['auditRouter'],
  },
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
  payload     String   @db.LongText             // CANONICAL string that is hashed. Source of truth.
  before      Json?                             // convenience copy (redacted)
  after       Json?                             // convenience copy (redacted)
  diff        Json?                             // convenience copy
  prevHash    String   @db.Char(64)
  hash        String   @unique @db.Char(64)
  keyId       String   @db.VarChar(32)
  createdAt   DateTime @default(now()) @db.DateTime(3)

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
