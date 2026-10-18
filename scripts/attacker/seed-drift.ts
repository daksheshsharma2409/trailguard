/**
 * Script: seed-drift.ts
 *
 * Seeds an audit entry where a TEACHER deletes a User.
 * This action is not allowed by the static access matrix (ADMIN only),
 * simulating runtime privilege drift or an insider bypass.
 *
 * @see tasks.md T6.5, context.md §8
 */

import { PrismaClient } from '@prisma/client';
import { appendAuditEntries, type AuditPrismaTx } from '../../src/runtime/append.js';

export interface SeedDriftOptions {
  prisma?: PrismaClient | undefined;
  key?: string | undefined;
}

export async function seedDrift(options: SeedDriftOptions = {}): Promise<void> {
  const databaseUrl =
    process.env.DATABASE_URL ||
    process.env.TEST_DATABASE_URL ||
    'mysql://root:root@localhost:3307/trailguard_test';

  const prisma =
    options.prisma ||
    new PrismaClient({
      datasources: { db: { url: databaseUrl } },
    });

  const masterKey =
    options.key ||
    process.env.TRAILGUARD_KEY ||
    'demo-trailguard-master-key-32chars!!';

  try {
    await prisma.$transaction(async (tx) => {
      await appendAuditEntries(
        tx as unknown as AuditPrismaTx,
        [
          {
            model: 'User',
            recordId: 'user-drift-victim-1',
            action: 'DELETE',
            actorId: 'teacher-101',
            actorRole: 'TEACHER',
            requestId: 'req-drift-bypass-001',
            ipAddress: '192.168.1.150',
            userAgent: 'curl/8.1.2',
            before: { id: 'user-drift-victim-1', email: 'victim@college.edu', role: 'STUDENT' },
            after: null,
            diff: { id: 'user-drift-victim-1', email: 'victim@college.edu' },
          },
        ],
        {
          key: masterKey,
          keyId: 'k1',
        },
      );
    });

    console.log('Seeded drift entry: TEACHER deleted User (seq appended to audit log).');
  } finally {
    if (!options.prisma) {
      await prisma.$disconnect();
    }
  }
}

// Execute when invoked directly
if (import.meta.url === `file://${process.argv[1]}`) {
  seedDrift()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('seed-drift failed:', err);
      process.exit(1);
    });
}
