/**
 * Attacker script: truncate-tail.ts
 *
 * Simulates an attacker who deletes the most recent N audit log records
 * and resets the AuditHead table back to the previous head state.
 *
 * A database-only audit check sees an unbroken chain from seq 1 to the new head,
 * but external checkpoints recorded before the truncation detect the gap
 * and raise TRUNCATION_DETECTED.
 *
 * @see context.md §11, tasks.md T6.3
 */

import { PrismaClient } from '@prisma/client';

export interface TruncateTailOptions {
  /** Number of trailing rows to delete. Default: 1. */
  count?: number | undefined;
  /** Custom Prisma client. */
  prisma?: PrismaClient | undefined;
}

export async function truncateTail(options: TruncateTailOptions = {}): Promise<{
  rowsDeleted: number;
  newLastSeq: bigint;
  newLastHash: string;
}> {
  const databaseUrl =
    process.env.DATABASE_URL ||
    process.env.TEST_DATABASE_URL ||
    'mysql://root:root@localhost:3307/trailguard_test';

  const prisma =
    options.prisma ||
    new PrismaClient({
      datasources: { db: { url: databaseUrl } },
    });

  const count = options.count ?? 1;

  try {
    const headRows = await prisma.$queryRawUnsafe<Array<{ lastSeq: bigint; lastHash: string }>>(
      'SELECT lastSeq, lastHash FROM trailguard_audit_head WHERE id = 1',
    );

    if (headRows.length === 0) {
      throw new Error('AuditHead table is empty.');
    }

    const currentHead = headRows[0]!;
    const currentSeq = BigInt(currentHead.lastSeq);

    if (currentSeq <= BigInt(count)) {
      throw new Error(
        `Cannot truncate ${String(count)} rows from chain with head at seq ${String(currentSeq)}. Need at least ${String(count + 1)} rows.`,
      );
    }

    const targetSeq = currentSeq - BigInt(count);

    // 1. Delete rows after targetSeq
    await prisma.$executeRawUnsafe(
      'DELETE FROM trailguard_audit_log WHERE seq > ?',
      targetSeq,
    );

    // 2. Fetch the target row's hash
    const targetRows = await prisma.$queryRawUnsafe<Array<{ seq: bigint; hash: string }>>(
      'SELECT seq, hash FROM trailguard_audit_log WHERE seq = ?',
      targetSeq,
    );

    if (targetRows.length === 0) {
      throw new Error(`Target row seq ${String(targetSeq)} not found after deletion.`);
    }

    const newHead = targetRows[0]!;

    // 3. Reset AuditHead to target row
    await prisma.$executeRawUnsafe(
      'UPDATE trailguard_audit_head SET lastSeq = ?, lastHash = ? WHERE id = 1',
      newHead.seq,
      newHead.hash,
    );

    console.log(
      `Truncated tail: deleted rows with seq > ${String(targetSeq)}. Reset AuditHead to seq ${String(newHead.seq)}.`,
    );

    return {
      rowsDeleted: count,
      newLastSeq: newHead.seq,
      newLastHash: newHead.hash,
    };
  } finally {
    if (!options.prisma) {
      await prisma.$disconnect();
    }
  }
}

// Execute when invoked directly
if (import.meta.url === `file://${process.argv[1]}`) {
  const countArg = process.argv[2] ? parseInt(process.argv[2], 10) : 1;
  truncateTail({ count: countArg })
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('truncate-tail failed:', err);
      process.exit(1);
    });
}
