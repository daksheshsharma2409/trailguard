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
    'postgresql://root:root@localhost:5432/trailguard_test?schema=public';

  const prisma =
    options.prisma ||
    new PrismaClient({
      datasources: { db: { url: databaseUrl } },
    });

  const count = options.count ?? 1;

  try {
    const currentHead = await prisma.auditHead.findUnique({
      where: { id: 1 },
    });

    if (!currentHead) {
      throw new Error('AuditHead table is empty.');
    }

    const currentSeq = BigInt(currentHead.lastSeq);

    if (currentSeq <= BigInt(count)) {
      throw new Error(
        `Cannot truncate ${String(count)} rows from chain with head at seq ${String(currentSeq)}. Need at least ${String(count + 1)} rows.`,
      );
    }

    const targetSeq = currentSeq - BigInt(count);

    // 1. Delete rows after targetSeq
    await prisma.auditLog.deleteMany({
      where: { seq: { gt: targetSeq } },
    });

    // 2. Fetch the target row's hash
    const newHead = await prisma.auditLog.findUnique({
      where: { seq: targetSeq },
    });

    if (!newHead) {
      throw new Error(`Target row seq ${String(targetSeq)} not found after deletion.`);
    }

    // 3. Reset AuditHead to target row
    await prisma.auditHead.update({
      where: { id: 1 },
      data: {
        lastSeq: newHead.seq,
        lastHash: newHead.hash,
      },
    });

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
