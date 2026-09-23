/**
 * Attacker script: rehash-chain.ts
 *
 * Simulates a sophisticated attacker who compromises database write access,
 * tampers with an audit row, and attempts to cover their tracks by recomputing
 * the entire hash chain forward using plain SHA-256 (or a guessed/wrong HMAC key)
 * and updating the AuditHead row.
 *
 * Because the attacker lacks the genuine application HMAC key, Trailguard's
 * verification detects this as HASH_MISMATCH.
 *
 * @see context.md §11, tasks.md T6.3
 */

import { createHash, createHmac } from 'node:crypto';
import { PrismaClient } from '@prisma/client';
import { GENESIS_HASH } from '../../src/core/constants.js';
import { stableStringify } from '../../src/core/canonical.js';

interface AuditRow {
  seq: bigint;
  model: string;
  recordId: string;
  action: string;
  actorId: string | null;
  actorRole: string | null;
  requestId: string | null;
  ipAddress: string | null;
  userAgent: string | null;
  payload: string;
  before: unknown;
  after: unknown;
  diff: unknown;
  prevHash: string;
  hash: string;
}

export interface RehashChainOptions {
  /** Target seq to tamper with before rehashing. Defaults to the last row. */
  targetSeq?: number | bigint | undefined;
  /** Attacker key. If omitted, uses plain SHA-256. */
  attackerKey?: string | undefined;
  /** Whether to modify the target row payload. Default: true. */
  tamperPayload?: boolean | undefined;
  /** Custom Prisma client or database URL. */
  prisma?: PrismaClient | undefined;
}

export async function rehashChain(options: RehashChainOptions = {}): Promise<{
  rowsRehashed: number;
  lastSeq: bigint;
  lastHash: string;
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

  try {
    const rows = (await prisma.$queryRawUnsafe<AuditRow[]>(
      'SELECT seq, model, recordId, action, actorId, actorRole, requestId, ipAddress, userAgent, payload, `before`, after, diff, prevHash, hash FROM trailguard_audit_log ORDER BY seq ASC',
    ));

    if (rows.length === 0) {
      console.log('No audit rows found to rehash.');
      return { rowsRehashed: 0, lastSeq: 0n, lastHash: GENESIS_HASH };
    }

    const targetSeq = options.targetSeq !== undefined
      ? BigInt(options.targetSeq)
      : BigInt(rows[rows.length - 1]!.seq);

    let prevHash = GENESIS_HASH;
    let lastHash = '';
    let lastSeq = 0n;

    for (const row of rows) {
      const seq = BigInt(row.seq);

      let payloadObj: Record<string, unknown>;
      try {
        payloadObj = JSON.parse(row.payload) as Record<string, unknown>;
      } catch {
        payloadObj = {
          v: 1,
          seq: seq.toString(),
          ts: new Date().toISOString(),
          model: row.model,
          recordId: row.recordId,
          action: row.action,
        };
      }

      // Tamper with the target row
      if (seq === targetSeq && options.tamperPayload !== false) {
        payloadObj.tamperedByAttacker = true;
        payloadObj.action = 'UPDATE';
      }

      // Chain the previous hash
      payloadObj.prevHash = prevHash;
      const canonicalPayload = stableStringify(payloadObj);

      // Attacker computes hash using plain SHA-256 or guessed wrong key
      let newHash: string;
      if (options.attackerKey) {
        newHash = createHmac('sha256', options.attackerKey)
          .update(canonicalPayload)
          .digest('hex');
      } else {
        newHash = createHash('sha256')
          .update(canonicalPayload)
          .digest('hex');
      }

      await prisma.$executeRawUnsafe(
        'UPDATE trailguard_audit_log SET payload = ?, prevHash = ?, hash = ? WHERE seq = ?',
        canonicalPayload,
        prevHash,
        newHash,
        seq,
      );

      prevHash = newHash;
      lastHash = newHash;
      lastSeq = seq;
    }

    // Update AuditHead so head matches the forged chain
    await prisma.$executeRawUnsafe(
      'UPDATE trailguard_audit_head SET lastSeq = ?, lastHash = ? WHERE id = 1',
      lastSeq,
      lastHash,
    );

    console.log(
      `Rehashed ${String(rows.length)} audit rows using ${options.attackerKey ? 'guessed key' : 'plain SHA-256'}. AuditHead updated to seq ${String(lastSeq)}.`,
    );

    return {
      rowsRehashed: rows.length,
      lastSeq,
      lastHash,
    };
  } finally {
    if (!options.prisma) {
      await prisma.$disconnect();
    }
  }
}

// Execute when invoked directly
if (import.meta.url === `file://${process.argv[1]}`) {
  rehashChain()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('rehash-chain failed:', err);
      process.exit(1);
    });
}
