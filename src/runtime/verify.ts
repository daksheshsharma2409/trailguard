/**
 * Audit log verification algorithm.
 *
 * Verifies cryptographic integrity of the append-only HMAC chain:
 * 1. Gapless sequence numbers: seq === expectedSeq (else SEQ_GAP).
 * 2. Hash chaining: prevHash === expectedPrev (else PREV_HASH_MISMATCH).
 * 3. Known HMAC keyId (else UNKNOWN_KEY).
 * 4. Timing-safe HMAC payload verification (else HASH_MISMATCH).
 * 5. Deep-equal canonical cross-check of columns against payload (else COLUMN_PAYLOAD_MISMATCH).
 * 6. AuditHead synchronization with last row (else HEAD_MISMATCH).
 * 7. External checkpoints verification.
 *
 * @see context.md §7.9
 */

import {
  AUDIT_HEAD_ID,
  CHECKPOINT_SIG_PREFIX,
  DEFAULT_KEY_ID,
  GENESIS_HASH,
  VERIFY_BATCH_SIZE,
} from '../core/constants.js';
import { stableStringify } from '../core/canonical.js';
import { hmacHex, timingSafeEqualHex } from '../core/crypto.js';
import type {
  Checkpoint,
  KeysOptions,
  KeysShorthand,
  VerifyProblem,
  VerifyResult,
} from '../core/types.js';

export interface VerifyRow {
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
  keyId: string;
  createdAt: Date;
}

export interface VerifyPrismaClient {
  auditLog: {
    findMany: (args: {
      where?: Record<string, unknown> | undefined;
      orderBy: { seq: 'asc' };
      take: number;
    }) => Promise<VerifyRow[]>;
    findUnique?: ((args: { where: { seq: bigint } }) => Promise<VerifyRow | null>) | undefined;
  };
  auditHead: {
    findUnique: (args: {
      where: { id: number };
    }) => Promise<{ id: number; lastSeq: bigint; lastHash: string } | null>;
  };
}

export interface VerifyOptions {
  prisma: VerifyPrismaClient;
  keys: KeysOptions | KeysShorthand;
  batchSize?: number;
  all?: boolean;
  checkpoints?: Checkpoint[];
}

function resolveKeyMap(keys: KeysOptions | KeysShorthand): Map<string, string> {
  const map = new Map<string, string>();
  if ('secret' in keys) {
    map.set(DEFAULT_KEY_ID, keys.secret);
  } else {
    for (const [id, secret] of Object.entries(keys.secrets)) {
      map.set(id, secret);
    }
  }
  return map;
}

/**
 * Verify the audit log chain integrity and head alignment.
 *
 * @param options - Verification options including Prisma client and HMAC keys.
 * @returns Verification result containing validity status and any detected problems.
 */
export async function verifyAuditChain(options: VerifyOptions): Promise<VerifyResult> {
  const { prisma, all = false, batchSize = VERIFY_BATCH_SIZE } = options;
  const keyMap = resolveKeyMap(options.keys);

  const problems: VerifyProblem[] = [];
  const maxProblems = 100;

  function addProblem(problem: VerifyProblem): boolean {
    if (problems.length < maxProblems) {
      problems.push(problem);
    }
    return !all; // return true if verification should stop immediately
  }

  let expectedSeq = 1n;
  let expectedPrev = GENESIS_HASH;
  let lastRow: VerifyRow | null = null;
  let checkedRecords = 0;
  let cursorSeq: bigint | null = null;

  for (;;) {
    const where: Record<string, unknown> = {};
    if (cursorSeq !== null) {
      where['seq'] = { gt: cursorSeq };
    }

    const batch = await prisma.auditLog.findMany({
      where: Object.keys(where).length > 0 ? where : undefined,
      orderBy: { seq: 'asc' },
      take: batchSize,
    });

    if (batch.length === 0) {
      break;
    }

    for (const row of batch) {
      checkedRecords++;
      cursorSeq = row.seq;
      const seqStr = row.seq.toString();

      // 1. Check seq
      if (row.seq !== expectedSeq) {
        const stop = addProblem({
          code: 'SEQ_GAP',
          seq: seqStr,
          message: `Sequence gap detected: expected seq ${expectedSeq.toString()} but found ${seqStr}`,
        });
        if (stop) break;
        expectedSeq = row.seq; // advance to avoid cascading errors in --all mode
      }

      // 2. Check prevHash
      if (row.prevHash !== expectedPrev) {
        const stop = addProblem({
          code: 'PREV_HASH_MISMATCH',
          seq: seqStr,
          message: `Previous hash mismatch for seq ${seqStr}: expected ${expectedPrev} but found ${row.prevHash}`,
        });
        if (stop) break;
      }

      // 3. Check keyId
      const secret = keyMap.get(row.keyId);
      if (!secret) {
        const stop = addProblem({
          code: 'UNKNOWN_KEY',
          seq: seqStr,
          message: `Unknown HMAC keyId '${row.keyId}' at seq ${seqStr}`,
        });
        if (stop) break;
      } else {
        // 4. HMAC verify
        const expectedHash = hmacHex(secret, row.payload);
        if (!timingSafeEqualHex(expectedHash, row.hash)) {
          const stop = addProblem({
            code: 'HASH_MISMATCH',
            seq: seqStr,
            message: `HMAC verification failed for seq ${seqStr}`,
          });
          if (stop) break;
        }
      }

      // 5. Cross-check columns against payload
      try {
        const parsed = JSON.parse(row.payload) as Record<string, unknown>;

        const fieldsMatch =
          parsed['seq'] === seqStr &&
          parsed['model'] === row.model &&
          parsed['recordId'] === row.recordId &&
          parsed['action'] === row.action &&
          (parsed['actorId'] ?? null) === (row.actorId ?? null) &&
          (parsed['actorRole'] ?? null) === (row.actorRole ?? null) &&
          (parsed['requestId'] ?? null) === (row.requestId ?? null) &&
          (parsed['prevHash'] ?? null) === row.prevHash;

        const beforeMatch =
          stableStringify(parsed['before'] ?? null) ===
          stableStringify(row.before ?? null);
        const afterMatch =
          stableStringify(parsed['after'] ?? null) ===
          stableStringify(row.after ?? null);
        const diffMatch =
          stableStringify(parsed['diff'] ?? null) ===
          stableStringify(row.diff ?? null);

        if (!fieldsMatch || !beforeMatch || !afterMatch || !diffMatch) {
          const stop = addProblem({
            code: 'COLUMN_PAYLOAD_MISMATCH',
            seq: seqStr,
            message: `Database columns do not match canonical payload for seq ${seqStr}`,
          });
          if (stop) break;
        }
      } catch {
        const stop = addProblem({
          code: 'COLUMN_PAYLOAD_MISMATCH',
          seq: seqStr,
          message: `Payload is not valid JSON at seq ${seqStr}`,
        });
        if (stop) break;
      }

      expectedSeq = row.seq + 1n;
      expectedPrev = row.hash;
      lastRow = row;
    }

    if (!all && problems.length > 0) {
      break;
    }
  }

  // 6. Check AuditHead
  const head = await prisma.auditHead.findUnique({
    where: { id: AUDIT_HEAD_ID },
  });

  if (lastRow !== null) {
    if (!head || head.lastSeq !== lastRow.seq || head.lastHash !== lastRow.hash) {
      addProblem({
        code: 'HEAD_MISMATCH',
        seq: lastRow.seq.toString(),
        message: `AuditHead (${head ? head.lastSeq.toString() : 'missing'}) does not match last audit record (${lastRow.seq.toString()})`,
      });
    }
  } else if (head && head.lastSeq > 0n) {
    addProblem({
      code: 'HEAD_MISMATCH',
      message: `AuditHead has lastSeq=${head.lastSeq.toString()} but audit log is empty`,
    });
  }

  // 7. Checkpoints (if provided)
  let checkpointsChecked = 0;
  if (options.checkpoints && options.checkpoints.length > 0) {
    for (const cp of options.checkpoints) {
      checkpointsChecked++;
      const cpSeqBig = BigInt(cp.seq);

      // Truncation check
      const maxSeq = lastRow ? lastRow.seq : 0n;
      if (cpSeqBig > maxSeq) {
        const stop = addProblem({
          code: 'TRUNCATION_DETECTED',
          seq: cp.seq,
          message: `Checkpoint references seq ${cp.seq} beyond last recorded seq ${maxSeq.toString()}`,
        });
        if (stop) break;
        continue;
      }

      // Checkpoint signature verification
      const secret = keyMap.get(cp.keyId);
      if (!secret) {
        const stop = addProblem({
          code: 'CHECKPOINT_BAD_SIGNATURE',
          seq: cp.seq,
          message: `Unknown keyId '${cp.keyId}' in checkpoint at seq ${cp.seq}`,
        });
        if (stop) break;
        continue;
      }

      const sigPayload = `${CHECKPOINT_SIG_PREFIX}${cp.seq}:${cp.hash}:${cp.ts}:${cp.keyId}`;
      const expectedSig = hmacHex(secret, sigPayload);
      if (!timingSafeEqualHex(expectedSig, cp.sig)) {
        const stop = addProblem({
          code: 'CHECKPOINT_BAD_SIGNATURE',
          seq: cp.seq,
          message: `Checkpoint signature verification failed for seq ${cp.seq}`,
        });
        if (stop) break;
        continue;
      }

      // Verify checkpoint hash matches row in DB
      let targetRow: VerifyRow | null = null;
      if (lastRow && lastRow.seq === cpSeqBig) {
        targetRow = lastRow;
      } else if (typeof prisma.auditLog.findUnique === 'function') {
        targetRow = await prisma.auditLog.findUnique({ where: { seq: cpSeqBig } });
      } else {
        const matching = await prisma.auditLog.findMany({
          where: { seq: cpSeqBig },
          orderBy: { seq: 'asc' },
          take: 1,
        });
        targetRow = matching[0] ?? null;
      }

      if (!targetRow || targetRow.hash !== cp.hash) {
        const stop = addProblem({
          code: 'CHECKPOINT_MISMATCH',
          seq: cp.seq,
          message: `Checkpoint hash at seq ${cp.seq} does not match database record`,
        });
        if (stop) break;
      }
    }
  }

  const valid = problems.length === 0;
  const firstProblem = problems[0];

  return {
    valid,
    checkedRecords,
    head: head ? { seq: head.lastSeq.toString(), hash: head.lastHash } : undefined,
    checkpointsChecked,
    problems,
    brokenAt: firstProblem?.seq,
    reason: firstProblem?.message,
  };
}
