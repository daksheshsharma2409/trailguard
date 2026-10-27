/**
 * Audit log append algorithm.
 *
 * Runs inside an interactive transaction with the business write:
 * 1. Ensures the AuditHead row exists.
 * 2. Locks AuditHead with SELECT ... FOR UPDATE last.
 * 3. Assigns gapless sequence numbers and computes HMAC-SHA256 chained hashes.
 * 4. Appends audit rows and updates AuditHead.
 *
 * @see context.md §7.2, §7.4
 */

import {
  AUDIT_HEAD_ID,
  GENESIS_HASH,
  PAYLOAD_VERSION,
} from '../core/constants.js';
import { stableStringify } from '../core/canonical.js';
import { hmacHex } from '../core/crypto.js';
import { AuditWriteError } from '../core/errors.js';
import type { AuditAction } from '../core/types.js';

export interface AppendEntryInput {
  model: string;
  recordId: string;
  action: AuditAction;
  actorId?: string | null | undefined;
  actorRole?: string | null | undefined;
  requestId?: string | null | undefined;
  ipAddress?: string | null | undefined;
  userAgent?: string | null | undefined;
  before?: unknown;
  after?: unknown;
  diff?: unknown;
}

export interface AppendOptions {
  keyId: string;
  key: string | Buffer;
  testHooks?: {
    beforeAppend?: (() => void | Promise<void>) | undefined;
  } | undefined;
}

export interface AppendedRecord {
  seq: bigint;
  model: string;
  recordId: string;
  action: AuditAction;
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

export interface AuditPrismaTx {
  auditHead: {
    update: (args: {
      where: { id: number };
      data: { lastSeq: bigint; lastHash: string };
    }) => Promise<unknown>;
    createMany?: (args: {
      data: Array<{ id: number; lastSeq: bigint; lastHash: string }>;
      skipDuplicates?: boolean;
    }) => Promise<unknown>;
  };
  auditLog: {
    create: (args: { data: Record<string, unknown> }) => Promise<unknown>;
  };
  $queryRaw: <T = unknown>(
    query: TemplateStringsArray,
    ...values: unknown[]
  ) => Promise<T>;
}

let headInitialized = false;
let initPromise: Promise<void> | null = null;

/**
 * Returns whether the head row has already been initialized in the database.
 */
export function isHeadInitialized(): boolean {
  return headInitialized;
}

/**
 * Reset in-memory flag tracking whether the AuditHead row has been initialized.
 * Useful for test suites that reset the database.
 */
export function resetHeadCache(): void {
  headInitialized = false;
  initPromise = null;
}

/**
 * Ensure AuditHead row (id = 1) exists in the database.
 */
export async function ensureHeadRow(txOrClient: AuditPrismaTx): Promise<void> {
  if (headInitialized) {
    return;
  }
  if (!initPromise) {
    initPromise = (async () => {
      try {
        if (typeof txOrClient.auditHead.createMany === 'function') {
          await txOrClient.auditHead.createMany({
            data: [{ id: AUDIT_HEAD_ID, lastSeq: 0n, lastHash: GENESIS_HASH }],
            skipDuplicates: true,
          });
        }
        headInitialized = true;
      } finally {
        initPromise = null;
      }
    })();
  }
  await initPromise;
}

/**
 * Append one or more audit log entries within an interactive transaction.
 *
 * @param tx - Interactive transaction client.
 * @param entries - Entries to append.
 * @param options - HMAC key, keyId, and optional test hooks.
 * @returns Array of created audit log records.
 */
export async function appendAuditEntries(
  tx: AuditPrismaTx,
  entries: AppendEntryInput[],
  options: AppendOptions,
): Promise<AppendedRecord[]> {
  if (entries.length === 0) {
    return [];
  }

  if (options.testHooks?.beforeAppend) {
    await options.testHooks.beforeAppend();
  }

  await ensureHeadRow(tx);

  // Lock head last to minimize lock-hold time
  let headRows = await tx.$queryRaw<Array<{ lastSeq: bigint; lastHash: string }>>`
    SELECT "lastSeq", "lastHash" FROM "trailguard_audit_head" WHERE id = 1 FOR UPDATE
  `;

  if (headRows.length === 0) {
    // If head was wiped or missing, initialize and re-lock
    if (typeof tx.auditHead.createMany === 'function') {
      await tx.auditHead.createMany({
        data: [{ id: AUDIT_HEAD_ID, lastSeq: 0n, lastHash: GENESIS_HASH }],
        skipDuplicates: true,
      });
    }
    headRows = await tx.$queryRaw<Array<{ lastSeq: bigint; lastHash: string }>>`
      SELECT "lastSeq", "lastHash" FROM "trailguard_audit_head" WHERE id = 1 FOR UPDATE
    `;
  }

  const head = headRows[0];
  if (!head) {
    throw new AuditWriteError('Failed to acquire head lock on trailguard_audit_head');
  }

  let currentSeq = head.lastSeq;
  let currentHash = head.lastHash;
  const created: AppendedRecord[] = [];

  for (const entry of entries) {
    const seq = currentSeq + 1n;
    const prevHash = currentHash;
    const ts = new Date().toISOString();

    const payloadObj = {
      v: PAYLOAD_VERSION,
      seq: seq.toString(),
      ts,
      model: entry.model,
      recordId: entry.recordId,
      action: entry.action,
      actorId: entry.actorId ?? null,
      actorRole: entry.actorRole ?? null,
      requestId: entry.requestId ?? null,
      ipAddress: entry.ipAddress ?? null,
      userAgent: entry.userAgent ?? null,
      before: entry.before ?? null,
      after: entry.after ?? null,
      diff: entry.diff ?? null,
      prevHash,
    };

    const payload = stableStringify(payloadObj);
    const hash = hmacHex(options.key, payload);

    const rowData = {
      seq,
      model: entry.model,
      recordId: entry.recordId,
      action: entry.action,
      actorId: entry.actorId ?? null,
      actorRole: entry.actorRole ?? null,
      requestId: entry.requestId ?? null,
      ipAddress: entry.ipAddress ?? null,
      userAgent: entry.userAgent ?? null,
      payload,
      before: entry.before ?? null,
      after: entry.after ?? null,
      diff: entry.diff ?? null,
      prevHash,
      hash,
      keyId: options.keyId,
    };

    await tx.auditLog.create({ data: rowData });

    created.push({
      ...rowData,
      createdAt: new Date(ts),
    });

    currentSeq = seq;
    currentHash = hash;
  }

  await tx.auditHead.update({
    where: { id: AUDIT_HEAD_ID },
    data: {
      lastSeq: currentSeq,
      lastHash: currentHash,
    },
  });

  return created;
}
