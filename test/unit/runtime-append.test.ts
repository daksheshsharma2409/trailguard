/**
 * Unit tests for audit log append algorithm (runtime/append.ts).
 *
 * Tests all branches using mock AuditPrismaTx without requiring PostgreSQL:
 * - Empty entries array returns []
 * - testHooks.beforeAppend execution
 * - Head row initialization via ensureHeadRow
 * - Head re-initialization if missing when locking
 * - Appending single entry and multiple entries with gapless seq and hash chaining
 * - Updating head row at commit
 * - resetHeadCache and isHeadInitialized
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { GENESIS_HASH } from '../../src/core/constants.js';
import {
  appendAuditEntries,
  ensureHeadRow,
  resetHeadCache,
  isHeadInitialized,
  type AuditPrismaTx,
  type AppendEntryInput,
} from '../../src/runtime/append.js';

describe('Unit: appendAuditEntries (runtime/append.ts)', () => {
  const masterKey = 'test-audit-master-key-32-chars!!';
  const keyId = 'k1';

  beforeEach(() => {
    resetHeadCache();
  });

  function createMockTx(initialHead = { lastSeq: 0n, lastHash: GENESIS_HASH }): {
    tx: AuditPrismaTx;
    createdRows: Array<Record<string, unknown>>;
    headUpdates: Array<{ lastSeq: bigint; lastHash: string }>;
  } {
    const createdRows: Array<Record<string, unknown>> = [];
    const headUpdates: Array<{ lastSeq: bigint; lastHash: string }> = [];
    let currentHead = { ...initialHead };

    const tx: AuditPrismaTx = {
      auditHead: {
        update: async (args) => {
          currentHead = { lastSeq: args.data.lastSeq, lastHash: args.data.lastHash };
          headUpdates.push(currentHead);
          return currentHead;
        },
        createMany: async () => {
          return { count: 1 };
        },
      },
      auditLog: {
        create: async (args) => {
          createdRows.push(args.data);
          return args.data;
        },
      },
      $queryRaw: async () => {
        return [currentHead];
      },
    };

    return { tx, createdRows, headUpdates };
  }

  it('returns empty array when entries list is empty', async () => {
    const { tx } = createMockTx();
    const result = await appendAuditEntries(tx, [], { key: masterKey, keyId });
    expect(result).toEqual([]);
  });

  it('executes beforeAppend testHook if provided', async () => {
    const { tx } = createMockTx();
    let hookRan = false;

    await appendAuditEntries(
      tx,
      [
        {
          model: 'Student',
          recordId: 'rec-1',
          action: 'CREATE',
        },
      ],
      {
        key: masterKey,
        keyId,
        testHooks: {
          beforeAppend: () => {
            hookRan = true;
          },
        },
      },
    );

    expect(hookRan).toBe(true);
  });

  it('tracks head initialization state and resetHeadCache', async () => {
    expect(isHeadInitialized()).toBe(false);
    const { tx } = createMockTx();
    await ensureHeadRow(tx);
    expect(isHeadInitialized()).toBe(true);
    resetHeadCache();
    expect(isHeadInitialized()).toBe(false);
  });

  it('appends multiple entries with gapless seq and chained hashes', async () => {
    const { tx, createdRows, headUpdates } = createMockTx();

    const entries: AppendEntryInput[] = [
      {
        model: 'Student',
        recordId: 's-1',
        action: 'CREATE',
        actorId: 'admin-1',
        actorRole: 'ADMIN',
        after: { name: 'Alice' },
      },
      {
        model: 'Student',
        recordId: 's-1',
        action: 'UPDATE',
        actorId: 'admin-1',
        actorRole: 'ADMIN',
        before: { name: 'Alice' },
        after: { name: 'Alicia' },
        diff: { name: { old: 'Alice', new: 'Alicia' } },
      },
    ];

    const results = await appendAuditEntries(tx, entries, { key: masterKey, keyId });

    expect(results).toHaveLength(2);
    expect(createdRows).toHaveLength(2);

    // Row 1
    expect(results[0]?.seq).toBe(1n);
    expect(results[0]?.prevHash).toBe(GENESIS_HASH);
    expect(results[0]?.hash).toHaveLength(64);

    // Row 2
    expect(results[1]?.seq).toBe(2n);
    expect(results[1]?.prevHash).toBe(results[0]?.hash);
    expect(results[1]?.hash).toHaveLength(64);

    // Head updated to last entry
    expect(headUpdates).toHaveLength(1);
    expect(headUpdates[0]?.lastSeq).toBe(2n);
    expect(headUpdates[0]?.lastHash).toBe(results[1]?.hash);
  });

  it('re-initializes head if head query returns empty', async () => {
    let queryCount = 0;
    const { tx } = createMockTx();

    // Mock queryRaw to return empty on first query, then return head on retry
    tx.$queryRaw = async () => {
      queryCount++;
      if (queryCount === 1) {
        return [];
      }
      return [{ lastSeq: 0n, lastHash: GENESIS_HASH }];
    };

    const results = await appendAuditEntries(
      tx,
      [
        {
          model: 'Student',
          recordId: 'rec-1',
          action: 'CREATE',
        },
      ],
      { key: masterKey, keyId },
    );

    expect(results).toHaveLength(1);
    expect(results[0]?.seq).toBe(1n);
  });
});
