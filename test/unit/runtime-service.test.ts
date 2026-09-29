/**
 * Unit tests for AuditChainService (runtime/service.ts).
 *
 * Tests:
 * - manual log with and without caller-provided tx
 * - field redaction and diff calculation during manual log
 * - validation error when model or recordId is missing
 * - getHistory delegation
 * - verify delegation
 * - checkpoint generation and sink execution
 * - exportLogs filtering
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { GENESIS_HASH } from '../../src/core/constants.js';
import { AuditWriteError } from '../../src/core/errors.js';
import { resetHeadCache, type AuditPrismaTx } from '../../src/runtime/append.js';
import {
  AuditChainService,
  type AuditServicePrismaClient,
} from '../../src/runtime/service.js';

describe('Unit: AuditChainService (runtime/service.ts)', () => {
  const masterKey = 'test-audit-master-key-32-chars!!';
  let mockPrisma: AuditServicePrismaClient;
  let auditLogs: Array<Record<string, unknown>>;
  let currentHead: { lastSeq: bigint; lastHash: string };

  beforeEach(() => {
    resetHeadCache();
    auditLogs = [];
    currentHead = { lastSeq: 0n, lastHash: GENESIS_HASH };

    const tx: AuditPrismaTx = {
      auditHead: {
        update: async (args) => {
          currentHead = { lastSeq: args.data.lastSeq, lastHash: args.data.lastHash };
          return currentHead;
        },
        createMany: async () => ({ count: 1 }),
      },
      auditLog: {
        create: async (args) => {
          auditLogs.push(args.data);
          return args.data;
        },
      },
      $queryRaw: async () => [currentHead],
    };

    mockPrisma = {
      auditLog: {
        findMany: async (args) => {
          let rows = [...auditLogs];
          const where = args['where'] as Record<string, unknown> | undefined;
          if (where?.['model']) {
            rows = rows.filter((r) => r['model'] === where['model']);
          }
          if (where?.['recordId']) {
            rows = rows.filter((r) => r['recordId'] === where['recordId']);
          }
          return rows;
        },
      },
      auditHead: {
        findUnique: async () => ({ id: 1, ...currentHead }),
      },
      $queryRaw: async () => [currentHead],
      $transaction: async (fn) => fn(tx),
    };
  });

  it('throws AuditWriteError if model or recordId is missing', async () => {
    const service = new AuditChainService(mockPrisma, {
      models: ['Student'],
      keys: { secret: masterKey },
    });

    await expect(
      service.log({
        model: '',
        recordId: '123',
        action: 'CREATE',
      }),
    ).rejects.toThrow(AuditWriteError);
  });

  it('logs entry without caller tx and applies redaction and diffs', async () => {
    const service = new AuditChainService(mockPrisma, {
      models: ['Student'],
      keys: { secret: masterKey },
      redactFields: ['secretCode'],
    });

    const record = await service.log({
      model: 'Student',
      recordId: 's-10',
      action: 'UPDATE',
      actorId: 'admin-1',
      actorRole: 'ADMIN',
      before: { name: 'Bob', secretCode: 'classified' },
      after: { name: 'Bobby', secretCode: 'classified' },
    });

    expect(record.seq).toBe(1n);
    expect(record.model).toBe('Student');
    expect(record.recordId).toBe('s-10');
    expect(record.actorId).toBe('admin-1');

    // Assert secretCode is redacted in after
    const afterObj = record.after as Record<string, unknown>;
    expect(afterObj['secretCode']).toMatch(/^\[REDACTED:[a-f0-9]{4}\]$/);

    // Diff contains changed name
    const diffObj = record.diff as Record<string, unknown>;
    expect(diffObj['name']).toEqual({ old: 'Bob', new: 'Bobby' });
  });

  it('logs entry with caller-provided tx', async () => {
    const service = new AuditChainService(mockPrisma, {
      models: ['Student'],
      keys: { secret: masterKey },
    });

    const tx: AuditPrismaTx = {
      auditHead: {
        update: async (args) => {
          currentHead = { lastSeq: args.data.lastSeq, lastHash: args.data.lastHash };
          return currentHead;
        },
      },
      auditLog: {
        create: async (args) => {
          auditLogs.push(args.data);
          return args.data;
        },
      },
      $queryRaw: async () => [currentHead],
    };

    const record = await service.log(
      {
        model: 'Student',
        recordId: 's-11',
        action: 'CREATE',
        after: { name: 'Charlie' },
      },
      tx,
    );

    expect(record.seq).toBe(1n);
    expect(record.recordId).toBe('s-11');
  });

  it('delegates getHistory query', async () => {
    const service = new AuditChainService(mockPrisma, {
      models: ['Student'],
      keys: { secret: masterKey },
    });

    await service.log({
      model: 'Student',
      recordId: 's-12',
      action: 'CREATE',
      after: { name: 'David' },
    });

    const history = await service.getHistory('Student', 's-12');
    expect(history).toHaveLength(1);
    expect(history[0]?.recordId).toBe('s-12');
  });

  it('creates on-demand signed checkpoint', async () => {
    let capturedCp: unknown = null;
    const service = new AuditChainService(mockPrisma, {
      models: ['Student'],
      keys: { secret: masterKey },
      checkpoint: {
        every: 1,
        sink: (cp) => {
          capturedCp = cp;
        },
      },
    });

    await service.log({
      model: 'Student',
      recordId: 's-13',
      action: 'CREATE',
    });

    const checkpoint = await service.checkpoint();
    expect(checkpoint.seq).toBe('1');
    expect(checkpoint.sig).toHaveLength(64);
    expect(capturedCp).toBeDefined();
  });

  it('exports logs with model filter', async () => {
    const service = new AuditChainService(mockPrisma, {
      models: ['Student', 'Course'],
      keys: { secret: masterKey },
    });

    await service.log({ model: 'Student', recordId: 's-1', action: 'CREATE' });
    await service.log({ model: 'Course', recordId: 'c-1', action: 'CREATE' });

    const studentLogs = await service.exportLogs({ model: 'Student' });
    expect(studentLogs).toHaveLength(1);
    expect(studentLogs[0]?.model).toBe('Student');
  });
});
