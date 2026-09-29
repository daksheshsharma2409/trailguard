/**
 * Unit tests for createAuditClient and helpers (runtime/client.ts).
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { GENESIS_HASH } from '../../src/core/constants.js';
import { AuditConfigError } from '../../src/core/errors.js';
import { resetHeadCache } from '../../src/runtime/append.js';
import { runWithAuditContext } from '../../src/runtime/context.js';
import {
  createAuditClient,
  toDelegateName,
  resolveKeys,
} from '../../src/runtime/client.js';

describe('Unit: createAuditClient (runtime/client.ts)', () => {
  const masterKey = 'test-audit-master-key-32-chars!!';

  beforeEach(() => {
    resetHeadCache();
  });

  it('toDelegateName lowercases first letter', () => {
    expect(toDelegateName('Student')).toBe('student');
    expect(toDelegateName('UserProfile')).toBe('userProfile');
    expect(toDelegateName('')).toBe('');
  });

  it('resolveKeys resolves shorthand secret to default keyId', () => {
    const keys = resolveKeys({
      models: ['Student'],
      keys: { secret: masterKey },
    });

    expect(keys.currentKeyId).toBe('default');
    expect(keys.currentKey).toBe(masterKey);
  });

  it('resolveKeys throws if shorthand secret is empty', () => {
    expect(() =>
      resolveKeys({
        models: ['Student'],
        keys: { secret: '' },
      }),
    ).toThrow(AuditConfigError);
  });

  it('resolveKeys resolves multi-key config', () => {
    const keys = resolveKeys({
      models: ['Student'],
      keys: {
        current: 'k2',
        secrets: {
          k1: 'old-key-secret-32-chars-long!!!!',
          k2: masterKey,
        },
      },
    });

    expect(keys.currentKeyId).toBe('k2');
    expect(keys.currentKey).toBe(masterKey);
  });

  it('resolveKeys throws if current key is missing from secrets', () => {
    expect(() =>
      resolveKeys({
        models: ['Student'],
        keys: {
          current: 'k3',
          secrets: {
            k1: 'secret-1',
          },
        },
      }),
    ).toThrow(AuditConfigError);
  });

  it('createAuditClient throws if models array is empty', () => {
    const mockPrisma = {
      $extends: vi.fn(),
      $transaction: vi.fn(),
    };

    expect(() =>
      createAuditClient(mockPrisma, {
        models: [],
        keys: { secret: masterKey },
      }),
    ).toThrow(AuditConfigError);
  });

  it('createAuditClient registers query extensions on $allModels', () => {
    let capturedExtension: unknown = null;
    const mockPrisma = {
      $extends: vi.fn((ext) => {
        capturedExtension = ext;
        return { extended: true };
      }),
      $transaction: vi.fn(),
    };

    const client = createAuditClient(mockPrisma, {
      models: ['Student'],
      keys: { secret: masterKey },
    });

    expect(client).toEqual({ extended: true });
    expect(mockPrisma.$extends).toHaveBeenCalledTimes(1);
    expect(capturedExtension).toBeDefined();

    const extObj = capturedExtension as {
      name: string;
      query: {
        $allModels: {
          create: unknown;
          update: unknown;
          delete: unknown;
          upsert: unknown;
        };
      };
    };

    expect(extObj.name).toBe('trailguard-audit');
    expect(typeof extObj.query.$allModels.create).toBe('function');
    expect(typeof extObj.query.$allModels.update).toBe('function');
    expect(typeof extObj.query.$allModels.delete).toBe('function');
    expect(typeof extObj.query.$allModels.upsert).toBe('function');
  });

  it('intercepts create, update, delete, and upsert for audited models', async () => {
    let capturedExtension: {
      name: string;
      query: {
        $allModels: {
          create: (args: Record<string, unknown>) => Promise<unknown>;
          update: (args: Record<string, unknown>) => Promise<unknown>;
          delete: (args: Record<string, unknown>) => Promise<unknown>;
          upsert: (args: Record<string, unknown>) => Promise<unknown>;
        };
      };
    } | null = null;

    const mockTx = {
      student: {
        create: async (args: Record<string, unknown>) => ({ id: 's-1', ...(args['data'] as Record<string, unknown>) }),
        update: async (args: Record<string, unknown>) => ({ id: (args['where'] as Record<string, unknown>)['id'], ...(args['data'] as Record<string, unknown>) }),
        delete: async (args: Record<string, unknown>) => ({ id: (args['where'] as Record<string, unknown>)['id'], name: 'Alice' }),
        upsert: async (args: Record<string, unknown>) => ({ id: (args['where'] as Record<string, unknown>)['id'], ...(args['create'] as Record<string, unknown>) }),
        findUnique: async (args: Record<string, unknown>) => ({ id: (args['where'] as Record<string, unknown>)['id'], name: 'Selected' }),
      },
      auditHead: {
        createMany: async () => ({ count: 1 }),
        update: async () => ({ lastSeq: 1n, lastHash: 'h' }),
      },
      auditLog: {
        create: async () => ({}),
      },
      $queryRaw: async () => [{ lastSeq: 0n, lastHash: GENESIS_HASH }],
    };

    const mockPrisma = {
      $extends: (ext: unknown) => {
        capturedExtension = ext as typeof capturedExtension;
        return ext;
      },
      $transaction: async (fn: (tx: unknown) => Promise<unknown>) => fn(mockTx),
      $queryRaw: async () => [{ lastSeq: 0n, lastHash: GENESIS_HASH }],
      auditHead: {
        createMany: async () => ({ count: 1 }),
      },
    };

    let checkpointSinkCalled = false;
    createAuditClient(mockPrisma, {
      models: ['Student'],
      keys: { secret: masterKey },
      onMissingContext: 'system',
      checkpoint: {
        every: 1,
        sink: () => {
          checkpointSinkCalled = true;
        },
      },
    });

    expect(capturedExtension).toBeDefined();
    const queryExtensions = capturedExtension!.query.$allModels;

    // 1. Non-audited model passes straight through
    const nonAuditedQuery = vi.fn(async () => ({ passed: true }));
    const nonAuditedResult = await queryExtensions.create({
      model: 'UnAuditedModel',
      args: { data: {} },
      query: nonAuditedQuery,
    });
    expect(nonAuditedResult).toEqual({ passed: true });
    expect(nonAuditedQuery).toHaveBeenCalledTimes(1);

    // 2. Audited create
    const createResult = await runWithAuditContext({ actorId: 'u1', actorRole: 'ADMIN' }, () =>
      queryExtensions.create({
        model: 'Student',
        args: { data: { name: 'Alice' } },
        query: vi.fn(),
      }),
    );
    expect(createResult).toEqual({ id: 's-1', name: 'Alice' });
    expect(checkpointSinkCalled).toBe(true);

    // 3. Audited create with custom selection (select/include)
    const createSelectResult = await runWithAuditContext({ actorId: 'u1' }, () =>
      queryExtensions.create({
        model: 'Student',
        args: { data: { name: 'Alice' }, select: { id: true } },
        query: vi.fn(),
      }),
    );
    expect(createSelectResult).toEqual({ id: 's-1', name: 'Selected' });

    // 4. Audited update
    const updateResult = await runWithAuditContext({ actorId: 'u1' }, () =>
      queryExtensions.update({
        model: 'Student',
        args: { where: { id: 's-1' }, data: { name: 'Alicia' } },
        query: vi.fn(),
      }),
    );
    expect(updateResult).toEqual({ id: 's-1', name: 'Alicia' });

    // 5. Audited delete
    const deleteResult = await runWithAuditContext({ actorId: 'u1' }, () =>
      queryExtensions.delete({
        model: 'Student',
        args: { where: { id: 's-1' } },
        query: vi.fn(),
      }),
    );
    expect(deleteResult).toEqual({ id: 's-1', name: 'Selected' });

    // 6. Audited upsert
    const upsertResult = await runWithAuditContext({ actorId: 'u1' }, () =>
      queryExtensions.upsert({
        model: 'Student',
        args: { where: { id: 's-1' }, create: { name: 'Alice' }, update: { name: 'Alicia' } },
        query: vi.fn(),
      }),
    );
    expect(upsertResult).toEqual({ id: 's-1', name: 'Alice' });
  });
});
