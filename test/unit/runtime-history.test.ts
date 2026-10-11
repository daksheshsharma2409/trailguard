/**
 * Unit tests for getHistory query utility (runtime/history.ts).
 */

import { describe, it, expect } from 'vitest';
import { getHistory, type HistoryPrismaClient } from '../../src/runtime/history.js';

describe('Unit: getHistory (runtime/history.ts)', () => {
  it('queries history for a model and recordId with defaults', async () => {
    let capturedArgs: unknown = null;
    const mockPrisma: HistoryPrismaClient = {
      auditLog: {
        findMany: async (args) => {
          capturedArgs = args;
          return [
            {
              seq: 1n,
              model: 'Student',
              recordId: 'rec-1',
              action: 'CREATE',
              actorId: 'admin-1',
              actorRole: 'ADMIN',
            },
          ];
        },
      },
    };

    const history = await getHistory(mockPrisma, 'Student', 'rec-1');

    expect(history).toHaveLength(1);
    expect(history[0]?.recordId).toBe('rec-1');
    expect(capturedArgs).toEqual({
      where: {
        model: 'Student',
        recordId: 'rec-1',
      },
      orderBy: {
        seq: 'asc',
      },
    });
  });

  it('passes descending order and pagination options', async () => {
    let capturedArgs: unknown = null;
    const mockPrisma: HistoryPrismaClient = {
      auditLog: {
        findMany: async (args) => {
          capturedArgs = args;
          return [];
        },
      },
    };

    await getHistory(mockPrisma, 'Student', 'rec-2', {
      order: 'desc',
      limit: 10,
      skip: 5,
    });

    expect(capturedArgs).toEqual({
      where: {
        model: 'Student',
        recordId: 'rec-2',
      },
      orderBy: {
        seq: 'desc',
      },
      take: 10,
      skip: 5,
    });
  });

  describe('getRestorePreview', () => {
    it('returns null when record has no audit entries', async () => {
      const mockPrisma: HistoryPrismaClient = {
        auditLog: {
          findMany: async () => [],
        },
      };

      const preview = await (await import('../../src/runtime/history.js')).getRestorePreview(
        mockPrisma,
        'Student',
        'nonexistent-id',
      );

      expect(preview).toBeNull();
    });

    it('returns before state when the last recorded action was DELETE', async () => {
      const mockPrisma: HistoryPrismaClient = {
        auditLog: {
          findMany: async () => [
            {
              seq: 42n,
              model: 'Student',
              recordId: 'rec-1',
              action: 'DELETE',
              before: { id: 'rec-1', name: 'Alice', token: '[REDACTED:16b]' },
              after: null,
            },
          ],
        },
      };

      const preview = await (await import('../../src/runtime/history.js')).getRestorePreview(
        mockPrisma,
        'Student',
        'rec-1',
      );

      expect(preview).not.toBeNull();
      expect(preview?.model).toBe('Student');
      expect(preview?.recordId).toBe('rec-1');
      expect(preview?.action).toBe('DELETE');
      expect(preview?.seq).toBe('42');
      expect(preview?.state).toEqual({ id: 'rec-1', name: 'Alice', token: '[REDACTED:16b]' });
    });

    it('returns after state when the last recorded action was UPDATE or CREATE', async () => {
      const mockPrisma: HistoryPrismaClient = {
        auditLog: {
          findMany: async () => [
            {
              seq: 15n,
              model: 'Student',
              recordId: 'rec-2',
              action: 'UPDATE',
              before: { id: 'rec-2', name: 'Bob' },
              after: JSON.stringify({ id: 'rec-2', name: 'Robert', passwordHash: '[REDACTED:32b]' }),
            },
          ],
        },
      };

      const preview = await (await import('../../src/runtime/history.js')).getRestorePreview(
        mockPrisma,
        'Student',
        'rec-2',
      );

      expect(preview).not.toBeNull();
      expect(preview?.action).toBe('UPDATE');
      expect(preview?.seq).toBe('15');
      expect(preview?.state).toEqual({
        id: 'rec-2',
        name: 'Robert',
        passwordHash: '[REDACTED:32b]',
      });
    });
  });
});

