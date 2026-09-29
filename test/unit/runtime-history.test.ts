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
});
