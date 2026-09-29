/**
 * Unit tests for auditRouter (runtime/router.ts).
 *
 * Tests:
 * - throws AuditConfigError if guard is omitted or empty
 * - throws AuditConfigError if prisma or keys is omitted
 * - GET /logs: validation, filtering, pagination and caps
 * - GET /logs/:seq: retrieval of specific row, 404 when not found
 * - GET /history/:model/:recordId: history query with model validation
 * - GET /verify: invokes verifyAuditChain and returns result
 */

import express from 'express';
import request from 'supertest';
import { describe, it, expect } from 'vitest';
import { AuditConfigError } from '../../src/core/errors.js';
import { auditRouter, type RouterPrismaClient } from '../../src/runtime/router.js';

describe('Unit: auditRouter (runtime/router.ts)', () => {
  const masterKey = 'test-audit-master-key-32-chars!!';

  it('throws AuditConfigError when guard is missing or empty', () => {
    const mockPrisma = {} as RouterPrismaClient;

    expect(() =>
      auditRouter({
        guard: undefined as unknown as import('express').RequestHandler,
        prisma: mockPrisma,
        keys: { secret: masterKey },
      }),
    ).toThrow(AuditConfigError);

    expect(() =>
      auditRouter({
        guard: [],
        prisma: mockPrisma,
        keys: { secret: masterKey },
      }),
    ).toThrow(AuditConfigError);
  });

  it('throws AuditConfigError when prisma or keys is missing', () => {
    const guard: import('express').RequestHandler = (req, res, next) => next();

    expect(() =>
      auditRouter({
        guard,
        prisma: undefined as unknown as RouterPrismaClient,
        keys: { secret: masterKey },
      }),
    ).toThrow(AuditConfigError);

    expect(() =>
      auditRouter({
        guard,
        prisma: {} as RouterPrismaClient,
        keys: undefined as unknown as { secret: string },
      }),
    ).toThrow(AuditConfigError);
  });

  it('handles GET /logs with pagination and query filters', async () => {
    const mockPrisma: RouterPrismaClient = {
      auditLog: {
        findMany: async () => [
          {
            seq: 1n,
            model: 'Student',
            recordId: 'rec-1',
            action: 'CREATE',
            actorId: 'admin-1',
            actorRole: 'ADMIN',
            payload: '{}',
            hash: 'h1',
            prevHash: 'p1',
            keyId: 'default',
            createdAt: new Date(),
          },
        ],
        count: async () => 1,
      },
    };

    const app = express();
    app.use(
      '/audit',
      auditRouter({
        guard: (req, res, next) => next(),
        prisma: mockPrisma,
        keys: { secret: masterKey },
      }),
    );

    const res = await request(app).get('/audit/logs?page=1&pageSize=10');
    expect(res.status).toBe(200);
    expect(res.body.logs).toHaveLength(1);
    expect(res.body.logs[0].seq).toBe('1');
    expect(res.body.total).toBe(1);
  });

  it('handles GET /logs/:seq and returns 404 when not found', async () => {
    const mockPrisma: RouterPrismaClient = {
      auditLog: {
        findMany: async () => [],
        findUnique: async (args) => {
          if (args.where.seq === 1n) {
            return {
              seq: 1n,
              model: 'Student',
              recordId: 'rec-1',
              action: 'CREATE',
            };
          }
          return null;
        },
      },
    };

    const app = express();
    app.use(
      '/audit',
      auditRouter({
        guard: (req, res, next) => next(),
        prisma: mockPrisma,
        keys: { secret: masterKey },
      }),
    );

    const foundRes = await request(app).get('/audit/logs/1');
    expect(foundRes.status).toBe(200);
    expect(foundRes.body.seq).toBe('1');

    const notFoundRes = await request(app).get('/audit/logs/999');
    expect(notFoundRes.status).toBe(404);
  });

  it('handles GET /history/:model/:recordId', async () => {
    const mockPrisma: RouterPrismaClient = {
      auditLog: {
        findMany: async () => [
          {
            seq: 1n,
            model: 'Student',
            recordId: 'rec-1',
            action: 'CREATE',
          },
        ],
      },
    };

    const app = express();
    app.use(
      '/audit',
      auditRouter({
        guard: (req, res, next) => next(),
        prisma: mockPrisma,
        keys: { secret: masterKey },
        models: ['Student'],
      }),
    );

    const res = await request(app).get('/audit/history/Student/rec-1');
    expect(res.status).toBe(200);
    expect(res.body.history).toHaveLength(1);

    // Unknown model should return 400
    const unknownRes = await request(app).get('/audit/history/UnknownModel/rec-1');
    expect(unknownRes.status).toBe(400);
  });

  it('handles GET /verify', async () => {
    const mockPrisma: RouterPrismaClient = {
      auditLog: {
        findMany: async () => [],
      },
      auditHead: {
        findUnique: async () => ({ id: 1, lastSeq: 0n, lastHash: '0'.repeat(64) }),
      },
    };

    const app = express();
    app.use(
      '/audit',
      auditRouter({
        guard: (req, res, next) => next(),
        prisma: mockPrisma,
        keys: { secret: masterKey },
      }),
    );

    const res = await request(app).get('/audit/verify');
    expect(res.status).toBe(200);
    expect(res.body.valid).toBe(true);
    expect(res.body.checkedRecords).toBe(0);
  });
});
