import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import express, { type Request, type Response, type NextFunction } from 'express';
import request from 'supertest';
import { PrismaClient } from './generated/index.js';
import { auditRouter } from '../../src/runtime/router.js';
import { createAuditClient } from '../../src/runtime/client.js';
import { resetHeadCache } from '../../src/runtime/append.js';
import { runWithAuditContext } from '../../src/runtime/context.js';
import { AuditConfigError } from '../../src/core/errors.js';

describe('Integration: auditRouter', () => {
  let prisma: PrismaClient;
  const masterKey = 'router-test-master-hmac-key-32!';

  beforeAll(async () => {
    prisma = new PrismaClient();
    await prisma.$connect();
  });

  afterAll(async () => {
    await prisma.$disconnect();
  });

  beforeEach(async () => {
    await prisma.$executeRawUnsafe('DELETE FROM trailguard_audit_log');
    await prisma.$executeRawUnsafe('DELETE FROM trailguard_audit_head');
    await prisma.$executeRawUnsafe('DELETE FROM Student');
    resetHeadCache();
  });

  it('throws AuditConfigError when constructing without guard or with empty guard array', () => {
    // Missing guard
    expect(() =>
      auditRouter({
        prisma,
        keys: { secret: masterKey },
      } as unknown as Parameters<typeof auditRouter>[0]),
    ).toThrow(AuditConfigError);

    // Empty guard array
    expect(() =>
      auditRouter({
        guard: [],
        prisma,
        keys: { secret: masterKey },
      }),
    ).toThrow(AuditConfigError);
  });

  function createTestApp() {
    const app = express();
    app.use(express.json());

    const authenticate = (req: Request, res: Response, next: NextFunction) => {
      const auth = req.headers['authorization'];
      if (!auth) {
        res.status(401).json({ error: 'Missing authorization header' });
        return;
      }
      if (auth === 'Bearer teacher-token') {
        (req as unknown as { user: { id: string; role: string } }).user = {
          id: 'teacher-1',
          role: 'TEACHER',
        };
        next();
        return;
      }
      if (auth === 'Bearer admin-token') {
        (req as unknown as { user: { id: string; role: string } }).user = {
          id: 'admin-1',
          role: 'ADMIN',
        };
        next();
        return;
      }
      res.status(401).json({ error: 'Invalid token' });
    };

    const requireAdmin = (req: Request, res: Response, next: NextFunction) => {
      const user = (req as unknown as { user?: { role: string } }).user;
      if (!user || user.role !== 'ADMIN') {
        res.status(403).json({ error: 'Forbidden: ADMIN role required' });
        return;
      }
      next();
    };

    app.use(
      '/audit',
      auditRouter({
        guard: [authenticate, requireAdmin],
        prisma,
        keys: { secret: masterKey },
        models: ['Student'],
      }),
    );

    return app;
  }

  it('rejects unauthenticated and non-admin requests with the guard responses', async () => {
    const app = createTestApp();

    // 1. Unauthenticated -> 401
    const unauthRes = await request(app).get('/audit/logs');
    expect(unauthRes.status).toBe(401);
    expect(unauthRes.body.error).toBe('Missing authorization header');

    // 2. Non-admin (TEACHER) -> 403
    const forbiddenRes = await request(app)
      .get('/audit/logs')
      .set('Authorization', 'Bearer teacher-token');
    expect(forbiddenRes.status).toBe(403);
    expect(forbiddenRes.body.error).toBe('Forbidden: ADMIN role required');
  });

  it('allows ADMIN to query logs, single log, history, and verification', async () => {
    const auditClient = createAuditClient(prisma, {
      models: ['Student'],
      keys: { secret: masterKey },
      redactFields: ['phone'],
    });

    // Seed an audited student
    const student = await runWithAuditContext(
      { actorId: 'admin-1', actorRole: 'ADMIN', requestId: 'req-init' },
      () =>
        auditClient.student.create({
          data: {
            id: 'std-router-1',
            name: 'Alice Wonder',
            email: 'alice@router.test',
            phone: '555-987-6543',
            marks: 92,
          },
        }),
    );

    // Update student to create a second log entry
    await runWithAuditContext(
      { actorId: 'admin-1', actorRole: 'ADMIN', requestId: 'req-upd' },
      () =>
        auditClient.student.update({
          where: { id: student.id },
          data: { marks: 98 },
        }),
    );

    const app = createTestApp();

    // 1. GET /audit/logs
    const logsRes = await request(app)
      .get('/audit/logs')
      .set('Authorization', 'Bearer admin-token');

    expect(logsRes.status).toBe(200);
    expect(logsRes.body.total).toBe(2);
    expect(logsRes.body.logs).toHaveLength(2);
    expect(logsRes.body.logs[0].seq).toBe('2');
    expect(logsRes.body.logs[1].seq).toBe('1');

    // 2. GET /audit/logs/:seq
    const seqRes = await request(app)
      .get('/audit/logs/1')
      .set('Authorization', 'Bearer admin-token');

    expect(seqRes.status).toBe(200);
    expect(seqRes.body.seq).toBe('1');
    expect(seqRes.body.model).toBe('Student');
    expect(seqRes.body.recordId).toBe('std-router-1');
    expect(seqRes.body.action).toBe('CREATE');

    // 3. GET /audit/history/:model/:recordId
    const historyRes = await request(app)
      .get('/audit/history/Student/std-router-1')
      .set('Authorization', 'Bearer admin-token');

    expect(historyRes.status).toBe(200);
    expect(historyRes.body.model).toBe('Student');
    expect(historyRes.body.recordId).toBe('std-router-1');
    expect(historyRes.body.history).toHaveLength(2);
    expect(historyRes.body.history[0].seq).toBe('1');
    expect(historyRes.body.history[1].seq).toBe('2');

    // 4. GET /audit/verify
    const verifyRes = await request(app)
      .get('/audit/verify')
      .set('Authorization', 'Bearer admin-token');

    expect(verifyRes.status).toBe(200);
    expect(verifyRes.body.valid).toBe(true);
    expect(verifyRes.body.checkedRecords).toBe(2);
  });

  it('caps pageSize at 200 when client requests pageSize=100000', async () => {
    const app = createTestApp();

    const res = await request(app)
      .get('/audit/logs?pageSize=100000')
      .set('Authorization', 'Bearer admin-token');

    expect(res.status).toBe(200);
    expect(res.body.pageSize).toBe(200);
  });

  it('returns 400 when querying for an unknown model', async () => {
    const app = createTestApp();

    // In /logs?model=Unknown
    const logsRes = await request(app)
      .get('/audit/logs?model=UnknownModel')
      .set('Authorization', 'Bearer admin-token');

    expect(logsRes.status).toBe(400);
    expect(logsRes.body.error).toContain("Unknown model 'UnknownModel'");

    // In /history/Unknown/:id
    const historyRes = await request(app)
      .get('/audit/history/UnknownModel/123')
      .set('Authorization', 'Bearer admin-token');

    expect(historyRes.status).toBe(400);
    expect(historyRes.body.error).toContain("Unknown model 'UnknownModel'");
  });

  it('never leaks raw redacted values in any responses', async () => {
    const rawSecretPhone = '555-TOP-SECRET-PHONE';

    const auditClient = createAuditClient(prisma, {
      models: ['Student'],
      keys: { secret: masterKey },
      redactFields: ['phone'],
    });

    await runWithAuditContext(
      { actorId: 'admin-1', actorRole: 'ADMIN' },
      () =>
        auditClient.student.create({
          data: {
            id: 'std-secret-1',
            name: 'Secret Student',
            email: 'secret@example.com',
            phone: rawSecretPhone,
          },
        }),
    );

    const app = createTestApp();

    // 1. Check /logs
    const logsRes = await request(app)
      .get('/audit/logs')
      .set('Authorization', 'Bearer admin-token');

    expect(logsRes.status).toBe(200);
    expect(logsRes.text).not.toContain(rawSecretPhone);
    expect(logsRes.text).toContain('[REDACTED:');

    // 2. Check /logs/1
    const singleRes = await request(app)
      .get('/audit/logs/1')
      .set('Authorization', 'Bearer admin-token');

    expect(singleRes.status).toBe(200);
    expect(singleRes.text).not.toContain(rawSecretPhone);
    expect(singleRes.text).toContain('[REDACTED:');

    // 3. Check /history/Student/std-secret-1
    const histRes = await request(app)
      .get('/audit/history/Student/std-secret-1')
      .set('Authorization', 'Bearer admin-token');

    expect(histRes.status).toBe(200);
    expect(histRes.text).not.toContain(rawSecretPhone);
    expect(histRes.text).toContain('[REDACTED:');
  });

  it('GET /logs/:seq returns 404 when sequence number does not exist', async () => {
    const app = createTestApp();

    const res = await request(app)
      .get('/audit/logs/99999')
      .set('Authorization', 'Bearer admin-token');

    expect(res.status).toBe(404);
    expect(res.body.error).toContain('99999');
  });

  it('GET /verify returns HTTP 200 with valid:false when chain is broken', async () => {
    const auditClient = createAuditClient(prisma, {
      models: ['Student'],
      keys: { secret: masterKey },
    });

    await runWithAuditContext(
      { actorId: 'admin-1', actorRole: 'ADMIN' },
      () =>
        auditClient.student.create({
          data: {
            id: 'std-tamper',
            name: 'To Tamper',
            email: 'tamper@example.com',
          },
        }),
    );

    // Tamper with payload in DB
    await prisma.$executeRawUnsafe(
      `UPDATE trailguard_audit_log SET payload = '{"tampered":true}' WHERE seq = 1`,
    );

    const app = createTestApp();

    const res = await request(app)
      .get('/audit/verify')
      .set('Authorization', 'Bearer admin-token');

    // context.md §7.10: "HTTP 200 either way; body.valid tells truth"
    expect(res.status).toBe(200);
    expect(res.body.valid).toBe(false);
    expect(res.body.problems).toBeDefined();
    expect(res.body.problems.length).toBeGreaterThan(0);
  });
});
