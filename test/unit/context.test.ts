import { describe, it, expect } from 'vitest';
import express, { type Request, type Response, type NextFunction } from 'express';
import request from 'supertest';
import {
  auditContext,
  getAuditContext,
  runWithAuditContext,
} from '../../src/runtime/context.js';
import { AuditContextMissingError } from '../../src/core/errors.js';

describe('runtime/context', () => {
  describe('getAuditContext outside ALS', () => {
    it('throws AuditContextMissingError when onMissingContext is throw (default)', () => {
      expect(() => getAuditContext()).toThrow(AuditContextMissingError);
      expect(() => getAuditContext('throw')).toThrow(AuditContextMissingError);
    });

    it('returns system actor when onMissingContext is system', () => {
      const ctx = getAuditContext('system');
      expect(ctx.actorId).toBe('system');
      expect(ctx.actorRole).toBe('SYSTEM');
      expect(ctx.requestId).toBeDefined();
    });
  });

  describe('runWithAuditContext', () => {
    it('executes function within provided audit context', () => {
      const result = runWithAuditContext(
        { actorId: 'worker-1', actorRole: 'SERVICE' },
        () => {
          const ctx = getAuditContext();
          expect(ctx.actorId).toBe('worker-1');
          expect(ctx.actorRole).toBe('SERVICE');
          return 42;
        },
      );
      expect(result).toBe(42);
    });

    it('maintains context across async boundaries', async () => {
      await runWithAuditContext(
        { actorId: 'async-actor', actorRole: 'WORKER' },
        async () => {
          await new Promise((resolve) => setTimeout(resolve, 10));
          const ctx = getAuditContext();
          expect(ctx.actorId).toBe('async-actor');
          expect(ctx.actorRole).toBe('WORKER');
        },
      );
    });
  });

  describe('Express auditContext middleware', () => {
    it('resolves actor lazily when authenticate middleware runs after auditContext', async () => {
      const app = express();

      // 1. auditContext placed FIRST
      app.use(auditContext());

      // 2. authenticate middleware runs AFTER
      app.use((req: Request, _res: Response, next: NextFunction) => {
        (req as unknown as { user?: { id: string; role: string } }).user = {
          id: 'user_99',
          role: 'MANAGER',
        };
        next();
      });

      // 3. route handler inspects context at write time
      app.get('/write', (_req: Request, res: Response) => {
        const ctx = getAuditContext();
        res.json(ctx);
      });

      const response = await request(app).get('/write');
      expect(response.status).toBe(200);
      expect(response.body.actorId).toBe('user_99');
      expect(response.body.actorRole).toBe('MANAGER');
      expect(response.body.requestId).toBeDefined();
    });

    it('isolates context across concurrent requests', async () => {
      const app = express();
      app.use(auditContext());

      app.get('/user/:id', (req: Request, res: Response) => {
        const id = req.params['id'] ?? 'unknown';
        (req as unknown as { user?: { id: string; role: string } }).user = {
          id: 'actor_' + id,
          role: 'USER',
        };

        const delayMs = id === '1' ? 30 : 10;
        setTimeout(() => {
          const ctx = getAuditContext();
          res.json({ actorId: ctx.actorId, requestedId: id });
        }, delayMs);
      });

      const [res1, res2] = await Promise.all([
        request(app).get('/user/1'),
        request(app).get('/user/2'),
      ]);

      expect(res1.status).toBe(200);
      expect(res1.body.actorId).toBe('actor_1');
      expect(res1.body.requestedId).toBe('1');

      expect(res2.status).toBe(200);
      expect(res2.body.actorId).toBe('actor_2');
      expect(res2.body.requestedId).toBe('2');
    });

    it('ignores client-supplied x-request-id by default', async () => {
      const app = express();
      app.use(auditContext());

      app.get('/check-req-id', (_req: Request, res: Response) => {
        const ctx = getAuditContext();
        res.json({ requestId: ctx.requestId });
      });

      const response = await request(app)
        .get('/check-req-id')
        .set('x-request-id', 'client-forged-request-id');

      expect(response.status).toBe(200);
      expect(response.body.requestId).not.toBe('client-forged-request-id');
    });

    it('honors client x-request-id when trustRequestIdHeader is true', async () => {
      const app = express();
      app.use(auditContext({ trustRequestIdHeader: true }));

      app.get('/check-req-id', (_req: Request, res: Response) => {
        const ctx = getAuditContext();
        res.json({ requestId: ctx.requestId });
      });

      const response = await request(app)
        .get('/check-req-id')
        .set('x-request-id', 'trusted-custom-req-123');

      expect(response.status).toBe(200);
      expect(response.body.requestId).toBe('trusted-custom-req-123');
    });

    it('supports custom getActor extractor', async () => {
      const app = express();
      app.use(
        auditContext({
          getActor: (req) => {
            const customSession = (req as unknown as { session?: { accountId?: string; accessLevel?: string } }).session;
            return {
              id: customSession?.accountId,
              role: customSession?.accessLevel,
            };
          },
        }),
      );

      app.use((req: Request, _res: Response, next: NextFunction) => {
        (req as unknown as { session?: { accountId: string; accessLevel: string } }).session = {
          accountId: 'acc_55',
          accessLevel: 'ADMINISTRATOR',
        };
        next();
      });

      app.get('/custom', (_req: Request, res: Response) => {
        const ctx = getAuditContext();
        res.json(ctx);
      });

      const response = await request(app).get('/custom');
      expect(response.status).toBe(200);
      expect(response.body.actorId).toBe('acc_55');
      expect(response.body.actorRole).toBe('ADMINISTRATOR');
    });
  });
});
