import express from 'express';

export const router = express.Router();

function authenticate(_req: express.Request, _res: express.Response, next: express.NextFunction) {
  next();
}

function requireRole(role: string) {
  return (_req: express.Request, _res: express.Response, next: express.NextFunction) => {
    if (role) {
      next();
    }
  };
}

router.get('/health', (_req, res) => {
  res.json({ ok: true });
});

router.post('/items', authenticate, requireRole('ADMIN'), (_req, res) => {
  res.json({ created: true });
});
