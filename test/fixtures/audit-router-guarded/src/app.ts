import express from 'express';

export const authenticate = (req: any, res: any, next: any) => next();
export const requireRole = (role: string) => (req: any, res: any, next: any) => next();

export const auditRouter = (options?: any) => {
  const router = express.Router();
  router.get('/logs', (req, res) => res.json({ logs: [] }));
  return router;
};

const app = express();
app.use(express.json());

// Guarded audit router mount: both auth and role in effective chain
app.use('/audit', authenticate, requireRole('ADMIN'), auditRouter());

export default app;
