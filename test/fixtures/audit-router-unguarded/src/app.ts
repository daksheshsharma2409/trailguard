import express from 'express';

export const auditRouter = (options?: any) => {
  const router = express.Router();
  router.get('/logs', (req, res) => res.json({ logs: [] }));
  return router;
};

const app = express();
app.use(express.json());

// Unguarded audit router mount: no auth, no role in effective chain
app.use('/audit', auditRouter());

export default app;
