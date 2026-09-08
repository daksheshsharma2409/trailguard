import { Router } from 'express';

const router = Router();

// Mutating route missing authentication (RBAC001)
router.delete('/:id', (_req, res) => {
  res.json({ ok: true });
});

export default router;
