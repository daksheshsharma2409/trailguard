import { Router } from 'express';

const router = Router();

// Missing authentication on mutating route!
router.delete('/:id', (req: any, res: any) => {
  res.json({ deleted: req.params.id });
});

export default router;
