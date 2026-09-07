import { Router } from 'express';

const router = Router();
const authenticate = (req: any, res: any, next: any) => next();

router.use(authenticate);

// Authenticated, but missing role check and missing ownership check!
router.delete('/:id', (req: any, res: any) => {
  res.json({ deleted: req.params.id });
});

export default router;
