import { Router } from 'express';

const router = Router();

const authenticate = (req: any, res: any, next: any) => next();
const getItem = (req: any, res: any) => res.json({ id: req.params.id });
const deleteItem = (req: any, res: any) => res.json({ ok: true });

// Route placed BEFORE router.use(authenticate)
router.get('/:id', getItem);

// Middleware placed AFTER route 1, but BEFORE route 2
router.use(authenticate);

// Route placed AFTER router.use(authenticate)
router.delete('/:id', deleteItem);

export default router;
