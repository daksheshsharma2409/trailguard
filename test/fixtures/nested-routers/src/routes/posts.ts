import { Router } from 'express';

const router = Router();

const getPost = (req: any, res: any) => res.json({ id: req.params.id });
const createPost = (req: any, res: any) => res.json({ ok: true });

// Level 3 routes
router.get('/:id', getPost);
router.post('/', createPost);

export default router;
