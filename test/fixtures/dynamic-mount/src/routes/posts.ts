import { Router } from 'express';

const router = Router();
const getPost = (req: any, res: any) => res.json({ id: req.params.id });

router.get('/:id', getPost);

export default router;
