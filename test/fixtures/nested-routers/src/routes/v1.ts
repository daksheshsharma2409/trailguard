import { Router } from 'express';
import postsRouter from './posts.js';

const router = Router();

// Level 2 mount
router.use('/posts', postsRouter);

export default router;
