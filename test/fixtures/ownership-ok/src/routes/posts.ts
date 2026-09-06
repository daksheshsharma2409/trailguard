import { Router } from 'express';

const router = Router();
const authenticate = (req: any, res: any, next: any) => next();

router.use(authenticate);

// Mutating route with verified ownership check in where clause
router.delete('/:id', async (req: any, res: any) => {
  const post = await (globalThis as any).prisma.post.deleteMany({
    where: {
      id: req.params.id,
      authorId: req.user.id,
    },
  });
  res.json(post);
});

export default router;
