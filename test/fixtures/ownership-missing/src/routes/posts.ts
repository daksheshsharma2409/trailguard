import { Router } from 'express';

const router = Router();
const authenticate = (req: any, res: any, next: any) => next();

router.use(authenticate);

// Mutating route missing ownership check: only filters by id!
router.delete('/:id', async (req: any, res: any) => {
  const post = await (globalThis as any).prisma.post.delete({
    where: {
      id: req.params.id,
    },
  });
  res.json(post);
});

export default router;
