import express from 'express';

export const authenticate = (req: any, res: any, next: any) => next();
export const requireRole = (role: string) => (req: any, res: any, next: any) => next();

export const prisma: any = {
  $executeRaw: async (...args: any[]) => args,
  $executeRawUnsafe: async (...args: any[]) => args,
  $queryRaw: async (...args: any[]) => args,
  $queryRawUnsafe: async (...args: any[]) => args,
};

const app = express();
app.use(express.json());

// 1. Tagged template raw SQL with UPDATE
app.post('/api/raw-update', authenticate, requireRole('ADMIN'), async (req, res) => {
  await prisma.$executeRaw`UPDATE Student SET name = 'Updated' WHERE id = 1`;
  res.json({ ok: true });
});

// 2. Unsafe string raw SQL with DELETE
app.delete('/api/raw-delete', authenticate, requireRole('ADMIN'), async (req, res) => {
  await prisma.$executeRawUnsafe("DELETE FROM Student WHERE id = 1");
  res.json({ ok: true });
});

// 3. Read-only raw SQL (SELECT should not be flagged)
app.get('/api/raw-read', authenticate, requireRole('USER'), async (req, res) => {
  await prisma.$queryRaw`SELECT * FROM Student`;
  res.json({ ok: true });
});

export default app;
