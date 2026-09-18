import express from 'express';

// Stubs for middleware and clients
export const authenticate = (req: any, res: any, next: any) => next();
export const requireRole = (role: string) => (req: any, res: any, next: any) => next();

export const prisma: any = {
  student: {
    update: async (args: any) => args,
  },
  course: {
    update: async (args: any) => args,
  },
};

export const auditClient: any = {
  student: {
    update: async (args: any) => args,
  },
};

const app = express();
app.use(express.json());

// 1. Audited call using audited client (allowed, not flagged)
app.post('/api/students/audited', authenticate, requireRole('ADMIN'), async (req, res) => {
  await auditClient.student.update({
    where: { id: req.body.id },
    data: { name: req.body.name },
  });
  res.json({ ok: true });
});

// 2. Non-audited model write (Course is not in audit.models, ignored)
app.post('/api/courses', authenticate, requireRole('ADMIN'), async (req, res) => {
  await prisma.course.update({
    where: { id: req.body.id },
    data: { title: req.body.title },
  });
  res.json({ ok: true });
});

// 3. Raw Prisma write on audited model (bypasses auditClient -> flags AUD001)
app.patch('/api/students/:id', authenticate, requireRole('ADMIN'), async (req, res) => {
  await prisma.student.update({
    where: { id: req.params.id },
    data: { name: req.body.name },
  });
  res.json({ ok: true });
});

export default app;
