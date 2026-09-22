/**
 * User administration routes for demo app.
 */

import { Router } from 'express';
import { auditClient, prisma } from '../db.js';
import { authenticate, requireRole } from '../auth/middleware.js';

export const usersRouter = Router();

// List all users (ADMIN only)
usersRouter.get('/', authenticate, requireRole('ADMIN'), async (_req, res) => {
  const users = await prisma.user.findMany({
    select: {
      id: true,
      email: true,
      role: true,
      phone: true,
      createdAt: true,
      updatedAt: true,
    },
  });
  res.json({ users });
});

// Update user role (ADMIN only)
usersRouter.patch('/:id/role', authenticate, requireRole('ADMIN'), async (req, res) => {
  const id = req.params.id ?? '';
  const { role } = req.body as { role?: string };

  if (!role) {
    res.status(400).json({ error: 'Role is required' });
    return;
  }

  const user = await auditClient.user.update({
    where: { id },
    data: { role },
    select: {
      id: true,
      email: true,
      role: true,
      phone: true,
      updatedAt: true,
    },
  });

  res.json({ user });
});
