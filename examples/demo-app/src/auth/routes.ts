/**
 * Authentication routes for demo app.
 */

import { Router } from 'express';
import bcrypt from 'bcryptjs';
import { auditClient, prisma } from '../db.js';
import { signToken } from './jwt.js';

export const authRouter = Router();

authRouter.post('/register', async (req, res) => {
  const { email, password, role, phone } = req.body as {
    email?: string;
    password?: string;
    role?: string;
    phone?: string;
  };

  if (!email || !password) {
    res.status(400).json({ error: 'Email and password are required' });
    return;
  }

  const existing = await prisma.user.findUnique({ where: { email } });
  if (existing) {
    res.status(409).json({ error: 'User already exists' });
    return;
  }

  const passwordHash = await bcrypt.hash(password, 10);

  const user = await auditClient.user.create({
    data: {
      email,
      passwordHash,
      role: role ?? 'STUDENT',
      phone: phone ?? null,
    },
  });

  const token = signToken({ id: user.id, email: user.email, role: user.role });
  res.status(201).json({
    token,
    user: { id: user.id, email: user.email, role: user.role, phone: user.phone },
  });
});

authRouter.post('/login', async (req, res) => {
  const { email, password } = req.body as { email?: string; password?: string };

  if (!email || !password) {
    res.status(400).json({ error: 'Email and password are required' });
    return;
  }

  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) {
    res.status(401).json({ error: 'Invalid email or password' });
    return;
  }

  const valid = await bcrypt.compare(password, user.passwordHash);
  if (!valid) {
    res.status(401).json({ error: 'Invalid email or password' });
    return;
  }

  const token = signToken({ id: user.id, email: user.email, role: user.role });
  res.json({
    token,
    user: { id: user.id, email: user.email, role: user.role },
  });
});
