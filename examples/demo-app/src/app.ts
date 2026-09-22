/**
 * Express application definition for Trailguard demo app.
 */

import express from 'express';
import { auditContext, auditRouter } from '../../../src/index.js';
import { prisma } from './db.js';
import { authenticate, requireRole } from './auth/middleware.js';
import { authRouter } from './auth/routes.js';
import { studentsRouter } from './routes/students.js';
import { usersRouter } from './routes/users.js';

export const app = express();

// 1. JSON parsing middleware
app.use(express.json());

// 2. Audit context middleware — must run before routes so ALS store wraps requests
app.use(auditContext());

// 3. Public authentication routes (suppressed in baseline for RBAC001)
app.use('/auth', authRouter);

// 4. Business routes
app.use('/api/students', studentsRouter);
app.use('/api/users', usersRouter);

// 5. Audit endpoints guarded by authentication and role check (AUD002 compliant)
app.use(
  '/audit',
  auditRouter({
    guard: [authenticate, requireRole('ADMIN', 'AUDITOR')],
    prisma,
    keys: {
      secret:
        process.env.TRAILGUARD_KEY || 'demo-trailguard-master-key-32chars!!',
    },
  }),
);
