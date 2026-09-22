/**
 * Student management routes for demo app.
 */

import { Router } from 'express';
import { auditClient, prisma } from '../db.js';
import { authenticate, requireRole } from '../auth/middleware.js';

export const studentsRouter = Router();

// List all students
studentsRouter.get('/', authenticate, async (_req, res) => {
  const students = await prisma.student.findMany();
  res.json({ students });
});

// Create a new student (ADMIN or TEACHER)
studentsRouter.post('/', authenticate, requireRole('ADMIN', 'TEACHER'), async (req, res) => {
  const { name, email, phone, marks, teacherId } = req.body as {
    name?: string;
    email?: string;
    phone?: string;
    marks?: number;
    teacherId?: string;
  };

  if (!name || !email) {
    res.status(400).json({ error: 'Name and email are required' });
    return;
  }

  const student = await auditClient.student.create({
    data: {
      name,
      email,
      phone: phone ?? null,
      marks: marks ?? 0,
      teacherId: teacherId ?? null,
    },
  });

  res.status(201).json({ student });
});

// Get a student by ID
studentsRouter.get('/:id', authenticate, async (req, res) => {
  const id = req.params.id ?? '';
  const student = await prisma.student.findUnique({ where: { id } });

  if (!student) {
    res.status(404).json({ error: 'Student not found' });
    return;
  }

  res.json({ student });
});

// Update a student (ADMIN or TEACHER)
studentsRouter.patch('/:id', authenticate, requireRole('ADMIN', 'TEACHER'), async (req, res) => {
  const id = req.params.id ?? '';
  const { name, phone, marks, teacherId } = req.body as {
    name?: string;
    phone?: string;
    marks?: number;
    teacherId?: string;
  };

  const student = await auditClient.student.update({
    where: { id },
    data: {
      ...(name !== undefined && { name }),
      ...(phone !== undefined && { phone }),
      ...(marks !== undefined && { marks }),
      ...(teacherId !== undefined && { teacherId }),
    },
  });

  res.json({ student });
});

// Delete a student (ADMIN or TEACHER)
studentsRouter.delete('/:id', authenticate, requireRole('ADMIN', 'TEACHER'), async (req, res) => {
  const id = req.params.id ?? '';

  const student = await auditClient.student.delete({
    where: { id },
  });

  res.json({ message: 'Student deleted successfully', student });
});
