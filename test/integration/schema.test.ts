import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { PrismaClient } from './generated/index.js';

describe('Integration: Prisma schema', () => {
  let prisma: PrismaClient;

  beforeAll(async () => {
    prisma = new PrismaClient();
    await prisma.$connect();
  });

  afterAll(async () => {
    await prisma.$disconnect();
  });

  it('inserts and retrieves a Student record', async () => {
    const student = await prisma.student.create({
      data: {
        name: 'Alice Smith',
        email: 'alice@example.com',
        phone: '555-0199',
        marks: 98,
        teacherId: 'teacher-1',
      },
    });

    expect(student.id).toBeDefined();
    expect(student.name).toBe('Alice Smith');
    expect(student.email).toBe('alice@example.com');
    expect(student.marks).toBe(98);

    const found = await prisma.student.findUnique({
      where: { id: student.id },
    });

    expect(found).not.toBeNull();
    expect(found?.name).toBe('Alice Smith');
  });

  it('verifies AuditLog and AuditHead tables exist and can be queried', async () => {
    const logCount = await prisma.auditLog.count();
    const headCount = await prisma.auditHead.count();

    expect(logCount).toBe(0);
    expect(headCount).toBe(0);
  });
});
