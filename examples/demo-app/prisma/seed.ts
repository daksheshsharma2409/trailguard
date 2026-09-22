/**
 * Database seeding script for demo app.
 *
 * Runs under runWithAuditContext({ actorId: 'system:seed', actorRole: 'SYSTEM' })
 * and populates initial users and students via the audited client.
 *
 * @see context.md §11
 */

import bcrypt from 'bcryptjs';
import { runWithAuditContext } from '../../../src/index.js';
import { prisma, auditClient } from '../src/db.js';

export async function seed(): Promise<void> {
  console.log('Seeding demo database...');

  // Clean existing data for clean demo setup
  await prisma.$executeRawUnsafe('DELETE FROM trailguard_audit_log');
  await prisma.$executeRawUnsafe('DELETE FROM trailguard_audit_head');
  await prisma.$executeRawUnsafe('DELETE FROM Student');
  await prisma.$executeRawUnsafe('DELETE FROM User');

  await runWithAuditContext(
    { actorId: 'system:seed', actorRole: 'SYSTEM' },
    async () => {
      // 1. Seed Users
      const adminHash = await bcrypt.hash('admin123', 10);
      const teacherHash = await bcrypt.hash('teacher123', 10);
      const auditorHash = await bcrypt.hash('auditor123', 10);

      await auditClient.user.create({
        data: {
          email: 'admin@college.edu',
          passwordHash: adminHash,
          role: 'ADMIN',
          phone: '555-0100',
        },
      });

      const teacher = await auditClient.user.create({
        data: {
          email: 'teacher@college.edu',
          passwordHash: teacherHash,
          role: 'TEACHER',
          phone: '555-0101',
        },
      });

      await auditClient.user.create({
        data: {
          email: 'auditor@college.edu',
          passwordHash: auditorHash,
          role: 'AUDITOR',
          phone: '555-0102',
        },
      });

      // 2. Seed Students
      await auditClient.student.create({
        data: {
          name: 'Alice Smith',
          email: 'alice@college.edu',
          marks: 92,
          phone: '555-0201',
          teacherId: teacher.id,
        },
      });

      await auditClient.student.create({
        data: {
          name: 'Bob Jones',
          email: 'bob@college.edu',
          marks: 78,
          phone: '555-0202',
          teacherId: teacher.id,
        },
      });

      await auditClient.student.create({
        data: {
          name: 'Charlie Brown',
          email: 'charlie@college.edu',
          marks: 85,
          phone: '555-0203',
          teacherId: teacher.id,
        },
      });
    },
  );

  console.log('Demo database seeded successfully with HMAC-chained audit log entries.');
}

// Execute when invoked directly
if (import.meta.url === `file://${process.argv[1]}`) {
  seed()
    .catch((err) => {
      console.error('Seed error:', err);
      process.exit(1);
    })
    .finally(async () => {
      await prisma.$disconnect();
    });
}
