/**
 * Integration test for the demo application (T6.1).
 *
 * Verifies the complete demo app lifecycle:
 * 1. Setup & seeding initial data under runWithAuditContext
 * 2. Authenticating as teacher (JWT)
 * 3. Creating student via audited client
 * 4. Updating student marks
 * 5. Authenticating as auditor
 * 6. Querying GET /audit/history/Student/:id:
 *    - Asserts before/after/diff and actor
 *    - Asserts phone is redacted ([REDACTED:xxxx])
 * 7. Trailguard static scan on demo app reports 0 unsuppressed findings (exit 0)
 *
 * @see context.md §11, tasks.md T6.1
 */

import * as path from 'node:path';
import request from 'supertest';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { app } from '../../examples/demo-app/src/app.js';
import { prisma } from '../../examples/demo-app/src/db.js';
import { seed } from '../../examples/demo-app/prisma/seed.js';
import { scan } from '../../src/scan/index.js';
import { runVerifyCommand } from '../../src/cli/verify-command.js';

describe('Integration: Demo App (Fixed State)', () => {
  const demoConfigPath = path.resolve('examples/demo-app/trailguard.config.ts');
  const masterKey = 'demo-trailguard-master-key-32chars!!';

  beforeAll(async () => {
    process.env.DATABASE_URL =
      process.env.DATABASE_URL ||
      process.env.TEST_DATABASE_URL ||
      'postgresql://root:root@localhost:5432/trailguard_test?schema=public';
    process.env.TRAILGUARD_KEY = masterKey;
    process.env.JWT_SECRET = 'demo-jwt-secret-key-12345';
    await seed();
  });

  afterAll(async () => {
    await prisma.$disconnect();
  });

  it('runs the full teacher student CRUD and auditor history verification flow', async () => {
    // 1. Authenticate as Teacher
    const loginRes = await request(app)
      .post('/auth/login')
      .send({ email: 'teacher@college.edu', password: 'teacher123' });

    expect(loginRes.status).toBe(200);
    expect(loginRes.body.token).toBeDefined();
    const teacherToken = loginRes.body.token as string;
    const teacherId = String(loginRes.body.user.id);

    // 2. Create Student with phone and marks
    const createRes = await request(app)
      .post('/api/students')
      .set('Authorization', `Bearer ${teacherToken}`)
      .send({
        name: 'Eva Green',
        email: 'eva@college.edu',
        phone: '555-8888',
        marks: 82,
      });

    expect(createRes.status).toBe(201);
    expect(createRes.body.student).toBeDefined();
    const studentId = createRes.body.student.id as string;

    // 3. Update Student Marks
    const updateRes = await request(app)
      .patch(`/api/students/${studentId}`)
      .set('Authorization', `Bearer ${teacherToken}`)
      .send({
        marks: 96,
      });

    expect(updateRes.status).toBe(200);
    expect(updateRes.body.student.marks).toBe(96);

    // 4. Authenticate as Auditor
    const auditorLoginRes = await request(app)
      .post('/auth/login')
      .send({ email: 'auditor@college.edu', password: 'auditor123' });

    expect(auditorLoginRes.status).toBe(200);
    const auditorToken = auditorLoginRes.body.token as string;

    // 5. Query Audit History for Student
    const historyRes = await request(app)
      .get(`/audit/history/Student/${studentId}`)
      .set('Authorization', `Bearer ${auditorToken}`);

    expect(historyRes.status).toBe(200);
    expect(historyRes.body.history).toBeDefined();
    const history = historyRes.body.history as Array<{
      action: string;
      actorId: string;
      actorRole: string;
      before: Record<string, unknown> | null;
      after: Record<string, unknown> | null;
      diff: Record<string, unknown> | null;
    }>;

    // We expect at least 2 entries: CREATE and UPDATE
    expect(history.length).toBe(2);

    // Entry 1: CREATE
    const createEntry = history[0]!;
    expect(createEntry.action).toBe('CREATE');
    expect(createEntry.actorId).toBe(teacherId);
    expect(createEntry.actorRole).toBe('TEACHER');
    expect(createEntry.before).toBeNull();
    expect(createEntry.after).toBeDefined();
    expect(createEntry.after?.name).toBe('Eva Green');
    // phone must be redacted
    expect(createEntry.after?.phone).toMatch(/^\[REDACTED:[a-f0-9]{4}\]$/);

    // Entry 2: UPDATE
    const updateEntry = history[1]!;
    expect(updateEntry.action).toBe('UPDATE');
    expect(updateEntry.actorId).toBe(teacherId);
    expect(updateEntry.actorRole).toBe('TEACHER');
    expect(updateEntry.before?.marks).toBe(82);
    expect(updateEntry.after?.marks).toBe(96);
    expect(updateEntry.diff?.marks).toEqual({ old: 82, new: 96 });

    // 6. Audit log chain is valid
    const verifyOutcome = await runVerifyCommand({
      config: demoConfigPath,
      keyEnv: 'TRAILGUARD_KEY',
    });
    expect(verifyOutcome.exitCode).toBe(0);
    expect(verifyOutcome.message).toContain('valid');

    // 7. Trailguard scan on demo app reports 0 unsuppressed findings
    const scanOutput = await scan({
      config: demoConfigPath,
    });
    expect(scanOutput.exitCode).toBe(0);
    const unsuppressed = scanOutput.findings.filter((f) => !f.suppressed);
    expect(unsuppressed.length).toBe(0);
  });

  it('applies vulnerable.patch via demo:break, detects exactly 3 HIGH findings, and restores cleanly via demo:fix', async () => {
    const { execSync } = await import('node:child_process');

    try {
      // 1. Break the demo app
      execSync('npm run demo:break', { stdio: 'pipe' });

      // 2. Scan should detect exactly 3 HIGH findings
      const brokenScan = await scan({
        config: demoConfigPath,
        failOn: 'high',
      });

      expect(brokenScan.exitCode).toBe(1);
      const unsuppressed = brokenScan.findings.filter((f) => !f.suppressed);
      expect(unsuppressed.length).toBe(3);

      const ruleIds = unsuppressed.map((f) => f.ruleId).sort();
      expect(ruleIds).toEqual(['AUD001', 'RBAC001', 'RBAC002']);

      const aud001 = unsuppressed.find((f) => f.ruleId === 'AUD001');
      expect(aud001?.risk).toBe('high');
      expect(aud001?.route?.path).toBe('/api/students/bulk-reset');

      const rbac001 = unsuppressed.find((f) => f.ruleId === 'RBAC001');
      expect(rbac001?.risk).toBe('high');
      expect(rbac001?.route?.path).toBe('/api/users/:id/role');

      const rbac002 = unsuppressed.find((f) => f.ruleId === 'RBAC002');
      expect(rbac002?.risk).toBe('high');
      expect(rbac002?.route?.path).toBe('/api/students/:id');
    } finally {
      // 3. Fix the demo app
      execSync('npm run demo:fix', { stdio: 'pipe' });
    }

    // 4. Verify clean scan state restored
    const fixedScan = await scan({
      config: demoConfigPath,
    });
    expect(fixedScan.exitCode).toBe(0);
    const fixedUnsuppressed = fixedScan.findings.filter((f) => !f.suppressed);
    expect(fixedUnsuppressed.length).toBe(0);
  });
});
