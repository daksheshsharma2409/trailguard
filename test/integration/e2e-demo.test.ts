/**
 * End-to-end integration test executing the complete seven-step demo (T6.4).
 *
 * Steps:
 * 1. break: npm run demo:break -> trailguard scan fails with 3 HIGH (AUD001, RBAC001, RBAC002)
 * 2. fix: npm run demo:fix -> trailguard scan passes with 0 findings
 * 3. write: normal writes via audited client -> valid chain, redacted fields, diffs
 * 4. verify: trailguard verify exits 0 (chain valid)
 * 5. tamper: direct DB payload update -> trailguard verify exits 1 (HASH_MISMATCH)
 * 6. rehash: rehashChain with plain SHA-256 -> trailguard verify exits 1 (HASH_MISMATCH)
 * 7. truncate: truncateTail -> verify passes alone, but verify --checkpoints exits 1 (TRUNCATION_DETECTED)
 *
 * @see context.md §11, tasks.md T6.4, docs/DEMO.md
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { execSync } from 'node:child_process';
import request from 'supertest';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { app } from '../../examples/demo-app/src/app.js';
import { prisma } from '../../examples/demo-app/src/db.js';
import { seed } from '../../examples/demo-app/prisma/seed.js';
import { scan } from '../../src/scan/index.js';
import { runVerifyCommand } from '../../src/cli/verify-command.js';
import { rehashChain } from '../../scripts/attacker/rehash-chain.js';
import { truncateTail } from '../../scripts/attacker/truncate-tail.js';
import { seedDrift } from '../../scripts/attacker/seed-drift.js';
import { runDriftCommand } from '../../src/cli/drift-command.js';
import { createCheckpoint, fileSink } from '../../src/runtime/checkpoint.js';
import { resetHeadCache } from '../../src/runtime/append.js';

describe('Integration: End-to-End Demo (T6.4)', () => {
  const demoConfigPath = path.resolve('examples/demo-app/trailguard.config.ts');
  const masterKey = 'demo-trailguard-master-key-32chars!!';
  let tempCheckpointFile: string;

  beforeAll(async () => {
    process.env.DATABASE_URL =
      process.env.DATABASE_URL ||
      process.env.TEST_DATABASE_URL ||
      'mysql://root:root@localhost:3307/trailguard_test';
    process.env.TRAILGUARD_KEY = masterKey;
    process.env.JWT_SECRET = 'demo-jwt-secret-key-12345';

    tempCheckpointFile = path.join(
      os.tmpdir(),
      `trailguard-e2e-demo-cp-${String(Date.now())}.jsonl`,
    );

    await seed();
  });

  afterAll(async () => {
    if (fs.existsSync(tempCheckpointFile)) {
      try {
        fs.unlinkSync(tempCheckpointFile);
      } catch {
        // ignore cleanup error
      }
    }
    await prisma.$disconnect();
  });

  it('Step 1 & 2: breaks demo app to detect 3 HIGH findings, then restores cleanly', async () => {
    try {
      // Step 1: Break
      execSync('npm run demo:break', { stdio: 'pipe' });

      const brokenScan = await scan({
        config: demoConfigPath,
        failOn: 'high',
      });

      expect(brokenScan.exitCode).toBe(1);
      const unsuppressed = brokenScan.findings.filter((f) => !f.suppressed);
      expect(unsuppressed.length).toBe(3);

      const ruleIds = unsuppressed.map((f) => f.ruleId).sort();
      expect(ruleIds).toEqual(['AUD001', 'RBAC001', 'RBAC002']);
    } finally {
      // Step 2: Fix
      execSync('npm run demo:fix', { stdio: 'pipe' });
    }

    const fixedScan = await scan({
      config: demoConfigPath,
    });
    expect(fixedScan.exitCode).toBe(0);
    const fixedUnsuppressed = fixedScan.findings.filter((f) => !f.suppressed);
    expect(fixedUnsuppressed.length).toBe(0);
  });

  it('Step 3 & 4: executes audited writes and proves cryptographic verification passes', async () => {
    resetHeadCache();
    await seed();

    // 1. Authenticate as Teacher
    const loginRes = await request(app)
      .post('/auth/login')
      .send({ email: 'teacher@college.edu', password: 'teacher123' });

    expect(loginRes.status).toBe(200);
    const teacherToken = loginRes.body.token as string;
    const teacherId = String(loginRes.body.user.id);

    // 2. Create Student with phone and marks
    const createRes = await request(app)
      .post('/api/students')
      .set('Authorization', `Bearer ${teacherToken}`)
      .send({
        name: 'John Doe',
        email: 'john@college.edu',
        phone: '555-0199',
        marks: 85,
      });

    expect(createRes.status).toBe(201);
    const studentId = createRes.body.student.id as string;

    // 3. Update Student marks
    const updateRes = await request(app)
      .patch(`/api/students/${studentId}`)
      .set('Authorization', `Bearer ${teacherToken}`)
      .send({ marks: 95 });

    expect(updateRes.status).toBe(200);

    // 4. Authenticate as Auditor and fetch history
    const auditorLoginRes = await request(app)
      .post('/auth/login')
      .send({ email: 'auditor@college.edu', password: 'auditor123' });
    expect(auditorLoginRes.status).toBe(200);
    const auditorToken = auditorLoginRes.body.token as string;

    const historyRes = await request(app)
      .get(`/audit/history/Student/${studentId}`)
      .set('Authorization', `Bearer ${auditorToken}`);

    expect(historyRes.status).toBe(200);
    const history = historyRes.body.history as Array<{
      action: string;
      actorId: string;
      actorRole: string;
      before: Record<string, unknown> | null;
      after: Record<string, unknown> | null;
      diff: Record<string, unknown> | null;
    }>;

    expect(history.length).toBe(2);
    expect(history[0]?.action).toBe('CREATE');
    expect(history[0]?.actorId).toBe(teacherId);
    expect(history[0]?.actorRole).toBe('TEACHER');
    expect(history[0]?.after?.phone).toMatch(/^\[REDACTED:[a-f0-9]{4}\]$/);

    expect(history[1]?.action).toBe('UPDATE');
    expect(history[1]?.diff?.marks).toEqual({ old: 85, new: 95 });

    // Step 4: Verify passes
    const verifyOutcome = await runVerifyCommand({
      config: demoConfigPath,
      keyEnv: 'TRAILGUARD_KEY',
    });
    expect(verifyOutcome.exitCode).toBe(0);
    expect(verifyOutcome.message).toContain('valid');
  });

  it('Step 5: detects direct database payload tampering as HASH_MISMATCH', async () => {
    // Direct MySQL modification of a past row
    await prisma.$executeRawUnsafe(
      'UPDATE trailguard_audit_log SET payload = \'{"tampered":true}\' WHERE seq = 2',
    );

    const tamperedOutcome = await runVerifyCommand({
      config: demoConfigPath,
      keyEnv: 'TRAILGUARD_KEY',
    });

    expect(tamperedOutcome.exitCode).toBe(1);
    expect(tamperedOutcome.message).toContain('broken at seq 2: [HASH_MISMATCH]');
  });

  it('Step 6: detects smart rehash-chain attack as HASH_MISMATCH', async () => {
    // Reset cleanly
    resetHeadCache();
    await seed();

    // Attacker runs rehashChain with plain SHA-256
    await rehashChain({
      targetSeq: 2,
      prisma: prisma as unknown as import('@prisma/client').PrismaClient,
    });

    // Verification must detect the forgery
    const verifyOutcome = await runVerifyCommand({
      config: demoConfigPath,
      keyEnv: 'TRAILGUARD_KEY',
    });

    expect(verifyOutcome.exitCode).toBe(1);
    expect(verifyOutcome.message).toContain('HASH_MISMATCH');
  });

  it('Step 7: detects truncation attack via external checkpoints as TRUNCATION_DETECTED', async () => {
    // Reset cleanly
    resetHeadCache();
    await seed();

    // Query current head
    const headRows = await prisma.$queryRawUnsafe<
      Array<{ lastSeq: bigint; lastHash: string }>
    >('SELECT lastSeq, lastHash FROM trailguard_audit_head WHERE id = 1');
    expect(headRows.length).toBeGreaterThan(0);
    const initialHead = headRows[0]!;

    // Create an external checkpoint before truncation
    const cp = createCheckpoint(
      { seq: initialHead.lastSeq, hash: initialHead.lastHash },
      masterKey,
      'k1',
    );
    await fileSink(tempCheckpointFile)(cp);

    // Attacker deletes the trailing row and resets AuditHead
    await truncateTail({
      count: 1,
      prisma: prisma as unknown as import('@prisma/client').PrismaClient,
    });

    // Without checkpoints, isolated database appears valid
    const isolatedOutcome = await runVerifyCommand({
      config: demoConfigPath,
      keyEnv: 'TRAILGUARD_KEY',
    });
    expect(isolatedOutcome.exitCode).toBe(0);
    expect(isolatedOutcome.message).toContain('valid');

    // With checkpoints, truncation is caught immediately
    const checkpointOutcome = await runVerifyCommand({
      config: demoConfigPath,
      keyEnv: 'TRAILGUARD_KEY',
      checkpoints: tempCheckpointFile,
    });

    expect(checkpointOutcome.exitCode).toBe(1);
    expect(checkpointOutcome.message).toContain('TRUNCATION_DETECTED');
  });

  it('Step 8: detects runtime access drift (DRIFT001) when TEACHER deletes User (T6.5)', async () => {
    // Reset cleanly
    resetHeadCache();
    await seed();

    // Verify initial clean state has 0 drift
    const initialDrift = await runDriftCommand({
      config: demoConfigPath,
      prisma: prisma as unknown as import('../../src/scan/drift.js').DriftPrismaClient,
    });
    expect(initialDrift.exitCode).toBe(0);

    // Seed drift: TEACHER performs DELETE on User (unauthorized by static matrix)
    await seedDrift({
      prisma: prisma as unknown as import('@prisma/client').PrismaClient,
      key: masterKey,
    });

    // Run trailguard drift
    const driftOutcome = await runDriftCommand({
      config: demoConfigPath,
      prisma: prisma as unknown as import('../../src/scan/drift.js').DriftPrismaClient,
    });

    expect(driftOutcome.exitCode).toBe(1);
    expect(driftOutcome.message).toContain('DRIFT001');
    expect(driftOutcome.message).toContain('TEACHER');
    expect(driftOutcome.message).toContain('User');
    expect(driftOutcome.message.toLowerCase()).toContain('delete');
  });
});
