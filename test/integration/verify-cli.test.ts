/**
 * Integration & E2E tests for `trailguard verify` CLI command.
 *
 * Tests:
 * 1. Valid DB returns exit code 0 with human-readable "✔ valid (N records)".
 * 2. Tampered DB returns exit code 1 with seq + reason ("✖ broken at seq X: reason").
 * 3. Missing key environment variable returns exit code 2 without printing secrets.
 * 4. Unreachable DB returns exit code 2 with clear error message.
 * 5. Checkpoints verification detects truncation (exit 1 TRUNCATION_DETECTED).
 * 6. Child process CLI execution matches exit codes and formatting.
 *
 * @see context.md §4.4, §4.5, §7.9, tasks.md T5.1
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { PrismaClient } from './generated/index.js';
import { createAuditClient } from '../../src/runtime/client.js';
import { runWithAuditContext } from '../../src/runtime/context.js';
import { resetHeadCache } from '../../src/runtime/append.js';
import { createCheckpoint, fileSink } from '../../src/runtime/checkpoint.js';
import { runVerifyCommand } from '../../src/cli/verify-command.js';

describe('Integration: trailguard verify CLI command', () => {
  let prisma: PrismaClient;
  const masterKey = 'test-secret-key-for-verify-cli!';
  let tempDir: string;

  beforeAll(async () => {
    prisma = new PrismaClient();
    await prisma.$connect();
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'trailguard-verify-cli-'));
  });

  afterAll(async () => {
    await prisma.$disconnect();
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  beforeEach(async () => {
    await prisma.auditLog.deleteMany();
    await prisma.auditHead.deleteMany();
    await prisma.student.deleteMany();
    resetHeadCache();
    process.env.TEST_VERIFY_KEY = masterKey;
  });

  async function seedStudents(count: number): Promise<void> {
    const auditClient = createAuditClient(prisma, {
      models: ['Student'],
      keys: { secret: masterKey },
    });

    for (let i = 1; i <= count; i++) {
      const idx = String(i);
      await runWithAuditContext({ actorId: `teacher-${idx}` }, () =>
        auditClient.student.create({
          data: {
            name: `Student ${idx}`,
            email: `student${idx}@test.com`,
            marks: 80 + i,
          },
        }),
      );
    }
  }

  it('valid DB returns exit 0 with human-readable ✔ valid (N records)', async () => {
    await seedStudents(5);

    const outcome = await runVerifyCommand({
      prisma,
      keyEnv: 'TEST_VERIFY_KEY',
    });

    expect(outcome.exitCode).toBe(0);
    expect(outcome.message).toBe('✔ valid (5 records)');
    expect(outcome.result?.valid).toBe(true);
    expect(outcome.result?.checkedRecords).toBe(5);
  });

  it('tampered DB returns exit 1 with seq and reason', async () => {
    await seedStudents(3);

    // Tamper with seq 2
    await prisma.auditLog.update({
      where: { seq: 2n },
      data: { payload: 'TAMPERED' },
    });

    const outcome = await runVerifyCommand({
      prisma,
      keyEnv: 'TEST_VERIFY_KEY',
    });

    expect(outcome.exitCode).toBe(1);
    expect(outcome.message).toContain('✖ broken at seq 2: [HASH_MISMATCH]');
    expect(outcome.result?.valid).toBe(false);
  });

  it('missing key env returns exit 2 with clear message and never prints key', async () => {
    delete process.env.NONEXISTENT_KEY_VAR;

    const outcome = await runVerifyCommand({
      prisma,
      keyEnv: 'NONEXISTENT_KEY_VAR',
    });

    expect(outcome.exitCode).toBe(2);
    expect(outcome.message).toContain("Environment variable 'NONEXISTENT_KEY_VAR' is not set or empty");
    // Ensure secrets are never exposed
    expect(outcome.message).not.toContain(masterKey);
  });

  it('unreachable DB returns exit 2 with clear error message', async () => {
    const badPrisma = {
      auditLog: {
        findMany: () => Promise.reject(new Error('connect ECONNREFUSED 127.0.0.1:9999')),
      },
      auditHead: {
        findUnique: () => Promise.resolve(null),
      },
    };

    const outcome = await runVerifyCommand({
      prisma: badPrisma as unknown as Parameters<typeof runVerifyCommand>[0]['prisma'],
      keyEnv: 'TEST_VERIFY_KEY',
    });

    expect(outcome.exitCode).toBe(2);
    expect(outcome.message).toContain('Verification failed unexpectedly');
    expect(outcome.message).toContain('ECONNREFUSED');
  });

  it('detects truncation with external checkpoints (exit 1 TRUNCATION_DETECTED)', async () => {
    await seedStudents(5);

    // Create a checkpoint at seq 5
    const headRow = await prisma.auditHead.findUnique({ where: { id: 1 } });
    const lastSeq = headRow?.lastSeq;
    const lastHash = headRow?.lastHash;
    expect(lastSeq).toBe(5n);

    const cp = createCheckpoint({ seq: lastSeq!, hash: lastHash! }, masterKey, 'default');
    const cpFile = path.join(tempDir, 'checkpoints.jsonl');
    await fileSink(cpFile)(cp);

    // Attacker truncates rows 4 and 5, resets head to seq 3
    const row3 = await prisma.auditLog.findUnique({ where: { seq: 3n } });
    await prisma.auditLog.deleteMany({ where: { seq: { gt: 3n } } });
    const row3Hash = row3?.hash ?? '';
    await prisma.auditHead.update({
      where: { id: 1 },
      data: { lastSeq: 3n, lastHash: row3Hash },
    });

    // Without checkpoints, verify alone says valid (3 records)
    const outcomeWithoutCp = await runVerifyCommand({
      prisma,
      keyEnv: 'TEST_VERIFY_KEY',
    });
    expect(outcomeWithoutCp.exitCode).toBe(0);

    // With checkpoints, verify catches truncation!
    const outcomeWithCp = await runVerifyCommand({
      prisma,
      keyEnv: 'TEST_VERIFY_KEY',
      checkpoints: cpFile,
    });
    expect(outcomeWithCp.exitCode).toBe(1);
    expect(outcomeWithCp.message).toContain('TRUNCATION_DETECTED');
  });

  it('collects multiple problems when --all is enabled', async () => {
    await seedStudents(4);

    // Tamper with seq 2 and seq 3
    await prisma.auditLog.update({
      where: { seq: 2n },
      data: { payload: 'TAMPERED_A' },
    });
    await prisma.auditLog.update({
      where: { seq: 3n },
      data: { payload: 'TAMPERED_B' },
    });

    const outcome = await runVerifyCommand({
      prisma,
      keyEnv: 'TEST_VERIFY_KEY',
      all: true,
    });

    expect(outcome.exitCode).toBe(1);
    expect(outcome.result?.problems.length).toBeGreaterThan(1);
    expect(outcome.message).toContain('✖ broken at seq 2: [HASH_MISMATCH]');
  });
});
