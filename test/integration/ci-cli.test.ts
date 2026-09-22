/**
 * Integration & E2E tests for `trailguard ci` CLI command.
 *
 * Tests:
 * 1. Clean scan + valid DB returns exit code 0 and summary table with PASS.
 * 2. `--no-db` skips verify and drift with a visible warning and exit code 0.
 * 3. Scan findings exceeding threshold marks Static Scan FAIL and returns exit code 1.
 * 4. Tampered DB marks Audit Verify FAIL and returns exit code 1.
 * 5. Tool / config error returns exit code 2 with ERROR status.
 * 6. `--format json` and `--out <file>` writes scan report to the target file.
 * 7. E2E CLI child process execution.
 *
 * @see context.md §4.4, §4.5, tasks.md T5.2
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { execFile } from 'node:child_process';
import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { PrismaClient } from './generated/index.js';
import { createAuditClient } from '../../src/runtime/client.js';
import { runWithAuditContext } from '../../src/runtime/context.js';
import { resetHeadCache } from '../../src/runtime/append.js';
import { runCiCommand } from '../../src/cli/ci-command.js';

describe('Integration: trailguard ci CLI command', () => {
  let prisma: PrismaClient;
  const masterKey = 'test-secret-key-for-ci-cli!';
  let tempDir: string;
  const cleanFixtureConfig = path.resolve('test/fixtures/clean/trailguard.config.ts');
  const missingAuthFixtureConfig = path.resolve('test/fixtures/missing-auth/trailguard.config.ts');

  beforeAll(async () => {
    prisma = new PrismaClient();
    await prisma.$connect();
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'trailguard-ci-cli-'));
  });

  afterAll(async () => {
    await prisma.$disconnect();
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  beforeEach(async () => {
    await prisma.$executeRawUnsafe('DELETE FROM trailguard_audit_log');
    await prisma.$executeRawUnsafe('DELETE FROM trailguard_audit_head');
    await prisma.$executeRawUnsafe('DELETE FROM Student');
    resetHeadCache();
    process.env.TEST_CI_KEY = masterKey;
  });

  async function seedStudents(count: number): Promise<void> {
    const auditClient = createAuditClient(prisma, {
      models: ['Student'],
      keys: { secret: masterKey },
    });

    for (let i = 1; i <= count; i++) {
      const idx = String(i);
      await runWithAuditContext({ actorId: `admin-${idx}` }, () =>
        auditClient.student.create({
          data: {
            name: `Student ${idx}`,
            email: `student${idx}@example.com`,
            marks: 85 + i,
          },
        }),
      );
    }
  }

  it('runs scan + verify on clean fixture and valid DB, returning exit code 0', async () => {
    await seedStudents(3);

    const outcome = await runCiCommand({
      config: cleanFixtureConfig,
      keyEnv: 'TEST_CI_KEY',
      prisma,
    });

    expect(outcome.exitCode).toBe(0);
    expect(outcome.summaryTable).toContain('Trailguard CI Summary');
    expect(outcome.summaryTable).toContain('Static Scan');
    expect(outcome.summaryTable).toContain('Audit Verify');
    expect(outcome.summaryTable).toContain('PASS');
    expect(outcome.summaryTable).toContain('Result: PASS (exit code: 0)');

    const scanStage = outcome.stages.find((s) => s.name === 'Static Scan');
    expect(scanStage?.status).toBe('PASS');
    expect(scanStage?.exitCode).toBe(0);

    const verifyStage = outcome.stages.find((s) => s.name === 'Audit Verify');
    expect(verifyStage?.status).toBe('PASS');
    expect(verifyStage?.exitCode).toBe(0);
    expect(verifyStage?.details).toContain('valid');
  });

  it('skips database verification and drift with a loud warning when --no-db is set', async () => {
    const outcome = await runCiCommand({
      config: cleanFixtureConfig,
      noDb: true,
    });

    expect(outcome.exitCode).toBe(0);
    expect(outcome.warning).toContain('--no-db specified');
    expect(outcome.warning).toContain('Skipping database verification');

    const verifyStage = outcome.stages.find((s) => s.name === 'Audit Verify');
    expect(verifyStage?.status).toBe('SKIPPED');
    expect(verifyStage?.details).toContain('--no-db');

    const driftStage = outcome.stages.find((s) => s.name === 'Drift Check');
    expect(driftStage?.status).toBe('SKIPPED');

    expect(outcome.summaryTable).toContain('Result: PASS (exit code: 0)');
  });

  it('handles commander-style db: false as --no-db', async () => {
    const outcome = await runCiCommand({
      config: cleanFixtureConfig,
      db: false,
    });

    expect(outcome.exitCode).toBe(0);
    expect(outcome.warning).toContain('--no-db specified');
    const verifyStage = outcome.stages.find((s) => s.name === 'Audit Verify');
    expect(verifyStage?.status).toBe('SKIPPED');
  });

  it('returns exit code 1 when static scan findings exceed threshold', async () => {
    await seedStudents(2);

    const outcome = await runCiCommand({
      config: missingAuthFixtureConfig,
      keyEnv: 'TEST_CI_KEY',
      prisma,
      failOn: 'high',
    });

    expect(outcome.exitCode).toBe(1);
    const scanStage = outcome.stages.find((s) => s.name === 'Static Scan');
    expect(scanStage?.status).toBe('FAIL');
    expect(scanStage?.exitCode).toBe(1);

    // Verify still runs and passes
    const verifyStage = outcome.stages.find((s) => s.name === 'Audit Verify');
    expect(verifyStage?.status).toBe('PASS');
    expect(verifyStage?.exitCode).toBe(0);

    expect(outcome.summaryTable).toContain('Result: FAIL (exit code: 1)');
  });

  it('returns exit code 1 when audit log verification detects tampering', async () => {
    await seedStudents(3);

    // Tamper with payload of row 2
    await prisma.$executeRawUnsafe(
      "UPDATE trailguard_audit_log SET payload = '{\"tampered\": true}' WHERE seq = 2",
    );

    const outcome = await runCiCommand({
      config: cleanFixtureConfig,
      keyEnv: 'TEST_CI_KEY',
      prisma,
    });

    expect(outcome.exitCode).toBe(1);
    const scanStage = outcome.stages.find((s) => s.name === 'Static Scan');
    expect(scanStage?.status).toBe('PASS');
    expect(scanStage?.exitCode).toBe(0);

    const verifyStage = outcome.stages.find((s) => s.name === 'Audit Verify');
    expect(verifyStage?.status).toBe('FAIL');
    expect(verifyStage?.exitCode).toBe(1);
    expect(verifyStage?.details).toMatch(/broken at seq 2/);

    expect(outcome.summaryTable).toContain('Result: FAIL (exit code: 1)');
  });

  it('returns exit code 2 when configuration or tool error occurs', async () => {
    const outcome = await runCiCommand({
      config: '/non/existent/path/trailguard.config.ts',
      noDb: true,
    });

    expect(outcome.exitCode).toBe(2);
    const scanStage = outcome.stages.find((s) => s.name === 'Static Scan');
    expect(scanStage?.status).toBe('ERROR');
    expect(scanStage?.exitCode).toBe(2);
    expect(outcome.summaryTable).toContain('Result: ERROR (exit code: 2)');
  });

  it('returns exit code 2 when HMAC key is missing for DB verification', async () => {
    delete process.env.NON_EXISTENT_CI_KEY;

    const outcome = await runCiCommand({
      config: cleanFixtureConfig,
      keyEnv: 'NON_EXISTENT_CI_KEY',
      prisma,
    });

    expect(outcome.exitCode).toBe(2);
    const verifyStage = outcome.stages.find((s) => s.name === 'Audit Verify');
    expect(verifyStage?.status).toBe('ERROR');
    expect(verifyStage?.exitCode).toBe(2);
    expect(verifyStage?.details).toContain('not set');
    expect(outcome.summaryTable).toContain('Result: ERROR (exit code: 2)');
  });

  it('applies --format and --out to the scan report', async () => {
    const outPath = path.join(tempDir, 'scan-report.json');

    const outcome = await runCiCommand({
      config: cleanFixtureConfig,
      format: 'json',
      out: outPath,
      noDb: true,
    });

    expect(outcome.exitCode).toBe(0);
    expect(fs.existsSync(outPath)).toBe(true);

    const fileContent = fs.readFileSync(outPath, 'utf-8');
    const parsed = JSON.parse(fileContent) as { routes?: unknown[] };
    expect(parsed).toBeDefined();
    expect(parsed.routes).toBeDefined();
  });

  it('executes via CLI child process with --no-db', async () => {
    const cliBin = path.resolve('bin/trailguard.js');

    await new Promise<void>((resolve, reject) => {
      execFile(
        'node',
        [cliBin, 'ci', '--config', cleanFixtureConfig, '--no-db'],
        {
          cwd: path.resolve('.'),
          env: { ...process.env },
        },
        (error, stdout, stderr) => {
          if (error && error.code !== 0) {
            reject(new Error(`CLI exited with code ${String(error.code)}: ${stderr || stdout}`));
            return;
          }
          expect(stderr).toContain('--no-db specified');
          expect(stdout).toContain('Trailguard CI Summary');
          expect(stdout).toContain('Static Scan');
          expect(stdout).toContain('Audit Verify');
          expect(stdout).toContain('Result: PASS (exit code: 0)');
          resolve();
        },
      );
    });
  });
});
