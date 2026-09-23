/**
 * Integration test for attacker scripts (T6.3).
 *
 * Tests:
 * 1. rehash-chain: after rehash-chain (plain SHA-256 or wrong key, rewrites all rows + head)
 *    trailguard verify → exit 1 HASH_MISMATCH.
 * 2. truncate-tail: after truncate-tail (deletes last rows + resets head)
 *    verify passes alone, but verify --checkpoints → exit 1 TRUNCATION_DETECTED.
 *
 * @see context.md §11, tasks.md T6.3
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
import { rehashChain } from '../../scripts/attacker/rehash-chain.js';
import { truncateTail } from '../../scripts/attacker/truncate-tail.js';

describe('Integration: Attacker Scripts (T6.3)', () => {
  let prisma: PrismaClient;
  const masterKey = 'test-secret-key-for-attacker-scripts!';
  let tempDir: string;
  let checkpointsFile: string;

  beforeAll(async () => {
    prisma = new PrismaClient();
    await prisma.$connect();
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'trailguard-attacker-'));
    checkpointsFile = path.join(tempDir, 'checkpoints.jsonl');
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
    process.env.TEST_ATTACKER_KEY = masterKey;
    if (fs.existsSync(checkpointsFile)) {
      fs.unlinkSync(checkpointsFile);
    }
  });

  async function seedAuditRows(count: number): Promise<void> {
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
            marks: 80 + i,
          },
        }),
      );
    }
  }

  it('detects rehash-chain attack as HASH_MISMATCH', async () => {
    await seedAuditRows(4);

    // Initial check passes
    const beforeOutcome = await runVerifyCommand({
      keyEnv: 'TEST_ATTACKER_KEY',
      prisma,
    });
    expect(beforeOutcome.exitCode).toBe(0);
    expect(beforeOutcome.message).toContain('valid (4 records)');

    // Attacker runs rehash-chain with plain SHA-256
    await rehashChain({
      targetSeq: 2,
      prisma: prisma as unknown as import('@prisma/client').PrismaClient,
    });

    // Trailguard verify detects the fraud because HMAC key was not used
    const afterOutcome = await runVerifyCommand({
      keyEnv: 'TEST_ATTACKER_KEY',
      prisma,
    });

    expect(afterOutcome.exitCode).toBe(1);
    expect(afterOutcome.message).toContain('HASH_MISMATCH');
    expect(afterOutcome.message).toMatch(/broken at seq 1|broken at seq 2/);
  });

  it('detects truncate-tail attack via checkpoints as TRUNCATION_DETECTED', async () => {
    await seedAuditRows(5);

    // Emit a legitimate external checkpoint at seq 5
    const headRows = await prisma.$queryRawUnsafe<Array<{ lastSeq: bigint; lastHash: string }>>(
      'SELECT lastSeq, lastHash FROM trailguard_audit_head WHERE id = 1',
    );
    const head = headRows[0]!;
    const cp = createCheckpoint({ seq: head.lastSeq, hash: head.lastHash }, masterKey, 'primary');
    await fileSink(checkpointsFile)(cp);

    expect(fs.existsSync(checkpointsFile)).toBe(true);

    // Attacker deletes the last 2 rows and resets head back to seq 3
    await truncateTail({
      count: 2,
      prisma: prisma as unknown as import('@prisma/client').PrismaClient,
    });

    // 1. Without checkpoints: the remaining chain (seq 1..3) appears valid in isolation
    const isolatedOutcome = await runVerifyCommand({
      keyEnv: 'TEST_ATTACKER_KEY',
      prisma,
    });
    expect(isolatedOutcome.exitCode).toBe(0);
    expect(isolatedOutcome.message).toContain('valid (3 records)');

    // 2. With checkpoints: external checkpoint at seq 5 detects that the database was truncated
    const checkpointOutcome = await runVerifyCommand({
      keyEnv: 'TEST_ATTACKER_KEY',
      checkpoints: checkpointsFile,
      prisma,
    });

    expect(checkpointOutcome.exitCode).toBe(1);
    expect(checkpointOutcome.message).toContain('TRUNCATION_DETECTED');
  });
});
