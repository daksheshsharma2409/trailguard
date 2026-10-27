import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { PrismaClient } from './generated/index.js';
import { createAuditClient } from '../../src/runtime/client.js';
import { runWithAuditContext } from '../../src/runtime/context.js';
import { verifyAuditChain } from '../../src/runtime/verify.js';
import { callbackSink } from '../../src/runtime/checkpoint.js';
import { resetHeadCache } from '../../src/runtime/append.js';
import type { Checkpoint } from '../../src/core/types.js';

describe('Integration: Checkpoints', () => {
  let prisma: PrismaClient;
  const masterKey = 'test-checkpoint-key-secret-32-chars!';

  beforeAll(async () => {
    prisma = new PrismaClient();
    await prisma.$connect();
  });

  afterAll(async () => {
    await prisma.$disconnect();
  });

  beforeEach(async () => {
    await prisma.auditLog.deleteMany();
    await prisma.auditHead.deleteMany();
    await prisma.student.deleteMany();
    resetHeadCache();
  });

  it('detects truncation when last rows are deleted and head reset, while plain verify passes', async () => {
    const checkpoints: Checkpoint[] = [];
    const auditClient = createAuditClient(prisma, {
      models: ['Student'],
      keys: { secret: masterKey },
      checkpoint: {
        every: 2,
        sink: callbackSink((cp) => {
          checkpoints.push(cp);
        }),
      },
    });

    // Create 4 students -> triggers checkpoints at seq 2 and seq 4
    for (let i = 1; i <= 4; i++) {
      const idx = String(i);
      await runWithAuditContext({ actorId: `teacher-${idx}` }, () =>
        auditClient.student.create({
          data: {
            name: `Student ${idx}`,
            email: `student${idx}@test.com`,
          },
        }),
      );
    }

    expect(checkpoints).toHaveLength(2);
    expect(checkpoints[0]?.seq).toBe('2');
    expect(checkpoints[1]?.seq).toBe('4');

    // Get row 2's hash to forge a valid-looking head
    const row2 = await prisma.auditLog.findUnique({ where: { seq: 2n } });
    expect(row2).not.toBeNull();
    const row2Hash = row2?.hash ?? '';

    // Malicious DB admin deletes rows 3 and 4, and resets AuditHead to row 2
    await prisma.auditLog.deleteMany({ where: { seq: { in: [3n, 4n] } } });
    await prisma.auditHead.update({
      where: { id: 1 },
      data: { lastSeq: 2n, lastHash: row2Hash },
    });

    // 1. Plain verify without checkpoints: sees 2 rows, head matches row 2, reports valid: true!
    const plainResult = await verifyAuditChain({
      prisma,
      keys: { secret: masterKey },
    });
    expect(plainResult.valid).toBe(true);
    expect(plainResult.checkedRecords).toBe(2);

    // 2. Verify with external checkpoints: detects truncation because checkpoint has seq 4!
    const cpResult = await verifyAuditChain({
      prisma,
      keys: { secret: masterKey },
      checkpoints,
    });
    expect(cpResult.valid).toBe(false);
    expect(cpResult.problems.some((p) => p.code === 'TRUNCATION_DETECTED')).toBe(true);
  });

  it('detects forged checkpoint signature as CHECKPOINT_BAD_SIGNATURE', async () => {
    const checkpoints: Checkpoint[] = [];
    const auditClient = createAuditClient(prisma, {
      models: ['Student'],
      keys: { secret: masterKey },
      checkpoint: {
        every: 1,
        sink: callbackSink((cp) => {
          checkpoints.push(cp);
        }),
      },
    });

    await runWithAuditContext({ actorId: 'admin' }, () =>
      auditClient.student.create({
        data: { name: 'Alice', email: 'alice@test.com' },
      }),
    );

    expect(checkpoints).toHaveLength(1);
    const validCp = checkpoints[0];
    expect(validCp).toBeDefined();
    if (!validCp) return;

    // Forge signature
    const forgedCp: Checkpoint = {
      ...validCp,
      sig: '0000000000000000000000000000000000000000000000000000000000000000',
    };

    const result = await verifyAuditChain({
      prisma,
      keys: { secret: masterKey },
      checkpoints: [forgedCp],
    });

    expect(result.valid).toBe(false);
    expect(result.problems.some((p) => p.code === 'CHECKPOINT_BAD_SIGNATURE')).toBe(true);
  });

  it('checkpoint sink failure does not fail the business write and calls onError', async () => {
    const capturedErrors: Error[] = [];

    const auditClient = createAuditClient(prisma, {
      models: ['Student'],
      keys: { secret: masterKey },
      checkpoint: {
        every: 1,
        sink: () => {
          throw new Error('Remote WORM storage connection failed');
        },
      },
      onError: (err) => {
        capturedErrors.push(err);
      },
    });

    // Business write should succeed despite sink throwing
    const student = await runWithAuditContext({ actorId: 'teacher-1' }, () =>
      auditClient.student.create({
        data: { name: 'Bob', email: 'bob@test.com' },
      }),
    );

    expect(student.id).toBeDefined();

    // Verify student exists in DB
    const studentInDb = await prisma.student.findUnique({
      where: { id: student.id },
    });
    expect(studentInDb).not.toBeNull();

    // Verify AuditLog entry was committed
    const logs = await prisma.auditLog.findMany();
    expect(logs).toHaveLength(1);

    // Verify onError was called
    expect(capturedErrors).toHaveLength(1);
    expect(capturedErrors[0]?.message).toBe('Remote WORM storage connection failed');
  });
});
