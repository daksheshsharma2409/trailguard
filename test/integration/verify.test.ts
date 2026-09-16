import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { PrismaClient } from './generated/index.js';
import { createAuditClient } from '../../src/runtime/client.js';
import { runWithAuditContext } from '../../src/runtime/context.js';
import { verifyAuditChain } from '../../src/runtime/verify.js';
import { resetHeadCache } from '../../src/runtime/append.js';

describe('Integration: verifyAuditChain', () => {
  let prisma: PrismaClient;
  const masterKey = 'test-secret-key-for-verify-chain!';

  beforeAll(async () => {
    prisma = new PrismaClient();
    await prisma.$connect();
  });

  afterAll(async () => {
    await prisma.$disconnect();
  });

  beforeEach(async () => {
    await prisma.$executeRawUnsafe('DELETE FROM trailguard_audit_log');
    await prisma.$executeRawUnsafe('DELETE FROM trailguard_audit_head');
    await prisma.$executeRawUnsafe('DELETE FROM Student');
    resetHeadCache();
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

  it('valid chain returns valid: true and checkedRecords: N', async () => {
    await seedStudents(5);

    const result = await verifyAuditChain({
      prisma,
      keys: { secret: masterKey },
    });

    expect(result.valid).toBe(true);
    expect(result.checkedRecords).toBe(5);
    expect(result.problems).toHaveLength(0);
    expect(result.head?.seq).toBe('5');
  });

  it('detects payload tampering as HASH_MISMATCH', async () => {
    await seedStudents(4);

    // Tamper with payload of seq 3
    await prisma.$executeRawUnsafe(
      'UPDATE trailguard_audit_log SET payload = \'{"tampered":true}\' WHERE seq = 3',
    );

    const result = await verifyAuditChain({
      prisma,
      keys: { secret: masterKey },
    });

    expect(result.valid).toBe(false);
    expect(result.problems[0]?.code).toBe('HASH_MISMATCH');
    expect(result.brokenAt).toBe('3');
  });

  it('detects tampering with only before column as COLUMN_PAYLOAD_MISMATCH', async () => {
    const auditClient = createAuditClient(prisma, {
      models: ['Student'],
      keys: { secret: masterKey },
    });

    const student = await runWithAuditContext({ actorId: 'u1' }, () =>
      auditClient.student.create({
        data: { name: 'Initial', email: 'init@test.com' },
      }),
    );

    await runWithAuditContext({ actorId: 'u2' }, () =>
      auditClient.student.update({
        where: { id: student.id },
        data: { name: 'Updated' },
      }),
    );

    // Tamper only with the 'before' convenience column on row 2
    await prisma.auditLog.update({
      where: { seq: 2n },
      data: { before: { name: 'ForgedName' } },
    });

    const result = await verifyAuditChain({
      prisma,
      keys: { secret: masterKey },
    });

    expect(result.valid).toBe(false);
    expect(result.problems[0]?.code).toBe('COLUMN_PAYLOAD_MISMATCH');
    expect(result.brokenAt).toBe('2');
  });

  it('detects deleting a middle row as SEQ_GAP', async () => {
    await seedStudents(4);

    // Delete middle row (seq 2)
    await prisma.$executeRawUnsafe('DELETE FROM trailguard_audit_log WHERE seq = 2');

    const result = await verifyAuditChain({
      prisma,
      keys: { secret: masterKey },
    });

    expect(result.valid).toBe(false);
    expect(result.problems[0]?.code).toBe('SEQ_GAP');
    expect(result.brokenAt).toBe('3');
  });

  it('fails verification when sequence of two rows is swapped', async () => {
    await seedStudents(3);

    // Swap seq 1 and seq 2
    await prisma.$executeRawUnsafe('UPDATE trailguard_audit_log SET seq = 99 WHERE seq = 1');
    await prisma.$executeRawUnsafe('UPDATE trailguard_audit_log SET seq = 1 WHERE seq = 2');
    await prisma.$executeRawUnsafe('UPDATE trailguard_audit_log SET seq = 2 WHERE seq = 99');

    const result = await verifyAuditChain({
      prisma,
      keys: { secret: masterKey },
    });

    expect(result.valid).toBe(false);
    expect(result.problems.length).toBeGreaterThan(0);
  });

  it('detects head mismatch as HEAD_MISMATCH', async () => {
    await seedStudents(3);

    // Corrupt AuditHead lastSeq
    await prisma.$executeRawUnsafe(
      'UPDATE trailguard_audit_head SET lastSeq = 999 WHERE id = 1',
    );

    const result = await verifyAuditChain({
      prisma,
      keys: { secret: masterKey },
    });

    expect(result.valid).toBe(false);
    expect(result.problems.some((p) => p.code === 'HEAD_MISMATCH')).toBe(true);
  });

  it('batches correctly across multiple pages when batchSize is small', async () => {
    await seedStudents(12);

    const result = await verifyAuditChain({
      prisma,
      keys: { secret: masterKey },
      batchSize: 4, // 12 records across 3 batches
    });

    expect(result.valid).toBe(true);
    expect(result.checkedRecords).toBe(12);
    expect(result.problems).toHaveLength(0);
  });
});
