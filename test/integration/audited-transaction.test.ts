import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { PrismaClient } from './generated/index.js';
import { createAuditClient } from '../../src/runtime/client.js';
import { runWithAuditContext } from '../../src/runtime/context.js';
import { resetHeadCache } from '../../src/runtime/append.js';
import { verifyAuditChain } from '../../src/runtime/verify.js';
import type { Checkpoint } from '../../src/core/types.js';

interface StudentModelOps {
  create: (args: Record<string, unknown>) => Promise<{ id: string; name: string; email: string; marks?: number | null }>;
  update: (args: Record<string, unknown>) => Promise<{ id: string; name: string; email: string; marks?: number | null }>;
  findUnique: (args: Record<string, unknown>) => Promise<{ id: string; name: string; email: string; marks?: number | null } | null>;
}

interface TestTx {
  student: StudentModelOps;
}

describe('Integration: $auditedTransaction (T3.14)', () => {
  let rawPrisma: PrismaClient;
  const masterKey = 'audit-test-key-32-chars-long-123';

  beforeAll(async () => {
    rawPrisma = new PrismaClient();
    await rawPrisma.$connect();
  });

  afterAll(async () => {
    await rawPrisma.$disconnect();
  });

  beforeEach(async () => {
    await rawPrisma.$executeRawUnsafe('DELETE FROM trailguard_audit_log');
    await rawPrisma.$executeRawUnsafe('DELETE FROM trailguard_audit_head');
    await rawPrisma.$executeRawUnsafe('DELETE FROM Student');
    resetHeadCache();
  });

  it('batches multiple operations in a single transaction with contiguous seqs and valid HMAC chain', async () => {
    const auditClient = createAuditClient(rawPrisma, {
      models: ['Student'],
      keys: { secret: masterKey },
    });

    const txResult = await runWithAuditContext(
      { actorId: 'teacher-1', actorRole: 'TEACHER', requestId: 'req-tx-1' },
      () =>
        auditClient.$auditedTransaction(async (rawTx: Record<string, unknown>) => {
          const tx = rawTx as unknown as TestTx;
          const s1 = await tx.student.create({
            data: {
              name: 'Alice Springs',
              email: 'alice@tx.test',
              marks: 85,
            },
          });

          const s2 = await tx.student.create({
            data: {
              name: 'Bob Marley',
              email: 'bob@tx.test',
              marks: 75,
            },
          });

          const updatedS1 = await tx.student.update({
            where: { id: s1.id },
            data: { marks: 95 },
          });

          return { s1, s2, updatedS1 };
        }),
    );

    expect(txResult.s1.name).toBe('Alice Springs');
    expect(txResult.s2.name).toBe('Bob Marley');
    expect(txResult.updatedS1.marks).toBe(95);

    // Verify AuditLog entries
    const logs = await rawPrisma.auditLog.findMany({
      orderBy: { seq: 'asc' },
    });

    expect(logs).toHaveLength(3);

    // Verify gapless contiguous seqs: 1, 2, 3
    expect(logs[0]!.seq).toBe(1n);
    expect(logs[1]!.seq).toBe(2n);
    expect(logs[2]!.seq).toBe(3n);

    // Verify actions
    expect(logs[0]!.action).toBe('CREATE');
    expect(logs[1]!.action).toBe('CREATE');
    expect(logs[2]!.action).toBe('UPDATE');

    // Verify actor and requestId captured across all entries
    for (const log of logs) {
      expect(log.actorId).toBe('teacher-1');
      expect(log.actorRole).toBe('TEACHER');
      expect(log.requestId).toBe('req-tx-1');
    }

    // Verify HMAC chain cryptographic validity
    const verifyResult = await verifyAuditChain({
      prisma: rawPrisma,
      keys: { secret: masterKey },
    });
    expect(verifyResult.valid).toBe(true);
    expect(verifyResult.checkedRecords).toBe(3);
    expect(verifyResult.problems).toHaveLength(0);
  });

  it('rolls back all business writes and audit entries when fn throws', async () => {
    const auditClient = createAuditClient(rawPrisma, {
      models: ['Student'],
      keys: { secret: masterKey },
    });

    await expect(
      runWithAuditContext(
        { actorId: 'teacher-abort', actorRole: 'TEACHER' },
        () =>
          auditClient.$auditedTransaction(async (rawTx: Record<string, unknown>) => {
            const tx = rawTx as unknown as TestTx;
            await tx.student.create({
              data: {
                name: 'Ghost Student',
                email: 'ghost@tx.test',
              },
            });

            await tx.student.create({
              data: {
                name: 'Phantom Student',
                email: 'phantom@tx.test',
              },
            });

            throw new Error('Simulated business error inside transaction');
          }),
      ),
    ).rejects.toThrow('Simulated business error inside transaction');

    // Both student records must be rolled back
    const students = await rawPrisma.student.findMany();
    expect(students).toHaveLength(0);

    // Zero audit records must be committed
    const logs = await rawPrisma.auditLog.findMany();
    expect(logs).toHaveLength(0);
  });

  it('rolls back business writes when testHooks.beforeAppend fails', async () => {
    const auditClient = createAuditClient(rawPrisma, {
      models: ['Student'],
      keys: { secret: masterKey },
      testHooks: {
        beforeAppend: () => {
          throw new Error('Injected head-lock failure before append');
        },
      },
    });

    await expect(
      runWithAuditContext(
        { actorId: 'teacher-lock-fail', actorRole: 'TEACHER' },
        () =>
          auditClient.$auditedTransaction(async (rawTx: Record<string, unknown>) => {
            const tx = rawTx as unknown as TestTx;
            await tx.student.create({
              data: {
                name: 'Uncommitted Student',
                email: 'uncommitted@tx.test',
              },
            });
          }),
      ),
    ).rejects.toThrow('Injected head-lock failure before append');

    // Student write must be rolled back
    const student = await rawPrisma.student.findUnique({
      where: { email: 'uncommitted@tx.test' },
    });
    expect(student).toBeNull();

    // Zero audit rows must exist
    const logs = await rawPrisma.auditLog.findMany();
    expect(logs).toHaveLength(0);
  });

  it('allows reading newly created rows within the same transaction', async () => {
    const auditClient = createAuditClient(rawPrisma, {
      models: ['Student'],
      keys: { secret: masterKey },
    });

    await runWithAuditContext(
      { actorId: 'teacher-read-back', actorRole: 'TEACHER' },
      () =>
        auditClient.$auditedTransaction(async (rawTx: Record<string, unknown>) => {
          const tx = rawTx as unknown as TestTx;
          const created = await tx.student.create({
            data: {
              name: 'Immediate Read',
              email: 'immediate@tx.test',
              marks: 80,
            },
          });

          // Read-your-own-writes within the same active transaction
          const found = await tx.student.findUnique({
            where: { id: created.id },
          });

          expect(found).not.toBeNull();
          expect(found?.name).toBe('Immediate Read');
          expect(found?.marks).toBe(80);
        }),
    );
  });

  it('emits checkpoints after transaction commit when due', async () => {
    const emittedCheckpoints: Checkpoint[] = [];

    const auditClient = createAuditClient(rawPrisma, {
      models: ['Student'],
      keys: { secret: masterKey },
      checkpoint: {
        every: 2,
        sink: (cp) => {
          emittedCheckpoints.push(cp);
        },
      },
    });

    await runWithAuditContext(
      { actorId: 'checkpoint-actor', actorRole: 'AUDITOR' },
      () =>
        auditClient.$auditedTransaction(async (rawTx: Record<string, unknown>) => {
          const tx = rawTx as unknown as TestTx;
          await tx.student.create({ data: { name: 'S1', email: 's1@tx.test' } });
          await tx.student.create({ data: { name: 'S2', email: 's2@tx.test' } });
          await tx.student.create({ data: { name: 'S3', email: 's3@tx.test' } });
        }),
    );

    // Cadence is every 2, so seq 2 should have triggered a checkpoint
    expect(emittedCheckpoints).toHaveLength(1);
    expect(emittedCheckpoints[0]!.seq).toBe('2');
  });
});
