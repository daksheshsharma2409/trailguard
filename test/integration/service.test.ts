import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { PrismaClient } from './generated/index.js';
import { AuditChainService, type AuditServicePrismaClient } from '../../src/runtime/service.js';
import { type AuditPrismaTx, resetHeadCache } from '../../src/runtime/append.js';
import { verifyCheckpointSignature } from '../../src/runtime/checkpoint.js';
import { runWithAuditContext } from '../../src/runtime/context.js';

describe('Integration: AuditChainService', () => {
  let prisma: PrismaClient;
  const masterKey = 'service-test-master-hmac-key-32!';

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

  it('commits manual audit log inside caller-managed $transaction', async () => {
    const student = await prisma.student.create({
      data: {
        id: 'std-svc-commit',
        name: 'Initial Name',
        email: 'svc.commit@example.com',
        marks: 70,
      },
    });

    const service = new AuditChainService(prisma as unknown as AuditServicePrismaClient, {
      models: ['Student'],
      keys: { secret: masterKey },
    });

    await prisma.$transaction(async (tx) => {
      const updated = await tx.student.update({
        where: { id: student.id },
        data: { name: 'Committed Name', marks: 85 },
      });

      await service.log(
        {
          model: 'Student',
          recordId: student.id,
          action: 'UPDATE',
          actorId: 'admin-1',
          actorRole: 'ADMIN',
          before: { name: student.name, marks: student.marks },
          after: { name: updated.name, marks: updated.marks },
        },
        tx as unknown as AuditPrismaTx,
      );
    });

    // Verify student was updated in DB
    const refreshed = await prisma.student.findUnique({
      where: { id: student.id },
    });
    expect(refreshed?.name).toBe('Committed Name');
    expect(refreshed?.marks).toBe(85);

    // Verify audit log was committed
    const logs = await prisma.auditLog.findMany();
    expect(logs).toHaveLength(1);
    expect(logs[0]?.model).toBe('Student');
    expect(logs[0]?.recordId).toBe(student.id);
    expect(logs[0]?.action).toBe('UPDATE');

    // Verify chain is cryptographically valid
    const verifyRes = await service.verify();
    expect(verifyRes.valid).toBe(true);
    expect(verifyRes.checkedRecords).toBe(1);
  });

  it('rolls back manual audit log and business write when caller-managed $transaction fails', async () => {
    const student = await prisma.student.create({
      data: {
        id: 'std-svc-rollback',
        name: 'Initial Name',
        email: 'svc.rollback@example.com',
        marks: 70,
      },
    });

    const service = new AuditChainService(prisma as unknown as AuditServicePrismaClient, {
      models: ['Student'],
      keys: { secret: masterKey },
    });

    await expect(
      prisma.$transaction(async (tx) => {
        const updated = await tx.student.update({
          where: { id: student.id },
          data: { name: 'Should Roll Back', marks: 99 },
        });

        await service.log(
          {
            model: 'Student',
            recordId: student.id,
            action: 'UPDATE',
            actorId: 'admin-1',
            actorRole: 'ADMIN',
            before: { name: student.name, marks: student.marks },
            after: { name: updated.name, marks: updated.marks },
          },
          tx as unknown as AuditPrismaTx,
        );

        throw new Error('Simulated failure inside caller transaction');
      }),
    ).rejects.toThrow('Simulated failure inside caller transaction');

    // Verify student was NOT updated in DB
    const refreshed = await prisma.student.findUnique({
      where: { id: student.id },
    });
    expect(refreshed?.name).toBe('Initial Name');
    expect(refreshed?.marks).toBe(70);

    // Verify no audit log was persisted
    const logs = await prisma.auditLog.findMany();
    expect(logs).toHaveLength(0);
  });

  it('manually logs standalone without caller tx', async () => {
    const service = new AuditChainService(prisma as unknown as AuditServicePrismaClient, {
      models: ['Student'],
      keys: { secret: masterKey },
    });

    const record = await runWithAuditContext(
      { actorId: 'user-standalone', actorRole: 'TEACHER', requestId: 'req-standalone' },
      () =>
        service.log({
          model: 'Student',
          recordId: 'std-standalone',
          action: 'CREATE',
          after: { id: 'std-standalone', name: 'Standalone Student' },
        }),
    );

    expect(record.seq).toBe(1n);
    expect(record.actorId).toBe('user-standalone');
    expect(record.actorRole).toBe('TEACHER');

    const logs = await prisma.auditLog.findMany();
    expect(logs).toHaveLength(1);
    expect(logs[0]?.recordId).toBe('std-standalone');
  });

  it('redacts sensitive fields in manual log calls', async () => {
    const service = new AuditChainService(prisma as unknown as AuditServicePrismaClient, {
      models: ['Student'],
      keys: { secret: masterKey },
      redactFields: ['phone', 'secretNotes'],
    });

    const record = await service.log({
      model: 'Student',
      recordId: 'std-redact',
      action: 'CREATE',
      after: {
        id: 'std-redact',
        name: 'Private Student',
        phone: '123-456-7890',
        secretNotes: 'Top secret medical info',
      },
    });

    const afterObj = record.after as Record<string, unknown>;
    expect(afterObj['phone']).toMatch(/^\[REDACTED:[0-9a-f]{4}\]$/);
    expect(afterObj['secretNotes']).toMatch(/^\[REDACTED:[0-9a-f]{4}\]$/);
    expect(afterObj['phone']).not.toContain('123-456-7890');
    expect(afterObj['secretNotes']).not.toContain('Top secret medical info');
  });

  it('getHistory returns records strictly ordered by sequence number', async () => {
    const service = new AuditChainService(prisma as unknown as AuditServicePrismaClient, {
      models: ['Student'],
      keys: { secret: masterKey },
    });

    const studentId = 'std-history-test';

    // 1 CREATE + 3 UPDATEs
    await service.log({
      model: 'Student',
      recordId: studentId,
      action: 'CREATE',
      after: { id: studentId, marks: 50 },
    });

    await service.log({
      model: 'Student',
      recordId: studentId,
      action: 'UPDATE',
      before: { marks: 50 },
      after: { marks: 60 },
    });

    await service.log({
      model: 'Student',
      recordId: studentId,
      action: 'UPDATE',
      before: { marks: 60 },
      after: { marks: 75 },
    });

    await service.log({
      model: 'Student',
      recordId: studentId,
      action: 'UPDATE',
      before: { marks: 75 },
      after: { marks: 90 },
    });

    // Also log an unrelated student to ensure filtering works
    await service.log({
      model: 'Student',
      recordId: 'unrelated-std',
      action: 'CREATE',
      after: { id: 'unrelated-std', marks: 100 },
    });

    // Ascending (default)
    const historyAsc = await service.getHistory('Student', studentId);
    expect(historyAsc).toHaveLength(4);
    expect(historyAsc[0]?.seq).toBe(1n);
    expect(historyAsc[1]?.seq).toBe(2n);
    expect(historyAsc[2]?.seq).toBe(3n);
    expect(historyAsc[3]?.seq).toBe(4n);

    expect(historyAsc[0]?.action).toBe('CREATE');
    expect(historyAsc[1]?.action).toBe('UPDATE');
    expect(historyAsc[2]?.action).toBe('UPDATE');
    expect(historyAsc[3]?.action).toBe('UPDATE');

    // Descending
    const historyDesc = await service.getHistory('Student', studentId, { order: 'desc' });
    expect(historyDesc).toHaveLength(4);
    expect(historyDesc[0]?.seq).toBe(4n);
    expect(historyDesc[1]?.seq).toBe(3n);
    expect(historyDesc[2]?.seq).toBe(2n);
    expect(historyDesc[3]?.seq).toBe(1n);

    // Pagination (limit and skip)
    const page = await service.getHistory('Student', studentId, { limit: 2, skip: 1 });
    expect(page).toHaveLength(2);
    expect(page[0]?.seq).toBe(2n);
    expect(page[1]?.seq).toBe(3n);
  });

  it('creates an on-demand signed checkpoint', async () => {
    let capturedCheckpoint: unknown = null;
    const service = new AuditChainService(prisma as unknown as AuditServicePrismaClient, {
      models: ['Student'],
      keys: { secret: masterKey },
      checkpoint: {
        every: 100, // manual checkpoint won't be triggered by cadence
        sink: (cp) => {
          capturedCheckpoint = cp;
        },
      },
    });

    await service.log({
      model: 'Student',
      recordId: 'std-cp-1',
      action: 'CREATE',
      after: { id: 'std-cp-1', marks: 95 },
    });

    const fixedDate = new Date('2026-10-26T12:00:00.000Z');
    const checkpoint = await service.checkpoint(fixedDate);

    expect(checkpoint.seq).toBe('1');
    expect(checkpoint.ts).toBe('2026-10-26T12:00:00.000Z');
    expect(checkpoint.keyId).toBe('default');
    expect(checkpoint.sig).toHaveLength(64);

    expect(verifyCheckpointSignature(checkpoint, masterKey)).toBe(true);
    expect(capturedCheckpoint).toEqual(checkpoint);
  });
});
