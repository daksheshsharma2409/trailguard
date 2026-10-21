import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { PrismaClient } from './generated/index.js';
import { createAuditClient } from '../../src/runtime/client.js';
import { runWithAuditContext } from '../../src/runtime/context.js';
import { resetHeadCache } from '../../src/runtime/append.js';
import { verifyAuditChain } from '../../src/runtime/verify.js';
import type { AuditLogRecord } from '../../src/core/types.js';

interface StudentModelOps {
  create: (args: Record<string, unknown>) => Promise<{ id: string; name: string; email: string; marks?: number | null }>;
  update: (args: Record<string, unknown>) => Promise<{ id: string; name: string; email: string; marks?: number | null }>;
  findUnique: (args: Record<string, unknown>) => Promise<{ id: string; name: string; email: string; marks?: number | null } | null>;
  findMany: (args?: Record<string, unknown>) => Promise<Array<{ id: string; name: string; email: string; marks?: number | null }>>;
}

interface TestTx {
  student: StudentModelOps;
}

interface AuditedTestClient {
  student: StudentModelOps;
  $auditedTransaction<T>(fn: (tx: TestTx) => Promise<T>): Promise<T>;
}

describe('Integration: Read-access auditing (T3.15)', () => {
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

  it('records READ audit entries for findUnique on configured readAuditModels', async () => {
    const auditClient = createAuditClient(rawPrisma, {
      models: ['Student'],
      readAuditModels: ['Student'],
      keys: { secret: masterKey },
    }) as unknown as AuditedTestClient;

    const student = await rawPrisma.student.create({
      data: {
        name: 'Sensitive Student',
        email: 'sensitive@school.edu',
        marks: 98,
      },
    });

    const readResult = await runWithAuditContext(
      { actorId: 'doctor-1', actorRole: 'HEALTH_OFFICER', requestId: 'req-read-unique-1' },
      () => auditClient.student.findUnique({ where: { id: student.id } }),
    );

    expect(readResult).toBeDefined();
    expect(readResult?.id).toBe(student.id);
    expect(readResult?.name).toBe('Sensitive Student');

    const logs = (await rawPrisma.auditLog.findMany({
      orderBy: { seq: 'asc' },
    })) as unknown as AuditLogRecord[];

    expect(logs).toHaveLength(1);
    const log = logs[0]!;
    expect(log.action).toBe('READ');
    expect(log.model).toBe('Student');
    expect(log.recordId).toBe(student.id);
    expect(log.actorId).toBe('doctor-1');
    expect(log.actorRole).toBe('HEALTH_OFFICER');
    expect(log.requestId).toBe('req-read-unique-1');
    expect(log.before).toBeNull();
    expect(log.diff).toBeNull();

    const afterData = typeof log.after === 'string' ? JSON.parse(log.after) : log.after;
    expect(afterData.email).toBe('sensitive@school.edu');
    expect(afterData.marks).toBe(98);

    const verifyRes = await verifyAuditChain({
      prisma: rawPrisma,
      keys: { secret: masterKey },
    });
    expect(verifyRes.valid).toBe(true);
  });

  it('redacts sensitive fields in READ audit entries', async () => {
    const auditClient = createAuditClient(rawPrisma, {
      models: ['Student'],
      readAuditModels: ['Student'],
      redactFields: ['marks'],
      keys: { secret: masterKey },
    }) as unknown as AuditedTestClient;

    const student = await rawPrisma.student.create({
      data: {
        name: 'Private Student',
        email: 'private@school.edu',
        marks: 100,
      },
    });

    const readResult = await runWithAuditContext(
      { actorId: 'user-1', actorRole: 'STAFF' },
      () => auditClient.student.findUnique({ where: { id: student.id } }),
    );

    expect(readResult?.marks).toBe(100);

    const logs = (await rawPrisma.auditLog.findMany()) as unknown as AuditLogRecord[];
    expect(logs).toHaveLength(1);
    const afterData = typeof logs[0]!.after === 'string' ? JSON.parse(logs[0]!.after) : logs[0]!.after;
    expect(afterData.marks).toMatch(/^\[REDACTED/);
    expect(afterData.name).toBe('Private Student');
  });

  it('records 1 READ audit entry per returned record for findMany', async () => {
    const auditClient = createAuditClient(rawPrisma, {
      models: ['Student'],
      readAuditModels: ['Student'],
      keys: { secret: masterKey },
    }) as unknown as AuditedTestClient;

    const s1 = await rawPrisma.student.create({
      data: { name: 'Batch 1', email: 'batch1@test.edu', marks: 80 },
    });
    const s2 = await rawPrisma.student.create({
      data: { name: 'Batch 2', email: 'batch2@test.edu', marks: 85 },
    });

    const results = await runWithAuditContext(
      { actorId: 'analyst-1', actorRole: 'ANALYST', requestId: 'req-batch' },
      () => auditClient.student.findMany({ where: { email: { contains: 'batch' } } }),
    );

    expect(results).toHaveLength(2);

    const logs = (await rawPrisma.auditLog.findMany({
      orderBy: { seq: 'asc' },
    })) as unknown as AuditLogRecord[];

    expect(logs).toHaveLength(2);
    expect(logs[0]!.action).toBe('READ');
    expect(logs[0]!.recordId).toBe(s1.id);
    expect(logs[1]!.action).toBe('READ');
    expect(logs[1]!.recordId).toBe(s2.id);

    const verifyRes = await verifyAuditChain({
      prisma: rawPrisma,
      keys: { secret: masterKey },
    });
    expect(verifyRes.valid).toBe(true);
  });

  it('does not create audit entries when findUnique or findMany returns no records', async () => {
    const auditClient = createAuditClient(rawPrisma, {
      models: ['Student'],
      readAuditModels: ['Student'],
      keys: { secret: masterKey },
    }) as unknown as AuditedTestClient;

    const resUnique = await runWithAuditContext(
      { actorId: 'user-1' },
      () => auditClient.student.findUnique({ where: { id: 'missing-id' } }),
    );
    expect(resUnique).toBeNull();

    const resMany = await runWithAuditContext(
      { actorId: 'user-1' },
      () => auditClient.student.findMany({ where: { name: 'missing-name' } }),
    );
    expect(resMany).toEqual([]);

    const logCount = await rawPrisma.auditLog.count();
    expect(logCount).toBe(0);
  });

  it('supports read-access auditing inside $auditedTransaction', async () => {
    const auditClient = createAuditClient(rawPrisma, {
      models: ['Student'],
      readAuditModels: ['Student'],
      keys: { secret: masterKey },
    }) as unknown as AuditedTestClient;

    const student = await rawPrisma.student.create({
      data: { name: 'Charlie', email: 'charlie@test.edu', marks: 75 },
    });

    await runWithAuditContext(
      { actorId: 'counselor-1', actorRole: 'COUNSELOR', requestId: 'req-tx-read' },
      () =>
        auditClient.$auditedTransaction(async (tx) => {
          const read = await tx.student.findUnique({ where: { id: student.id } });
          expect(read?.name).toBe('Charlie');

          await tx.student.update({
            where: { id: student.id },
            data: { marks: 90 },
          });
        }),
    );

    const logs = (await rawPrisma.auditLog.findMany({
      orderBy: { seq: 'asc' },
    })) as unknown as AuditLogRecord[];

    expect(logs).toHaveLength(2);
    expect(logs[0]!.action).toBe('READ');
    expect(logs[0]!.recordId).toBe(student.id);
    expect(logs[1]!.action).toBe('UPDATE');
    expect(logs[1]!.recordId).toBe(student.id);

    const verifyRes = await verifyAuditChain({
      prisma: rawPrisma,
      keys: { secret: masterKey },
    });
    expect(verifyRes.valid).toBe(true);
  });
});
