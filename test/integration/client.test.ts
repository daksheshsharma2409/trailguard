import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { PrismaClient } from './generated/index.js';
import { createAuditClient } from '../../src/runtime/client.js';
import { runWithAuditContext } from '../../src/runtime/context.js';
import { resetHeadCache } from '../../src/runtime/append.js';

describe('Integration: createAuditClient', () => {
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
    await rawPrisma.auditLog.deleteMany();
    await rawPrisma.auditHead.deleteMany();
    await rawPrisma.student.deleteMany();
    resetHeadCache();
  });

  it('audits create operation with correct before/after/diff/actor and return shape', async () => {
    const auditClient = createAuditClient(rawPrisma, {
      models: ['Student'],
      keys: { secret: masterKey },
    });

    const result = await runWithAuditContext(
      { actorId: 'teacher-10', actorRole: 'TEACHER', requestId: 'req-c-1' },
      () =>
        auditClient.student.create({
          data: {
            name: 'Alice Cooper',
            email: 'alice@example.com',
            phone: '555-1111',
            marks: 90,
          },
        }),
    );

    // Matches raw Prisma return shape
    expect(result.id).toBeDefined();
    expect(result.name).toBe('Alice Cooper');
    expect(result.email).toBe('alice@example.com');
    expect(result.marks).toBe(90);

    // Verify AuditLog entry
    const logs = await rawPrisma.auditLog.findMany();
    expect(logs).toHaveLength(1);
    const log = logs[0];
    expect(log).toBeDefined();
    if (!log) return;

    expect(log.model).toBe('Student');
    expect(log.recordId).toBe(result.id);
    expect(log.action).toBe('CREATE');
    expect(log.actorId).toBe('teacher-10');
    expect(log.actorRole).toBe('TEACHER');
    expect(log.requestId).toBe('req-c-1');
    expect(log.before).toBeNull();
    expect(log.diff).toBeNull();

    const afterJson = log.after as Record<string, unknown>;
    expect(afterJson.name).toBe('Alice Cooper');
    expect(afterJson.email).toBe('alice@example.com');
  });

  it('respects select on create and still records full state in audit log', async () => {
    const auditClient = createAuditClient(rawPrisma, {
      models: ['Student'],
      keys: { secret: masterKey },
    });

    const result = await runWithAuditContext(
      { actorId: 'admin-1', actorRole: 'ADMIN' },
      () =>
        auditClient.student.create({
          data: {
            name: 'Bob Ross',
            email: 'bob@example.com',
            phone: '555-2222',
            marks: 100,
          },
          select: {
            id: true,
            name: true,
          },
        }),
    );

    // Return value is shaped by select
    expect(result).toEqual({ id: result.id, name: 'Bob Ross' });
    expect('email' in result).toBe(false);

    // AuditLog contains full record
    const [log] = await rawPrisma.auditLog.findMany();
    expect(log).toBeDefined();
    const afterJson = log?.after as Record<string, unknown>;
    expect(afterJson.email).toBe('bob@example.com');
    expect(afterJson.marks).toBe(100);
  });

  it('audits update operation with before/after/diff', async () => {
    const student = await rawPrisma.student.create({
      data: {
        name: 'Charlie',
        email: 'charlie@example.com',
        phone: '111',
        marks: 70,
      },
    });

    const auditClient = createAuditClient(rawPrisma, {
      models: ['Student'],
      keys: { secret: masterKey },
    });

    const updated = await runWithAuditContext(
      { actorId: 'teacher-2', actorRole: 'TEACHER' },
      () =>
        auditClient.student.update({
          where: { id: student.id },
          data: {
            name: 'Charles',
            marks: 85,
          },
        }),
    );

    expect(updated.name).toBe('Charles');
    expect(updated.marks).toBe(85);

    const logs = await rawPrisma.auditLog.findMany();
    expect(logs).toHaveLength(1);
    const log = logs[0];
    expect(log).toBeDefined();
    if (!log) return;

    expect(log.action).toBe('UPDATE');
    const beforeJson = log.before as Record<string, unknown>;
    const afterJson = log.after as Record<string, unknown>;
    const diffJson = log.diff as Record<string, { old: unknown; new: unknown }>;

    expect(beforeJson.name).toBe('Charlie');
    expect(beforeJson.marks).toBe(70);

    expect(afterJson.name).toBe('Charles');
    expect(afterJson.marks).toBe(85);

    expect(diffJson).toEqual({
      name: { old: 'Charlie', new: 'Charles' },
      marks: { old: 70, new: 85 },
    });
  });

  it('audits delete operation with before state and null after', async () => {
    const student = await rawPrisma.student.create({
      data: {
        name: 'David',
        email: 'david@example.com',
      },
    });

    const auditClient = createAuditClient(rawPrisma, {
      models: ['Student'],
      keys: { secret: masterKey },
    });

    const deleted = await runWithAuditContext(
      { actorId: 'admin-1', actorRole: 'ADMIN' },
      () =>
        auditClient.student.delete({
          where: { id: student.id },
        }),
    );

    expect(deleted.id).toBe(student.id);

    const logs = await rawPrisma.auditLog.findMany();
    expect(logs).toHaveLength(1);
    const log = logs[0];
    expect(log).toBeDefined();
    if (!log) return;

    expect(log.action).toBe('DELETE');
    expect(log.after).toBeNull();
    expect(log.diff).toBeNull();
    const beforeJson = log.before as Record<string, unknown>;
    expect(beforeJson.name).toBe('David');
  });

  it('audits upsert operation for both CREATE and UPDATE paths', async () => {
    const auditClient = createAuditClient(rawPrisma, {
      models: ['Student'],
      keys: { secret: masterKey },
    });

    // 1. Upsert insert path
    const created = await runWithAuditContext(
      { actorId: 'user-1' },
      () =>
        auditClient.student.upsert({
          where: { email: 'eve@example.com' },
          create: {
            name: 'Eve',
            email: 'eve@example.com',
            marks: 50,
          },
          update: {
            name: 'Eve Updated',
          },
        }),
    );

    expect(created.name).toBe('Eve');
    let logs = await rawPrisma.auditLog.findMany();
    expect(logs).toHaveLength(1);
    expect(logs[0]?.action).toBe('CREATE');
    expect(logs[0]?.before).toBeNull();

    // 2. Upsert update path
    const updated = await runWithAuditContext(
      { actorId: 'user-2' },
      () =>
        auditClient.student.upsert({
          where: { email: 'eve@example.com' },
          create: {
            name: 'Eve',
            email: 'eve@example.com',
          },
          update: {
            name: 'Eve Senior',
            marks: 90,
          },
        }),
    );

    expect(updated.name).toBe('Eve Senior');
    logs = await rawPrisma.auditLog.findMany({ orderBy: { seq: 'asc' } });
    expect(logs).toHaveLength(2);
    expect(logs[1]?.action).toBe('UPDATE');
    const diff = logs[1]?.diff as Record<string, { old: unknown; new: unknown }>;
    expect(diff.name).toEqual({ old: 'Eve', new: 'Eve Senior' });
    expect(diff.marks).toEqual({ old: 50, new: 90 });
  });

  it('redacts sensitive fields in the audit log', async () => {
    const auditClient = createAuditClient(rawPrisma, {
      models: ['Student'],
      keys: { secret: masterKey },
      redactFields: ['phone'],
    });

    await runWithAuditContext(
      { actorId: 'staff-1' },
      () =>
        auditClient.student.create({
          data: {
            name: 'Frank',
            email: 'frank@example.com',
            phone: 'secret-phone-number',
          },
        }),
    );

    const [log] = await rawPrisma.auditLog.findMany();
    expect(log).toBeDefined();
    const after = log?.after as Record<string, unknown>;
    expect(after.phone).toMatch(/^\[REDACTED:[0-9a-f]{4}\]$/);
    expect(log?.payload).not.toContain('secret-phone-number');
  });

  it('rolls back both business write and audit row when testHooks.beforeAppend throws', async () => {
    const auditClient = createAuditClient(rawPrisma, {
      models: ['Student'],
      keys: { secret: masterKey },
      testHooks: {
        beforeAppend: () => {
          throw new Error('Simulated failure right before appending audit log');
        },
      },
    });

    await expect(
      runWithAuditContext({ actorId: 'user-1' }, () =>
        auditClient.student.create({
          data: {
            name: 'Grace Hopper',
            email: 'grace@example.com',
          },
        }),
      ),
    ).rejects.toThrow('Simulated failure right before appending audit log');

    // Both student and audit log rolled back
    const students = await rawPrisma.student.findMany();
    const logs = await rawPrisma.auditLog.findMany();

    expect(students).toHaveLength(0);
    expect(logs).toHaveLength(0);
  });

  it('non-audited model passes through without creating audit rows', async () => {
    // Only Student is configured as audited. AuditHead is not.
    const auditClient = createAuditClient(rawPrisma, {
      models: ['Student'],
      keys: { secret: masterKey },
    });

    // Create AuditHead directly through the extended client
    await runWithAuditContext({ actorId: 'system' }, () =>
      auditClient.auditHead.createMany({
        data: [{ id: 1, lastSeq: 0n, lastHash: '0'.repeat(64) }],
      }),
    );

    const logs = await rawPrisma.auditLog.findMany();
    expect(logs).toHaveLength(0);
  });
});
