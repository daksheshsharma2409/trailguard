import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { PrismaClient } from './generated/index.js';
import { createAuditClient } from '../../src/runtime/client.js';
import { runWithAuditContext } from '../../src/runtime/context.js';
import { resetHeadCache } from '../../src/runtime/append.js';
import { verifyAuditChain } from '../../src/runtime/verify.js';

describe('Integration: Concurrency & Atomicity', () => {
  let rawPrisma: PrismaClient;
  const masterKey = 'concurrency-test-key-32-chars-long!';

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

  describe('Atomicity', () => {
    it('rolls back business create when testHooks.beforeAppend throws', async () => {
      const auditClient = createAuditClient(rawPrisma, {
        models: ['Student'],
        keys: { secret: masterKey },
        testHooks: {
          beforeAppend: () => {
            throw new Error('Simulated failure during beforeAppend in CREATE');
          },
        },
      });

      await expect(
        runWithAuditContext(
          { actorId: 'admin-1', actorRole: 'ADMIN' },
          () =>
            auditClient.student.create({
              data: {
                id: 'atom-std-create',
                name: 'Atomic Create',
                email: 'atomic.create@example.com',
                marks: 85,
              },
            }),
        ),
      ).rejects.toThrow('Simulated failure during beforeAppend in CREATE');

      // Assert Student was NOT saved
      const student = await rawPrisma.student.findUnique({
        where: { id: 'atom-std-create' },
      });
      expect(student).toBeNull();

      // Assert no audit row created
      const logs = await rawPrisma.auditLog.findMany();
      expect(logs).toHaveLength(0);
    });

    it('rolls back business update when testHooks.beforeAppend throws', async () => {
      await rawPrisma.student.create({
        data: {
          id: 'atom-std-update',
          name: 'Original Name',
          email: 'atomic.update@example.com',
          marks: 70,
        },
      });

      const auditClient = createAuditClient(rawPrisma, {
        models: ['Student'],
        keys: { secret: masterKey },
        testHooks: {
          beforeAppend: () => {
            throw new Error('Simulated failure during beforeAppend in UPDATE');
          },
        },
      });

      await expect(
        runWithAuditContext(
          { actorId: 'admin-1', actorRole: 'ADMIN' },
          () =>
            auditClient.student.update({
              where: { id: 'atom-std-update' },
              data: {
                name: 'Modified Name That Should Roll Back',
                marks: 99,
              },
            }),
        ),
      ).rejects.toThrow('Simulated failure during beforeAppend in UPDATE');

      // Assert Student retained original values
      const student = await rawPrisma.student.findUnique({
        where: { id: 'atom-std-update' },
      });
      expect(student).not.toBeNull();
      expect(student?.name).toBe('Original Name');
      expect(student?.marks).toBe(70);

      // Assert no audit row created
      const logs = await rawPrisma.auditLog.findMany();
      expect(logs).toHaveLength(0);
    });

    it('rolls back business delete when testHooks.beforeAppend throws', async () => {
      await rawPrisma.student.create({
        data: {
          id: 'atom-std-delete',
          name: 'To Be Deleted',
          email: 'atomic.delete@example.com',
          marks: 75,
        },
      });

      const auditClient = createAuditClient(rawPrisma, {
        models: ['Student'],
        keys: { secret: masterKey },
        testHooks: {
          beforeAppend: () => {
            throw new Error('Simulated failure during beforeAppend in DELETE');
          },
        },
      });

      await expect(
        runWithAuditContext(
          { actorId: 'admin-1', actorRole: 'ADMIN' },
          () =>
            auditClient.student.delete({
              where: { id: 'atom-std-delete' },
            }),
        ),
      ).rejects.toThrow('Simulated failure during beforeAppend in DELETE');

      // Assert Student still exists
      const student = await rawPrisma.student.findUnique({
        where: { id: 'atom-std-delete' },
      });
      expect(student).not.toBeNull();
      expect(student?.id).toBe('atom-std-delete');

      // Assert no audit row created
      const logs = await rawPrisma.auditLog.findMany();
      expect(logs).toHaveLength(0);
    });
  });

  describe('Concurrency', () => {
    it(
      'handles 50 parallel updates without gaps, duplicates, or deadlocks',
      async () => {
        const studentCount = 50;
        const studentIds: string[] = [];

        // Pre-create 50 students directly
        for (let i = 1; i <= studentCount; i++) {
          const strI = String(i);
          const id = `student-p-${strI.padStart(3, '0')}`;
          studentIds.push(id);
          await rawPrisma.student.create({
            data: {
              id,
              name: `Student ${strI}`,
              email: `student.${strI}@example.com`,
              marks: 50,
            },
          });
        }

        const auditClient = createAuditClient(rawPrisma, {
          models: ['Student'],
          keys: { secret: masterKey },
          tx: {
            maxWait: 15000,
            timeout: 20000,
          },
        });

        // Execute 50 parallel updates concurrently
        const updatePromises = studentIds.map((id, index) => {
          const strIdx = String(index + 1);
          return runWithAuditContext(
            {
              actorId: `teacher-${strIdx}`,
              actorRole: 'TEACHER',
              requestId: `req-update-${strIdx}`,
            },
            () =>
              auditClient.student.update({
                where: { id },
                data: {
                  marks: 80 + (index % 20),
                },
              }),
          );
        });

        const results = await Promise.all(updatePromises);
        expect(results).toHaveLength(studentCount);

        // Fetch all audit logs ordered by seq
        const auditLogs = await rawPrisma.auditLog.findMany({
          orderBy: { seq: 'asc' },
        });

        expect(auditLogs).toHaveLength(studentCount);

        // Verify contiguous sequences and uniqueness
        const seqSet = new Set<bigint>();
        for (let i = 0; i < auditLogs.length; i++) {
          const log = auditLogs[i];
          if (!log) continue;
          expect(log.seq).toBe(BigInt(i + 1));
          expect(seqSet.has(log.seq)).toBe(false);
          seqSet.add(log.seq);
          expect(log.action).toBe('UPDATE');
        }
        expect(seqSet.size).toBe(studentCount);

        // Verify the entire audit chain cryptographic integrity
        const verifyResult = await verifyAuditChain({
          prisma: rawPrisma,
          keys: { secret: masterKey },
        });

        expect(verifyResult.valid).toBe(true);
        expect(verifyResult.checkedRecords).toBe(studentCount);
        expect(verifyResult.error).toBeUndefined();
      },
      30000,
    );

    it(
      'handles a mixed 60-op create/update/delete burst with valid chain and contiguous seqs',
      async () => {
        // Prepare 40 existing students: 20 will be updated, 20 will be deleted
        const updateStudentIds: string[] = [];
        const deleteStudentIds: string[] = [];

        for (let i = 1; i <= 20; i++) {
          const strI = String(i);
          const uId = `burst-upd-${strI}`;
          updateStudentIds.push(uId);
          await rawPrisma.student.create({
            data: {
              id: uId,
              name: `Burst Update ${strI}`,
              email: `burst.upd.${strI}@example.com`,
              marks: 60,
            },
          });

          const dId = `burst-del-${strI}`;
          deleteStudentIds.push(dId);
          await rawPrisma.student.create({
            data: {
              id: dId,
              name: `Burst Delete ${strI}`,
              email: `burst.del.${strI}@example.com`,
              marks: 60,
            },
          });
        }

        const auditClient = createAuditClient(rawPrisma, {
          models: ['Student'],
          keys: { secret: masterKey },
          tx: {
            maxWait: 15000,
            timeout: 20000,
          },
        });

        // 60 operations total: 20 creates, 20 updates, 20 deletes
        const mixedOps: Array<Promise<unknown>> = [];

        // 20 creates
        for (let i = 1; i <= 20; i++) {
          const strI = String(i);
          mixedOps.push(
            runWithAuditContext(
              {
                actorId: `creator-${strI}`,
                actorRole: 'ADMIN',
                requestId: `req-create-${strI}`,
              },
              () =>
                auditClient.student.create({
                  data: {
                    id: `burst-create-${strI}`,
                    name: `Burst Create ${strI}`,
                    email: `burst.new.${strI}@example.com`,
                    marks: 95,
                  },
                }),
            ),
          );
        }

        // 20 updates
        for (let i = 0; i < 20; i++) {
          const uId = updateStudentIds[i]!;
          const strIdx = String(i + 1);
          mixedOps.push(
            runWithAuditContext(
              {
                actorId: `updater-${strIdx}`,
                actorRole: 'TEACHER',
                requestId: `req-update-${strIdx}`,
              },
              () =>
                auditClient.student.update({
                  where: { id: uId },
                  data: { marks: 100 },
                }),
            ),
          );
        }

        // 20 deletes
        for (let i = 0; i < 20; i++) {
          const dId = deleteStudentIds[i]!;
          const strIdx = String(i + 1);
          mixedOps.push(
            runWithAuditContext(
              {
                actorId: `deleter-${strIdx}`,
                actorRole: 'ADMIN',
                requestId: `req-delete-${strIdx}`,
              },
              () =>
                auditClient.student.delete({
                  where: { id: dId },
                }),
            ),
          );
        }

        // Execute all 60 mixed operations concurrently
        const results = await Promise.all(mixedOps);
        expect(results).toHaveLength(60);

        // Fetch all audit logs ordered by seq
        const auditLogs = await rawPrisma.auditLog.findMany({
          orderBy: { seq: 'asc' },
        });

        expect(auditLogs).toHaveLength(60);

        // Count operations by action
        const actionCounts: Record<string, number> = {};
        const seqSet = new Set<bigint>();
        for (let i = 0; i < auditLogs.length; i++) {
          const log = auditLogs[i];
          if (!log) continue;
          expect(log.seq).toBe(BigInt(i + 1));
          expect(seqSet.has(log.seq)).toBe(false);
          seqSet.add(log.seq);
          actionCounts[log.action] = (actionCounts[log.action] ?? 0) + 1;
        }

        expect(seqSet.size).toBe(60);
        expect(actionCounts['CREATE']).toBe(20);
        expect(actionCounts['UPDATE']).toBe(20);
        expect(actionCounts['DELETE']).toBe(20);

        // Verify the entire chain
        const verifyResult = await verifyAuditChain({
          prisma: rawPrisma,
          keys: { secret: masterKey },
        });

        expect(verifyResult.valid).toBe(true);
        expect(verifyResult.checkedRecords).toBe(60);
        expect(verifyResult.error).toBeUndefined();
      },
      30000,
    );
  });
});
