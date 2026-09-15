import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { PrismaClient } from './generated/index.js';
import { appendAuditEntries, resetHeadCache, type AuditPrismaTx } from '../../src/runtime/append.js';
import { GENESIS_HASH } from '../../src/core/constants.js';
import { hmacHex } from '../../src/core/crypto.js';

describe('Integration: appendAuditEntries', () => {
  let prisma: PrismaClient;
  const testKey = 'test-audit-master-hmac-key-32!';
  const testKeyId = 'k1';

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
    resetHeadCache();
  });

  it('appends first entry with seq 1, GENESIS_HASH, and valid HMAC payload', async () => {
    const created = await prisma.$transaction(async (tx) => {
      return appendAuditEntries(
        tx as unknown as AuditPrismaTx,
        [
          {
            model: 'Student',
            recordId: 'std-100',
            action: 'CREATE',
            actorId: 'teacher-1',
            actorRole: 'TEACHER',
            requestId: 'req-001',
            ipAddress: '127.0.0.1',
            userAgent: 'Vitest/2.0',
            before: null,
            after: { id: 'std-100', name: 'Bob' },
            diff: null,
          },
        ],
        {
          key: testKey,
          keyId: testKeyId,
        },
      );
    });

    expect(created).toHaveLength(1);
    const row = created[0];
    expect(row).toBeDefined();
    if (!row) return;

    expect(row.seq).toBe(1n);
    expect(row.prevHash).toBe(GENESIS_HASH);

    // Verify HMAC recomputation
    const expectedHash = hmacHex(testKey, row.payload);
    expect(row.hash).toBe(expectedHash);

    // Verify payload JSON matches columns
    const parsedPayload = JSON.parse(row.payload) as Record<string, unknown>;
    expect(parsedPayload.v).toBe(1);
    expect(parsedPayload.seq).toBe('1');
    expect(parsedPayload.model).toBe(row.model);
    expect(parsedPayload.recordId).toBe(row.recordId);
    expect(parsedPayload.action).toBe(row.action);
    expect(parsedPayload.actorId).toBe(row.actorId);
    expect(parsedPayload.actorRole).toBe(row.actorRole);
    expect(parsedPayload.requestId).toBe(row.requestId);
    expect(parsedPayload.ipAddress).toBe(row.ipAddress);
    expect(parsedPayload.userAgent).toBe(row.userAgent);
    expect(parsedPayload.prevHash).toBe(row.prevHash);
    expect(parsedPayload.after).toEqual(row.after);

    // Verify AuditHead table in DB
    const head = await prisma.auditHead.findUnique({ where: { id: 1 } });
    expect(head).not.toBeNull();
    expect(head?.lastSeq).toBe(1n);
    expect(head?.lastHash).toBe(row.hash);
  });

  it('appends successive entries with gapless seq and hash chaining', async () => {
    // Write entry 1
    const [row1] = await prisma.$transaction(async (tx) => {
      return appendAuditEntries(
        tx as unknown as AuditPrismaTx,
        [
          {
            model: 'Student',
            recordId: 'std-1',
            action: 'CREATE',
            after: { id: 'std-1', name: 'Alice' },
          },
        ],
        { key: testKey, keyId: testKeyId },
      );
    });
    expect(row1).toBeDefined();
    if (!row1) return;

    // Write entries 2 and 3 in a subsequent transaction
    const [row2, row3] = await prisma.$transaction(async (tx) => {
      return appendAuditEntries(
        tx as unknown as AuditPrismaTx,
        [
          {
            model: 'Student',
            recordId: 'std-1',
            action: 'UPDATE',
            before: { id: 'std-1', name: 'Alice' },
            after: { id: 'std-1', name: 'Alicia' },
            diff: { name: { old: 'Alice', new: 'Alicia' } },
          },
          {
            model: 'Student',
            recordId: 'std-2',
            action: 'CREATE',
            after: { id: 'std-2', name: 'Bob' },
          },
        ],
        { key: testKey, keyId: testKeyId },
      );
    });

    expect(row2).toBeDefined();
    expect(row3).toBeDefined();
    if (!row2 || !row3) return;

    // Check gapless sequences: 1 -> 2 -> 3
    expect(row1.seq).toBe(1n);
    expect(row2.seq).toBe(2n);
    expect(row3.seq).toBe(3n);

    // Check hash chaining
    expect(row1.prevHash).toBe(GENESIS_HASH);
    expect(row2.prevHash).toBe(row1.hash);
    expect(row3.prevHash).toBe(row2.hash);

    // Recomputed hashes match
    expect(row2.hash).toBe(hmacHex(testKey, row2.payload));
    expect(row3.hash).toBe(hmacHex(testKey, row3.payload));

    // AuditHead updated to row3
    const head = await prisma.auditHead.findUnique({ where: { id: 1 } });
    expect(head?.lastSeq).toBe(3n);
    expect(head?.lastHash).toBe(row3.hash);

    // Query all logs from DB
    const allLogs = await prisma.auditLog.findMany({ orderBy: { seq: 'asc' } });
    expect(allLogs).toHaveLength(3);
    expect(allLogs[0]?.hash).toBe(row1.hash);
    expect(allLogs[1]?.hash).toBe(row2.hash);
    expect(allLogs[2]?.hash).toBe(row3.hash);
  });
});
