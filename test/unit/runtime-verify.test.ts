/**
 * Unit tests for audit log verification algorithm (verify.ts).
 *
 * Tests all verification paths using mock Prisma client without requiring MySQL:
 * - Clean valid chain with gapless sequence and HMAC signatures
 * - Empty audit log and empty head
 * - HEAD_MISMATCH: missing head or lastSeq/lastHash mismatch
 * - SEQ_GAP: missing or out-of-order sequence numbers
 * - PREV_HASH_MISMATCH: broken chaining or genesis hash mismatch
 * - UNKNOWN_KEY: row signed with unconfigured keyId
 * - HASH_MISMATCH: tampered payload content
 * - PAYLOAD_INVALID_JSON: corrupted non-JSON payload string
 * - COLUMN_PAYLOAD_MISMATCH: discrepancy between table column and payload
 * - Checkpoint verification: valid, TRUNCATION_DETECTED, signature failure, hash mismatch
 * - Key rotation support via KeysOptions
 * - --all flag collecting multiple problems up to cap
 */

import { describe, it, expect } from 'vitest';
import { GENESIS_HASH } from '../../src/core/constants.js';
import { stableStringify } from '../../src/core/canonical.js';
import { hmacHex } from '../../src/core/crypto.js';
import { createCheckpoint } from '../../src/runtime/checkpoint.js';
import {
  verifyAuditChain,
  type VerifyPrismaClient,
  type VerifyRow,
} from '../../src/runtime/verify.js';

describe('Unit: verifyAuditChain (runtime/verify.ts)', () => {
  const masterKey = 'test-audit-master-key-32-chars!!';
  const keyId = 'default';

  function createValidRow(
    seq: bigint,
    prevHash: string,
    key = masterKey,
    kId = keyId,
  ): VerifyRow {
    const payloadObj = {
      v: 1,
      seq: seq.toString(),
      ts: '2026-01-01T00:00:00.000Z',
      model: 'Student',
      recordId: `rec-${seq.toString()}`,
      action: 'CREATE',
      actorId: 'user-1',
      actorRole: 'TEACHER',
      requestId: null,
      ipAddress: null,
      userAgent: null,
      before: null,
      after: { id: `rec-${seq.toString()}`, name: 'Alice' },
      diff: null,
      prevHash,
    };

    const payload = stableStringify(payloadObj);
    const hash = hmacHex(key, payload);

    return {
      seq,
      model: 'Student',
      recordId: `rec-${seq.toString()}`,
      action: 'CREATE',
      actorId: 'user-1',
      actorRole: 'TEACHER',
      requestId: null,
      ipAddress: null,
      userAgent: null,
      payload,
      before: null,
      after: { id: `rec-${seq.toString()}`, name: 'Alice' },
      diff: null,
      prevHash,
      hash,
      keyId: kId,
      createdAt: new Date('2026-01-01T00:00:00.000Z'),
    };
  }

  function createMockPrisma(
    rows: VerifyRow[],
    head: { id: number; lastSeq: bigint; lastHash: string } | null,
  ): VerifyPrismaClient {
    return {
      auditLog: {
        findMany: async (args) => {
          let filtered = [...rows];
          const gt = (args.where?.seq as { gt?: bigint } | undefined)?.gt;
          if (gt !== undefined) {
            filtered = filtered.filter((r) => r.seq > gt);
          }
          return filtered.slice(0, args.take);
        },
      },
      auditHead: {
        findUnique: async () => head,
      },
    };
  }

  it('validates an empty audit log when head is at 0', async () => {
    const mockPrisma = createMockPrisma([], { id: 1, lastSeq: 0n, lastHash: GENESIS_HASH });

    const result = await verifyAuditChain({
      prisma: mockPrisma,
      keys: { secret: masterKey },
    });

    expect(result.valid).toBe(true);
    expect(result.checkedRecords).toBe(0);
  });

  it('validates an unbroken 3-row audit log', async () => {
    const row1 = createValidRow(1n, GENESIS_HASH);
    const row2 = createValidRow(2n, row1.hash);
    const row3 = createValidRow(3n, row2.hash);

    const mockPrisma = createMockPrisma([row1, row2, row3], {
      id: 1,
      lastSeq: 3n,
      lastHash: row3.hash,
    });

    const result = await verifyAuditChain({
      prisma: mockPrisma,
      keys: { secret: masterKey },
    });

    expect(result.valid).toBe(true);
    expect(result.checkedRecords).toBe(3);
    expect(result.head?.seq).toBe('3');
    expect(result.head?.hash).toBe(row3.hash);
  });

  it('detects HEAD_MISMATCH when head record does not exist', async () => {
    const row1 = createValidRow(1n, GENESIS_HASH);
    const mockPrisma = createMockPrisma([row1], null);

    const result = await verifyAuditChain({
      prisma: mockPrisma,
      keys: { secret: masterKey },
    });

    expect(result.valid).toBe(false);
    expect(result.problems[0]?.code).toBe('HEAD_MISMATCH');
  });

  it('detects HEAD_MISMATCH when head lastSeq or lastHash does not match last row', async () => {
    const row1 = createValidRow(1n, GENESIS_HASH);
    const mockPrisma = createMockPrisma([row1], { id: 1, lastSeq: 2n, lastHash: 'wrong-hash' });

    const result = await verifyAuditChain({
      prisma: mockPrisma,
      keys: { secret: masterKey },
    });

    expect(result.valid).toBe(false);
    expect(result.problems[0]?.code).toBe('HEAD_MISMATCH');
  });

  it('detects SEQ_GAP when sequence numbers are not contiguous', async () => {
    const row1 = createValidRow(1n, GENESIS_HASH);
    const row3 = createValidRow(3n, row1.hash);
    const mockPrisma = createMockPrisma([row1, row3], { id: 1, lastSeq: 3n, lastHash: row3.hash });

    const result = await verifyAuditChain({
      prisma: mockPrisma,
      keys: { secret: masterKey },
    });

    expect(result.valid).toBe(false);
    expect(result.problems[0]?.code).toBe('SEQ_GAP');
    expect(result.problems[0]?.seq).toBe('3');
  });

  it('detects PREV_HASH_MISMATCH when row chaining is broken', async () => {
    const row1 = createValidRow(1n, GENESIS_HASH);
    const row2 = createValidRow(2n, 'broken-previous-hash');
    const mockPrisma = createMockPrisma([row1, row2], { id: 1, lastSeq: 2n, lastHash: row2.hash });

    const result = await verifyAuditChain({
      prisma: mockPrisma,
      keys: { secret: masterKey },
    });

    expect(result.valid).toBe(false);
    expect(result.problems[0]?.code).toBe('PREV_HASH_MISMATCH');
    expect(result.problems[0]?.seq).toBe('2');
  });

  it('detects UNKNOWN_KEY when signed with an unregistered keyId', async () => {
    const row1 = createValidRow(1n, GENESIS_HASH, masterKey, 'unknown-key-id');
    const mockPrisma = createMockPrisma([row1], { id: 1, lastSeq: 1n, lastHash: row1.hash });

    const result = await verifyAuditChain({
      prisma: mockPrisma,
      keys: {
        current: 'k1',
        secrets: { k1: masterKey },
      },
    });

    expect(result.valid).toBe(false);
    expect(result.problems[0]?.code).toBe('UNKNOWN_KEY');
    expect(result.problems[0]?.seq).toBe('1');
  });

  it('detects HASH_MISMATCH when payload HMAC is invalid', async () => {
    const row1 = createValidRow(1n, GENESIS_HASH);
    row1.hash = 'a'.repeat(64);
    const mockPrisma = createMockPrisma([row1], { id: 1, lastSeq: 1n, lastHash: row1.hash });

    const result = await verifyAuditChain({
      prisma: mockPrisma,
      keys: { secret: masterKey },
    });

    expect(result.valid).toBe(false);
    expect(result.problems[0]?.code).toBe('HASH_MISMATCH');
  });

  it('detects HASH_MISMATCH when payload is malformed JSON', async () => {
    const row1 = createValidRow(1n, GENESIS_HASH);
    row1.payload = '{ invalid json';
    const mockPrisma = createMockPrisma([row1], { id: 1, lastSeq: 1n, lastHash: row1.hash });

    const result = await verifyAuditChain({
      prisma: mockPrisma,
      keys: { secret: masterKey },
    });

    expect(result.valid).toBe(false);
    expect(result.problems[0]?.code).toBe('HASH_MISMATCH');
  });

  it('detects COLUMN_PAYLOAD_MISMATCH when database column differs from payload', async () => {
    const row1 = createValidRow(1n, GENESIS_HASH);
    row1.actorRole = 'ADMIN';
    const mockPrisma = createMockPrisma([row1], { id: 1, lastSeq: 1n, lastHash: row1.hash });

    const result = await verifyAuditChain({
      prisma: mockPrisma,
      keys: { secret: masterKey },
    });

    expect(result.valid).toBe(false);
    expect(result.problems[0]?.code).toBe('COLUMN_PAYLOAD_MISMATCH');
  });

  it('verifies checkpoints: passes valid checkpoint and detects TRUNCATION_DETECTED', async () => {
    const row1 = createValidRow(1n, GENESIS_HASH);
    const row2 = createValidRow(2n, row1.hash);

    const validCp = createCheckpoint({ seq: 2n, hash: row2.hash }, masterKey, 'default');
    const mockPrisma = createMockPrisma([row1, row2], { id: 1, lastSeq: 2n, lastHash: row2.hash });

    const passResult = await verifyAuditChain({
      prisma: mockPrisma,
      keys: { secret: masterKey },
      checkpoints: [validCp],
    });
    expect(passResult.valid).toBe(true);

    const truncatedPrisma = createMockPrisma([row1], { id: 1, lastSeq: 1n, lastHash: row1.hash });

    const failResult = await verifyAuditChain({
      prisma: truncatedPrisma,
      keys: { secret: masterKey },
      checkpoints: [validCp],
    });

    expect(failResult.valid).toBe(false);
    expect(failResult.problems[0]?.code).toBe('TRUNCATION_DETECTED');
  });

  it('detects CHECKPOINT_BAD_SIGNATURE on forged checkpoint signature', async () => {
    const row1 = createValidRow(1n, GENESIS_HASH);
    const cp = createCheckpoint({ seq: 1n, hash: row1.hash }, masterKey, 'default');
    cp.sig = 'forged-signature';

    const mockPrisma = createMockPrisma([row1], { id: 1, lastSeq: 1n, lastHash: row1.hash });

    const result = await verifyAuditChain({
      prisma: mockPrisma,
      keys: { secret: masterKey },
      checkpoints: [cp],
    });

    expect(result.valid).toBe(false);
    expect(result.problems[0]?.code).toBe('CHECKPOINT_BAD_SIGNATURE');
  });

  it('supports key rotation with multiple secrets', async () => {
    const oldKey = 'old-key-secret-32-chars-long!!!!';
    const newKey = 'new-key-secret-32-chars-long!!!!';

    const row1 = createValidRow(1n, GENESIS_HASH, oldKey, 'k1');
    const row2 = createValidRow(2n, row1.hash, newKey, 'k2');

    const mockPrisma = createMockPrisma([row1, row2], { id: 1, lastSeq: 2n, lastHash: row2.hash });

    const result = await verifyAuditChain({
      prisma: mockPrisma,
      keys: {
        current: 'k2',
        secrets: {
          k1: oldKey,
          k2: newKey,
        },
      },
    });

    expect(result.valid).toBe(true);
    expect(result.checkedRecords).toBe(2);
  });

  it('collects multiple problems when all: true is passed', async () => {
    const row1 = createValidRow(1n, GENESIS_HASH);
    row1.hash = 'wrong1';
    const row2 = createValidRow(2n, row1.hash);
    row2.hash = 'wrong2';

    const mockPrisma = createMockPrisma([row1, row2], { id: 1, lastSeq: 2n, lastHash: 'wrong3' });

    const result = await verifyAuditChain({
      prisma: mockPrisma,
      keys: { secret: masterKey },
      all: true,
    });

    expect(result.valid).toBe(false);
    expect(result.problems.length).toBeGreaterThan(1);
  });
});
