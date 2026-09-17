import { describe, it, expect } from 'vitest';
import { promises as fs } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  createCheckpoint,
  verifyCheckpointSignature,
  fileSink,
  callbackSink,
} from '../../src/runtime/checkpoint.js';
import type { Checkpoint } from '../../src/core/types.js';

describe('runtime/checkpoint', () => {
  const masterKey = 'test-checkpoint-key-secret-32-chars!';
  const keyId = 'k1';

  it('creates valid signed checkpoint', () => {
    const cp = createCheckpoint(
      { seq: 42n, hash: 'abc123hash' },
      masterKey,
      keyId,
      new Date('2026-10-26T12:00:00.000Z'),
    );

    expect(cp.v).toBe(1);
    expect(cp.seq).toBe('42');
    expect(cp.hash).toBe('abc123hash');
    expect(cp.ts).toBe('2026-10-26T12:00:00.000Z');
    expect(cp.keyId).toBe('k1');
    expect(cp.sig).toBeDefined();

    const isValid = verifyCheckpointSignature(cp, masterKey);
    expect(isValid).toBe(true);
  });

  it('rejects forged checkpoint with invalid signature', () => {
    const cp = createCheckpoint(
      { seq: 1n, hash: 'validhash' },
      masterKey,
      keyId,
    );

    // Tamper with seq
    const forged = { ...cp, seq: '2' };
    expect(verifyCheckpointSignature(forged, masterKey)).toBe(false);

    // Tamper with key
    expect(verifyCheckpointSignature(cp, 'wrong-key')).toBe(false);
  });

  it('fileSink appends JSONL lines', async () => {
    const filePath = join(tmpdir(), `checkpoints-${String(Date.now())}.jsonl`);
    const sink = fileSink(filePath);

    const cp1 = createCheckpoint({ seq: 1n, hash: 'hash1' }, masterKey, keyId);
    const cp2 = createCheckpoint({ seq: 2n, hash: 'hash2' }, masterKey, keyId);

    await sink(cp1);
    await sink(cp2);

    const content = await fs.readFile(filePath, 'utf8');
    const lines = content.trim().split('\n');
    expect(lines).toHaveLength(2);

    const parsed1 = JSON.parse(lines[0] ?? '{}') as Checkpoint;
    const parsed2 = JSON.parse(lines[1] ?? '{}') as Checkpoint;

    expect(parsed1.seq).toBe('1');
    expect(parsed2.seq).toBe('2');

    await fs.unlink(filePath);
  });

  it('callbackSink forwards checkpoints', async () => {
    const received: Checkpoint[] = [];
    const sink = callbackSink((cp) => {
      received.push(cp);
    });

    const cp = createCheckpoint({ seq: 10n, hash: 'hash10' }, masterKey, keyId);
    await sink(cp);

    expect(received).toHaveLength(1);
    expect(received[0]?.seq).toBe('10');
  });
});
