/**
 * Checkpoints engine for trailguard runtime audit log.
 *
 * Checkpoints are signed external witnesses emitted on cadence or on demand,
 * protecting against database truncation attacks.
 *
 * @see context.md §7.8
 */

import { promises as fs } from 'node:fs';
import { CHECKPOINT_SIG_PREFIX } from '../core/constants.js';
import { hmacHex, timingSafeEqualHex } from '../core/crypto.js';
import type { Checkpoint, CheckpointSink } from '../core/types.js';

/**
 * Creates a signed Checkpoint for an audit log entry.
 *
 * @param entry - Audit log entry with seq and hash.
 * @param key   - HMAC secret key.
 * @param keyId - ID of the signing key.
 * @param now   - Optional date for timestamp generation (injectable clock for tests).
 */
export function createCheckpoint(
  entry: { seq: bigint | string; hash: string },
  key: string | Buffer,
  keyId: string,
  now?: Date,
): Checkpoint {
  const seq = entry.seq.toString();
  const hash = entry.hash;
  const ts = (now ?? new Date()).toISOString();
  const sigPayload = `${CHECKPOINT_SIG_PREFIX}${seq}:${hash}:${ts}:${keyId}`;
  const sig = hmacHex(key, sigPayload);

  return {
    v: 1,
    seq,
    hash,
    ts,
    keyId,
    sig,
  };
}

/**
 * Verifies the HMAC signature of a Checkpoint.
 */
export function verifyCheckpointSignature(
  checkpoint: Checkpoint,
  key: string | Buffer,
): boolean {
  const sigPayload = `${CHECKPOINT_SIG_PREFIX}${checkpoint.seq}:${checkpoint.hash}:${checkpoint.ts}:${checkpoint.keyId}`;
  const expectedSig = hmacHex(key, sigPayload);
  return timingSafeEqualHex(expectedSig, checkpoint.sig);
}

/**
 * Checkpoint sink that appends newline-delimited JSON (JSONL) to a file.
 */
export function fileSink(filePath: string): CheckpointSink {
  return async (checkpoint: Checkpoint): Promise<void> => {
    const line = JSON.stringify(checkpoint) + '\n';
    await fs.appendFile(filePath, line, 'utf8');
  };
}

/**
 * Checkpoint sink that writes JSONL to standard output.
 */
export function stdoutSink(): CheckpointSink {
  return (checkpoint: Checkpoint): void => {
    process.stdout.write(JSON.stringify(checkpoint) + '\n');
  };
}

/**
 * Checkpoint sink that delegates to a callback function.
 */
export function callbackSink(
  fn: (checkpoint: Checkpoint) => void | Promise<void>,
): CheckpointSink {
  return (checkpoint: Checkpoint): void | Promise<void> => {
    return fn(checkpoint);
  };
}
