/**
 * Unit tests for T1.2: Constants + types.
 *
 * Acceptance criteria:
 * - GENESIS_HASH, PAYLOAD_VERSION, table names exist and have correct values
 * - Types are re-exported from src/index.ts and src/scan/index.ts
 *   (verified by tsc --noEmit which includes both entry points)
 */
import { describe, it, expect } from 'vitest';
import {
  GENESIS_HASH,
  PAYLOAD_VERSION,
  AUDIT_LOG_TABLE,
  AUDIT_HEAD_TABLE,
  AUDIT_HEAD_ID,
  DEFAULT_KEY_ENV,
  DEFAULT_KEY_ID,
  MAX_PAGE_SIZE,
  VERIFY_BATCH_SIZE,
  DEFAULT_MAX_BULK_ROWS,
  CHECKPOINT_SIG_PREFIX,
} from '../../src/core/constants.js';

describe('Constants', () => {
  it('GENESIS_HASH is 64 zeros', () => {
    expect(GENESIS_HASH).toBe('0'.repeat(64));
    expect(GENESIS_HASH).toHaveLength(64);
  });

  it('PAYLOAD_VERSION is 1', () => {
    expect(PAYLOAD_VERSION).toBe(1);
  });

  it('table names are stable strings', () => {
    expect(AUDIT_LOG_TABLE).toBe('trailguard_audit_log');
    expect(AUDIT_HEAD_TABLE).toBe('trailguard_audit_head');
  });

  it('AUDIT_HEAD_ID is 1', () => {
    expect(AUDIT_HEAD_ID).toBe(1);
  });

  it('DEFAULT_KEY_ENV is TRAILGUARD_KEY', () => {
    expect(DEFAULT_KEY_ENV).toBe('TRAILGUARD_KEY');
  });

  it('DEFAULT_KEY_ID is "default"', () => {
    expect(DEFAULT_KEY_ID).toBe('default');
  });

  it('MAX_PAGE_SIZE is 200', () => {
    expect(MAX_PAGE_SIZE).toBe(200);
  });

  it('VERIFY_BATCH_SIZE is 1000', () => {
    expect(VERIFY_BATCH_SIZE).toBe(1000);
  });

  it('DEFAULT_MAX_BULK_ROWS is 1000', () => {
    expect(DEFAULT_MAX_BULK_ROWS).toBe(1000);
  });

  it('CHECKPOINT_SIG_PREFIX has the expected value', () => {
    expect(CHECKPOINT_SIG_PREFIX).toBe('trailguard.checkpoint:');
  });
});

describe('Public re-exports (compile-time check)', () => {
  it('runtime index re-exports constants', async () => {
    // Dynamic import verifies the actual dist module re-exports these names
    const runtime = await import('../../src/index.js') as Record<string, unknown>;
    expect(runtime['GENESIS_HASH']).toBe('0'.repeat(64));
    expect(runtime['PAYLOAD_VERSION']).toBe(1);
    expect(runtime['AUDIT_LOG_TABLE']).toBe('trailguard_audit_log');
    expect(runtime['AUDIT_HEAD_TABLE']).toBe('trailguard_audit_head');
  });
});
