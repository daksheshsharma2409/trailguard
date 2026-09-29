/**
 * Unit tests for src/core/errors.ts — T1.1 acceptance criteria.
 *
 * Each error class must have:
 *  - correct `.name`
 *  - correct `.code` string
 *  - meaningful `.message`
 *  - `instanceof` chain works for both the class and `TrailguardError`
 *  - `instanceof Error` works (prototype chain integrity)
 */
import { describe, it, expect } from 'vitest';
import {
  TrailguardError,
  AuditChainBrokenError,
  AuditContextMissingError,
  AuditConfigError,
  AuditWriteError,
  ScanConfigError,
  ScanParseError,
} from '../../src/core/errors.js';

describe('TrailguardError (base)', () => {
  it('has correct name, code, message', () => {
    const err = new TrailguardError('TEST_CODE', 'test message');
    expect(err.name).toBe('TrailguardError');
    expect(err.code).toBe('TEST_CODE');
    expect(err.message).toBe('test message');
  });

  it('is instanceof Error', () => {
    expect(new TrailguardError('X', 'y')).toBeInstanceOf(Error);
  });

  it('propagates cause', () => {
    const cause = new Error('original');
    const err = new TrailguardError('X', 'wrapped', { cause });
    expect(err.cause).toBe(cause);
  });
});

describe('AuditChainBrokenError', () => {
  it('has correct name and code', () => {
    const err = new AuditChainBrokenError('chain broken');
    expect(err.name).toBe('AuditChainBrokenError');
    expect(err.code).toBe('AUDIT_CHAIN_BROKEN');
    expect(err.message).toBe('chain broken');
  });

  it('is instanceof TrailguardError and Error', () => {
    const err = new AuditChainBrokenError('x');
    expect(err).toBeInstanceOf(TrailguardError);
    expect(err).toBeInstanceOf(Error);
  });

  it('captures optional brokenAt and reason', () => {
    const err = new AuditChainBrokenError('x', { brokenAt: '42', reason: 'hash mismatch' });
    expect(err.brokenAt).toBe('42');
    expect(err.reason).toBe('hash mismatch');
  });

  it('brokenAt and reason are undefined when not provided', () => {
    const err = new AuditChainBrokenError('x');
    expect(err.brokenAt).toBeUndefined();
    expect(err.reason).toBeUndefined();
  });
});

describe('AuditContextMissingError', () => {
  it('has correct name and code with default message', () => {
    const err = new AuditContextMissingError();
    expect(err.name).toBe('AuditContextMissingError');
    expect(err.code).toBe('AUDIT_CONTEXT_MISSING');
    expect(err.message).toContain('audit context');
  });

  it('accepts custom message', () => {
    const err = new AuditContextMissingError('custom msg');
    expect(err.message).toBe('custom msg');
  });

  it('is instanceof TrailguardError', () => {
    expect(new AuditContextMissingError()).toBeInstanceOf(TrailguardError);
  });
});

describe('AuditConfigError', () => {
  it('has correct name, code, message', () => {
    const err = new AuditConfigError('bad config');
    expect(err.name).toBe('AuditConfigError');
    expect(err.code).toBe('AUDIT_CONFIG_ERROR');
    expect(err.message).toBe('bad config');
  });

  it('is instanceof TrailguardError', () => {
    expect(new AuditConfigError('x')).toBeInstanceOf(TrailguardError);
  });
});

describe('AuditWriteError', () => {
  it('has correct name, code, message', () => {
    const err = new AuditWriteError('db down');
    expect(err.name).toBe('AuditWriteError');
    expect(err.code).toBe('AUDIT_WRITE_ERROR');
    expect(err.message).toBe('db down');
  });

  it('is instanceof TrailguardError', () => {
    expect(new AuditWriteError('x')).toBeInstanceOf(TrailguardError);
  });
});

describe('ScanConfigError', () => {
  it('has correct name, code, message', () => {
    const err = new ScanConfigError('missing config');
    expect(err.name).toBe('ScanConfigError');
    expect(err.code).toBe('SCAN_CONFIG_ERROR');
    expect(err.message).toBe('missing config');
  });

  it('captures optional filePath', () => {
    const err = new ScanConfigError('x', { filePath: '/foo/bar.ts' });
    expect(err.filePath).toBe('/foo/bar.ts');
  });

  it('filePath is undefined when not provided', () => {
    expect(new ScanConfigError('x').filePath).toBeUndefined();
  });

  it('is instanceof TrailguardError', () => {
    expect(new ScanConfigError('x')).toBeInstanceOf(TrailguardError);
  });
});

describe('ScanParseError', () => {
  it('has correct name, code, message', () => {
    const err = new ScanParseError('syntax error');
    expect(err.name).toBe('ScanParseError');
    expect(err.code).toBe('SCAN_PARSE_ERROR');
    expect(err.message).toBe('syntax error');
  });

  it('captures optional filePath and lineNumber', () => {
    const err = new ScanParseError('x', { filePath: '/src/app.ts', lineNumber: 42 });
    expect(err.filePath).toBe('/src/app.ts');
    expect(err.lineNumber).toBe(42);
  });

  it('captures cause in ScanParseError and ScanConfigError', () => {
    const cause = new Error('inner');
    const parseErr = new ScanParseError('x', { cause });
    expect(parseErr.cause).toBe(cause);
    const configErr = new ScanConfigError('x', { lineNumber: 10, cause });
    expect(configErr.lineNumber).toBe(10);
    expect(configErr.cause).toBe(cause);
    const chainErr = new AuditChainBrokenError('x', { cause });
    expect(chainErr.cause).toBe(cause);
  });

  it('filePath and lineNumber are undefined when not provided', () => {
    const err = new ScanParseError('x');
    expect(err.filePath).toBeUndefined();
    expect(err.lineNumber).toBeUndefined();
  });

  it('is instanceof TrailguardError', () => {
    expect(new ScanParseError('x')).toBeInstanceOf(TrailguardError);
  });
});

describe('instanceof after build (prototype chain integrity)', () => {
  it('all subclasses are instanceof TrailguardError', () => {
    const errors = [
      new AuditChainBrokenError('x'),
      new AuditContextMissingError(),
      new AuditConfigError('x'),
      new AuditWriteError('x'),
      new ScanConfigError('x'),
      new ScanParseError('x'),
    ];
    for (const err of errors) {
      expect(err).toBeInstanceOf(TrailguardError);
      expect(err).toBeInstanceOf(Error);
    }
  });
});
