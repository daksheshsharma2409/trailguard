import { describe, it, expect } from 'vitest';
import { redactRecord, computeRedactionTag, isRedactedValue } from '../../src/runtime/redact.js';
import { AuditConfigError } from '../../src/core/errors.js';

describe('runtime/redact', () => {
  const masterKey = 'test-secret-key-32-chars-long!';

  describe('computeRedactionTag', () => {
    it('generates a 4-hex-char tag', () => {
      const tag = computeRedactionTag(masterKey, 'Student', 'ssn', '123-45-6789');
      expect(tag).toMatch(/^[0-9a-f]{4}$/);
    });

    it('is deterministic: same value yields same tag', () => {
      const tag1 = computeRedactionTag(masterKey, 'Student', 'ssn', '123-45-6789');
      const tag2 = computeRedactionTag(masterKey, 'Student', 'ssn', '123-45-6789');
      expect(tag1).toBe(tag2);
    });

    it('produces different tags for different values', () => {
      const tag1 = computeRedactionTag(masterKey, 'Student', 'ssn', '123-45-6789');
      const tag2 = computeRedactionTag(masterKey, 'Student', 'ssn', '987-65-4321');
      expect(tag1).not.toBe(tag2);
    });

    it('produces different tags for different fields or models', () => {
      const tag1 = computeRedactionTag(masterKey, 'Student', 'ssn', '123-45-6789');
      const tag2 = computeRedactionTag(masterKey, 'Teacher', 'ssn', '123-45-6789');
      const tag3 = computeRedactionTag(masterKey, 'Student', 'taxId', '123-45-6789');

      expect(tag1).not.toBe(tag2);
      expect(tag1).not.toBe(tag3);
    });

    it('throws AuditConfigError if key is empty', () => {
      expect(() => computeRedactionTag('', 'Student', 'ssn', 'val')).toThrow(AuditConfigError);
    });
  });

  describe('isRedactedValue', () => {
    it('identifies formatted redacted values', () => {
      expect(isRedactedValue('[REDACTED:1a2b]')).toBe(true);
      expect(isRedactedValue('[REDACTED:ffff]')).toBe(true);
      expect(isRedactedValue('[REDACTED:123]')).toBe(false);
      expect(isRedactedValue('[REDACTED:12345]')).toBe(false);
      expect(isRedactedValue('regular-string')).toBe(false);
      expect(isRedactedValue(123)).toBe(false);
      expect(isRedactedValue(null)).toBe(false);
    });
  });

  describe('redactRecord', () => {
    it('returns null for null or undefined input', () => {
      expect(redactRecord(null, { model: 'Student', key: masterKey })).toBeNull();
      expect(redactRecord(undefined, { model: 'Student', key: masterKey })).toBeNull();
    });

    it('redacts configured global redactFields and leaves raw values absent', () => {
      const record = {
        id: 'std_1',
        name: 'Alice',
        password: 'super-secret-password',
        token: 'auth-token-xyz',
      };

      const redacted = redactRecord(record, {
        model: 'Student',
        key: masterKey,
        redactFields: ['password', 'token'],
      });

      expect(redacted).not.toBeNull();
      expect(redacted?.id).toBe('std_1');
      expect(redacted?.name).toBe('Alice');
      expect(redacted?.password).toMatch(/^\[REDACTED:[0-9a-f]{4}\]$/);
      expect(redacted?.token).toMatch(/^\[REDACTED:[0-9a-f]{4}\]$/);
      expect(JSON.stringify(redacted)).not.toContain('super-secret-password');
      expect(JSON.stringify(redacted)).not.toContain('auth-token-xyz');
    });

    it('does not mutate the source record', () => {
      const record = {
        id: 'std_1',
        secret: 'raw-secret',
      };

      const copy = { ...record };
      redactRecord(record, {
        model: 'Student',
        key: masterKey,
        redactFields: ['secret'],
      });

      expect(record).toEqual(copy);
      expect(record.secret).toBe('raw-secret');
    });

    it('redacts per-model fields', () => {
      const record = {
        id: 'std_1',
        secretA: 'valA',
        secretB: 'valB',
      };

      const redacted = redactRecord(record, {
        model: 'Student',
        key: masterKey,
        redact: {
          Student: ['secretA'],
          Teacher: ['secretB'],
        },
      });

      expect(redacted?.secretA).toMatch(/^\[REDACTED:[0-9a-f]{4}\]$/);
      expect(redacted?.secretB).toBe('valB');
    });

    it('removes ignoreFields entirely (array and per-model)', () => {
      const record = {
        id: 'std_1',
        blob: 'huge-data-payload',
        cachedData: 'temporary-data',
        normal: 'keep-me',
      };

      const redacted = redactRecord(record, {
        model: 'Student',
        key: masterKey,
        ignoreFields: {
          Student: ['blob'],
        },
      });

      expect(redacted).not.toBeNull();
      expect(redacted?.normal).toBe('keep-me');
      expect(redacted?.blob).toBeUndefined();
      expect('blob' in (redacted ?? {})).toBe(false);
    });

    it('supports global array for ignoreFields', () => {
      const record = {
        id: 'std_1',
        tempToken: '12345',
        normal: 'keep',
      };

      const redacted = redactRecord(record, {
        model: 'Student',
        key: masterKey,
        ignoreFields: ['tempToken'],
      });

      expect(redacted?.normal).toBe('keep');
      expect(redacted?.tempToken).toBeUndefined();
    });

    it('supports dotted path for nested field redaction and ignore', () => {
      const record = {
        id: 'user_1',
        profile: {
          ssn: '123-45-6789',
          nickname: 'Ali',
          internalNotes: 'ignore-this',
        },
      };

      const redacted = redactRecord(record, {
        model: 'User',
        key: masterKey,
        redactFields: ['profile.ssn'],
        ignoreFields: ['profile.internalNotes'],
      });

      const profile = redacted?.profile as Record<string, unknown>;
      expect(profile).toBeDefined();
      expect(profile.nickname).toBe('Ali');
      expect(profile.ssn).toMatch(/^\[REDACTED:[0-9a-f]{4}\]$/);
      expect(profile.internalNotes).toBeUndefined();
      expect(JSON.stringify(redacted)).not.toContain('123-45-6789');
    });

    it('does not re-redact already redacted fields', () => {
      const existingTag = '[REDACTED:abcd]';
      const record = {
        id: 'std_1',
        password: existingTag,
      };

      const redacted = redactRecord(record, {
        model: 'Student',
        key: masterKey,
        redactFields: ['password'],
      });

      expect(redacted?.password).toBe(existingTag);
    });
  });
});
