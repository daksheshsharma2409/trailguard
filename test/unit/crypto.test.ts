import { describe, it, expect } from 'vitest';
import { hmacHex, hmac, deriveKey, timingSafeEqualHex } from '../../src/core/crypto.js';

describe('T1.4 — Cryptographic helpers (node:crypto)', () => {
  describe('hmacHex / hmac', () => {
    it('aliases hmac to hmacHex', () => {
      expect(hmac).toBe(hmacHex);
    });

    it('passes RFC 4231 Test Case 1', () => {
      // Key = 20 bytes 0x0b, Data = "Hi There"
      const key = Buffer.alloc(20, 0x0b);
      const data = 'Hi There';
      const expected = 'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7';
      expect(hmacHex(key, data)).toBe(expected);
    });

    it('passes RFC 4231 Test Case 2', () => {
      // Key = "Jefe", Data = "what do ya want for nothing?"
      const key = 'Jefe';
      const data = 'what do ya want for nothing?';
      const expected = '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843';
      expect(hmacHex(key, data)).toBe(expected);
    });

    it('passes RFC 4231 Test Case 3', () => {
      // Key = 20 bytes 0xaa, Data = 50 bytes 0xdd
      const key = Buffer.alloc(20, 0xaa);
      const data = Buffer.alloc(50, 0xdd);
      const expected = '773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe';
      expect(hmacHex(key, data)).toBe(expected);
    });

    it('passes RFC 4231 Test Case 4', () => {
      // Key = 25 bytes 0x01..0x19, Data = 50 bytes 0xcd
      const key = Buffer.from('0102030405060708090a0b0c0d0e0f10111213141516171819', 'hex');
      const data = Buffer.alloc(50, 0xcd);
      const expected = '82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b';
      expect(hmacHex(key, data)).toBe(expected);
    });

    it('passes RFC 4231 Test Case 6 (key larger than block size 64 bytes)', () => {
      // Key = 131 bytes 0xaa, Data = "Test Using Larger Than Block-Size Key - Hash Key First"
      const key = Buffer.alloc(131, 0xaa);
      const data = 'Test Using Larger Than Block-Size Key - Hash Key First';
      const expected = '60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54';
      expect(hmacHex(key, data)).toBe(expected);
    });

    it('passes RFC 4231 Test Case 7 (key and data larger than block size)', () => {
      const key = Buffer.alloc(131, 0xaa);
      const data =
        'This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.';
      const expected = '9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2';
      expect(hmacHex(key, data)).toBe(expected);
    });

    it('returns 64-char lowercase hex string', () => {
      const res = hmacHex('secret-key', 'some data');
      expect(res).toHaveLength(64);
      expect(res).toMatch(/^[0-9a-f]{64}$/);
    });
  });

  describe('deriveKey', () => {
    it('derives consistent 64-character hex keys', () => {
      const k1 = deriveKey('master-secret', 'audit.entry');
      const k2 = deriveKey('master-secret', 'audit.entry');
      expect(k1).toHaveLength(64);
      expect(k1).toMatch(/^[0-9a-f]{64}$/);
      expect(k1).toBe(k2);
    });

    it('produces different keys for different labels', () => {
      const k1 = deriveKey('master-secret', 'audit.entry');
      const k2 = deriveKey('master-secret', 'checkpoint');
      expect(k1).not.toBe(k2);
    });

    it('produces different keys for different master keys', () => {
      const k1 = deriveKey('master-secret-1', 'audit.entry');
      const k2 = deriveKey('master-secret-2', 'audit.entry');
      expect(k1).not.toBe(k2);
    });
  });

  describe('timingSafeEqualHex', () => {
    it('returns true for identical hex strings', () => {
      const hex = 'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7';
      expect(timingSafeEqualHex(hex, hex)).toBe(true);
    });

    it('returns true for case-insensitive hex strings representing identical bytes', () => {
      const lower = '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843';
      const upper = lower.toUpperCase();
      expect(timingSafeEqualHex(lower, upper)).toBe(true);
    });

    it('returns false for different lengths without throwing', () => {
      expect(timingSafeEqualHex('abcd', 'abcdef')).toBe(false);
      expect(timingSafeEqualHex('', 'ab')).toBe(false);
      expect(timingSafeEqualHex('a', 'ab')).toBe(false);
      expect(timingSafeEqualHex('1234567890', '12345678')).toBe(false);
    });

    it('returns false for same length but different hex values', () => {
      const a = 'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7';
      const b = 'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff8';
      expect(timingSafeEqualHex(a, b)).toBe(false);
    });

    it('returns false for odd length hex strings without throwing', () => {
      expect(timingSafeEqualHex('abc', 'abc')).toBe(false);
    });

    it('returns false for invalid non-hex characters without throwing', () => {
      expect(timingSafeEqualHex('zz', 'xx')).toBe(false);
      expect(timingSafeEqualHex('gg', 'gg')).toBe(false);
      expect(timingSafeEqualHex('123g', '1234')).toBe(false);
    });

    it('returns true for empty strings', () => {
      expect(timingSafeEqualHex('', '')).toBe(true);
    });

    it('handles non-string arguments safely without throwing', () => {
      // @ts-expect-error testing invalid argument types
      expect(timingSafeEqualHex(null, 'ab')).toBe(false);
      // @ts-expect-error testing invalid argument types
      expect(timingSafeEqualHex('ab', undefined)).toBe(false);
      // @ts-expect-error testing invalid argument types
      expect(timingSafeEqualHex(123, 123)).toBe(false);
    });
  });
});
