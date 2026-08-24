/**
 * Tests for stableStringify — T1.3 acceptance criteria.
 *
 * Accept:
 * - key-order permutation invariance (property-style test with random objects)
 * - BigInt, Date, Buffer handled
 * - undefined omitted, null kept
 * - throws AuditWriteError on NaN / Infinity / cycles / functions
 * - output has no whitespace
 */
import { describe, it, expect } from 'vitest';
import { stableStringify } from '../../src/core/canonical.js';
import { AuditWriteError } from '../../src/core/errors.js';

// ── Helpers ────────────────────────────────────────────────────────────────

/** Shuffle the keys of an object (return a new object with same keys in random order). */
function shuffleKeys(obj: Record<string, unknown>): Record<string, unknown> {
  const keys = Object.keys(obj);
  // Fisher-Yates on keys
  for (let i = keys.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [keys[i], keys[j]] = [keys[j]!, keys[i]!];
  }
  const out: Record<string, unknown> = {};
  for (const k of keys) out[k] = obj[k];
  return out;
}

// ── Key-order permutation invariance ──────────────────────────────────────

describe('permutation invariance', () => {
  it('same result regardless of key insertion order', () => {
    const original = { b: 2, a: 1, c: 3, z: 'end', m: null };
    const shuffled = shuffleKeys(original);
    expect(stableStringify(original)).toBe(stableStringify(shuffled));
  });

  it('nested objects are also sorted', () => {
    const v1 = { outer: { b: 2, a: 1 }, x: 1 };
    const v2 = { x: 1, outer: { a: 1, b: 2 } };
    expect(stableStringify(v1)).toBe(stableStringify(v2));
  });

  it('runs 20 random permutations and all match', () => {
    const base = { seq: 1, model: 'User', action: 'CREATE', actorId: 'u1', prevHash: 'abc' };
    const canonical = stableStringify(base);
    for (let i = 0; i < 20; i++) {
      expect(stableStringify(shuffleKeys(base))).toBe(canonical);
    }
  });
});

// ── Primitive handling ─────────────────────────────────────────────────────

describe('primitive handling', () => {
  it('null is kept', () => {
    expect(stableStringify(null)).toBe('null');
    expect(stableStringify({ a: null })).toBe('{"a":null}');
  });

  it('undefined at top level → empty string (omitted)', () => {
    expect(stableStringify(undefined)).toBe('');
  });

  it('undefined properties are omitted', () => {
    expect(stableStringify({ a: 1, b: undefined, c: 3 })).toBe('{"a":1,"c":3}');
  });

  it('strings are JSON-encoded', () => {
    expect(stableStringify('hello')).toBe('"hello"');
    expect(stableStringify('with "quotes"')).toBe('"with \\"quotes\\""');
  });

  it('booleans work', () => {
    expect(stableStringify(true)).toBe('true');
    expect(stableStringify(false)).toBe('false');
  });

  it('numbers work', () => {
    expect(stableStringify(42)).toBe('42');
    expect(stableStringify(-1.5)).toBe('-1.5');
    expect(stableStringify(0)).toBe('0');
  });
});

// ── Special type handling ──────────────────────────────────────────────────

describe('BigInt', () => {
  it('serialises BigInt as decimal string', () => {
    expect(stableStringify(42n)).toBe('"42"');
    expect(stableStringify({ id: 99n })).toBe('{"id":"99"}');
  });
});

describe('Date', () => {
  it('serialises Date as ISO string', () => {
    const d = new Date('2024-01-15T12:00:00.000Z');
    expect(stableStringify(d)).toBe('"2024-01-15T12:00:00.000Z"');
    expect(stableStringify({ ts: d })).toBe('{"ts":"2024-01-15T12:00:00.000Z"}');
  });
});

describe('Buffer / Uint8Array', () => {
  it('serialises Buffer as base64 string', () => {
    const buf = Buffer.from('hello');
    const result = stableStringify(buf);
    expect(result).toBe('"aGVsbG8="');
  });

  it('serialises Uint8Array as base64 string', () => {
    const ua = new Uint8Array([72, 101, 108, 108, 111]); // "Hello"
    const result = stableStringify(ua);
    expect(result).toBe('"SGVsbG8="');
  });
});

describe('Prisma Decimal duck-type', () => {
  it('serialises object with toFixed() and d[] as string', () => {
    const fakeDecimal = {
      d: [123],
      toFixed: () => '123.45',
      toString: () => '123.45',
    };
    expect(stableStringify(fakeDecimal)).toBe('"123.45"');
  });
});

// ── Array handling ─────────────────────────────────────────────────────────

describe('arrays', () => {
  it('arrays preserve order', () => {
    expect(stableStringify([3, 1, 2])).toBe('[3,1,2]');
  });

  it('undefined in arrays becomes null', () => {
    expect(stableStringify([1, undefined, 3])).toBe('[1,null,3]');
  });

  it('nested objects in arrays are sorted', () => {
    expect(stableStringify([{ b: 2, a: 1 }])).toBe('[{"a":1,"b":2}]');
  });
});

// ── Rejection cases ────────────────────────────────────────────────────────

describe('rejections', () => {
  it('throws AuditWriteError for NaN', () => {
    expect(() => stableStringify(NaN)).toThrowError(AuditWriteError);
    expect(() => stableStringify({ x: NaN })).toThrowError(AuditWriteError);
  });

  it('throws AuditWriteError for Infinity', () => {
    expect(() => stableStringify(Infinity)).toThrowError(AuditWriteError);
    expect(() => stableStringify(-Infinity)).toThrowError(AuditWriteError);
    expect(() => stableStringify({ x: Infinity })).toThrowError(AuditWriteError);
  });

  it('throws AuditWriteError for functions', () => {
    expect(() => stableStringify(() => 1)).toThrowError(AuditWriteError);
    expect(() => stableStringify({ fn: () => 1 })).toThrowError(AuditWriteError);
  });

  it('throws AuditWriteError for symbols', () => {
    expect(() => stableStringify(Symbol('x'))).toThrowError(AuditWriteError);
  });

  it('throws AuditWriteError for circular references', () => {
    const obj: Record<string, unknown> = { a: 1 };
    obj['self'] = obj;
    expect(() => stableStringify(obj)).toThrowError(AuditWriteError);
  });

  it('throws AuditWriteError for circular arrays', () => {
    const arr: unknown[] = [1, 2];
    arr.push(arr);
    expect(() => stableStringify(arr)).toThrowError(AuditWriteError);
  });
});

// ── No whitespace ──────────────────────────────────────────────────────────

describe('output format', () => {
  it('output contains no whitespace', () => {
    const obj = { a: 1, b: 'hello', c: [1, 2, 3], d: { nested: true } };
    const result = stableStringify(obj);
    expect(result).not.toMatch(/\s/);
  });

  it('keys are sorted in codepoint order', () => {
    // codepoint order: uppercase letters < lowercase letters
    const obj = { z: 1, A: 2, a: 3, Z: 4 };
    const result = stableStringify(obj);
    // Sorted: A, Z, a, z
    expect(result).toBe('{"A":2,"Z":4,"a":3,"z":1}');
  });
});
