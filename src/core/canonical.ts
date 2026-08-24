/**
 * Canonical (stable) JSON serialisation for HMAC payload construction.
 *
 * Rules (per context.md §7.3):
 * - Object keys sorted in codepoint order, recursively. Arrays keep order.
 * - `undefined` properties omitted; `null` kept.
 * - `Date` → ISO string; `BigInt` → decimal string;
 *   `Buffer`/`Uint8Array` → base64 string;
 *   Prisma `Decimal` (has `toFixed` and a `d` field) → string.
 * - Rejects `NaN`, `Infinity`, functions, symbols, circular refs → `AuditWriteError`.
 * - No whitespace in output.
 *
 * @see context.md §7.3
 */

import { AuditWriteError } from './errors.js';

/**
 * Duck-type check for Prisma's Decimal class.
 * Decimal has a `toFixed` method and a `d` array field (internal digits).
 */
function isPrismaDecimal(value: unknown): value is { toFixed: () => string; d: unknown[] } {
  return (
    value !== null &&
    typeof value === 'object' &&
    typeof (value as Record<string, unknown>)['toFixed'] === 'function' &&
    Array.isArray((value as Record<string, unknown>)['d'])
  );
}

/**
 * Recursive serialisation helper.
 *
 * @param value  - The value to serialise.
 * @param seen   - Set of ancestor objects, used for cycle detection.
 * @returns JSON string fragment — never has outer whitespace.
 * @throws {AuditWriteError} For unseralisable values (NaN, Infinity, functions, symbols, cycles).
 */
function _stringify(value: unknown, seen: Set<object>): string {
  // Primitives
  if (value === null) return 'null';
  if (value === undefined) return '';   // caller handles omission

  if (typeof value === 'boolean') return value ? 'true' : 'false';

  if (typeof value === 'number') {
    if (Number.isNaN(value)) {
      throw new AuditWriteError('stableStringify: NaN is not allowed in audit payloads');
    }
    if (!Number.isFinite(value)) {
      throw new AuditWriteError('stableStringify: Infinity is not allowed in audit payloads');
    }
    return JSON.stringify(value);
  }

  if (typeof value === 'bigint') {
    return JSON.stringify(value.toString());
  }

  if (typeof value === 'function') {
    throw new AuditWriteError('stableStringify: functions are not allowed in audit payloads');
  }

  if (typeof value === 'symbol') {
    throw new AuditWriteError('stableStringify: symbols are not allowed in audit payloads');
  }

  if (typeof value === 'string') {
    return JSON.stringify(value);
  }

  // Object types
  if (value instanceof Date) {
    return JSON.stringify(value.toISOString());
  }

  if (value instanceof Uint8Array) {
    // Covers Buffer (which extends Uint8Array in Node)
    return JSON.stringify(Buffer.from(value).toString('base64'));
  }

  if (isPrismaDecimal(value)) {
    return JSON.stringify(value.toFixed());
  }

  if (Array.isArray(value)) {
    if (seen.has(value)) {
      throw new AuditWriteError('stableStringify: circular reference detected in audit payload');
    }
    seen.add(value);
    const items = value.map((item: unknown) => {
      if (item === undefined) return 'null'; // JSON arrays: undefined → null
      return _stringify(item, seen);
    });
    seen.delete(value);
    return `[${items.join(',')}]`;
  }

  // Plain object
  if (typeof value === 'object') {
    if (seen.has(value as object)) {
      throw new AuditWriteError('stableStringify: circular reference detected in audit payload');
    }
    seen.add(value as object);

    const keys = Object.keys(value as object).sort(); // codepoint order
    const parts: string[] = [];
    for (const key of keys) {
      const v = (value as Record<string, unknown>)[key];
      if (v === undefined) continue; // omit undefined
      const serialisedValue = _stringify(v, seen);
      parts.push(`${JSON.stringify(key)}:${serialisedValue}`);
    }
    seen.delete(value as object);
    return `{${parts.join(',')}}`;
  }

  // Fallback — should be unreachable with strict TS, but just in case
  throw new AuditWriteError(
    `stableStringify: unsupported value type "${typeof value}" in audit payload`,
  );
}

/**
 * Produce a canonical, stable JSON string for use in HMAC payloads.
 *
 * - Keys sorted codepoint-order, recursively
 * - No whitespace
 * - `undefined` omitted, `null` kept
 * - `Date` → ISO string, `BigInt` → decimal string, `Uint8Array/Buffer` → base64,
 *   Prisma `Decimal` → string
 *
 * @throws {AuditWriteError} For NaN, Infinity, functions, symbols, or circular refs.
 */
export function stableStringify(value: unknown): string {
  return _stringify(value, new Set<object>());
}
