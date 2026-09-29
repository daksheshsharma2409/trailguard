/**
 * Cryptographic helpers for the audit chain.
 *
 * All operations use Node's native `node:crypto` module — no third-party libs.
 *
 * @see context.md §7.3, §7.4
 */

import { createHmac, createHash, timingSafeEqual } from 'node:crypto';

/**
 * Compute SHA-256 hash over `data`, returning a lowercase hex string.
 *
 * @param data - The data to hash (string or Buffer).
 * @returns 64-character lowercase hex string.
 */
export function sha256Hex(data: string | Buffer): string {
  return createHash('sha256').update(data).digest('hex');
}

/**
 * Compute HMAC-SHA256 over `data` using `key`, returning a lowercase hex string.
 *
 * @param key  - The raw secret (string or Buffer).
 * @param data - The message to authenticate (string or Buffer).
 * @returns 64-character lowercase hex string.
 */
export function hmacHex(key: string | Buffer, data: string | Buffer): string {
  return createHmac('sha256', key).update(data).digest('hex');
}

/**
 * Alias for `hmacHex`.
 */
export const hmac = hmacHex;

/**
 * Derive a key for a specific label via HMAC-SHA256.
 *
 * Useful for domain-separating keys: `deriveKey(masterKey, 'audit.entry')`.
 *
 * @param key   - The master key (string or Buffer).
 * @param label - An ASCII label string (e.g. `'audit.entry'`, `'checkpoint'`).
 * @returns 64-character lowercase hex string (the derived key in hex).
 */
export function deriveKey(key: string | Buffer, label: string): string {
  return createHmac('sha256', key).update(label, 'utf8').digest('hex');
}

const HEX_REGEX = /^[0-9a-fA-F]*$/;

/**
 * Compare two hex strings in constant time.
 *
 * Returns `false` (without throwing) when the strings have different lengths,
 * contain invalid hex characters, or when either argument is not a valid string,
 * so that timing cannot leak length or error information via exception paths.
 *
 * @param a - Hex string.
 * @param b - Hex string.
 * @returns `true` only if both strings represent identical byte sequences.
 */
export function timingSafeEqualHex(a: string, b: string): boolean {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  if (a.length % 2 !== 0) return false;
  if (!HEX_REGEX.test(a) || !HEX_REGEX.test(b)) return false;

  try {
    const bufA = Buffer.from(a, 'hex');
    const bufB = Buffer.from(b, 'hex');
    return timingSafeEqual(bufA, bufB);
  } catch {
    return false;
  }
}
