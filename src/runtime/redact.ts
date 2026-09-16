/**
 * Redaction engine for trailguard runtime audit log.
 *
 * Replaces sensitive fields with deterministic, non-invertible tags:
 * `[REDACTED:xxxx]` where tag is a 4-hex-char HMAC of the value.
 *
 * @see context.md §7.7
 */

import { deriveKey, hmac } from '../core/crypto.js';
import { stableStringify } from '../core/canonical.js';
import { AuditConfigError } from '../core/errors.js';

export interface RedactOptions {
  model: string;
  key: string | Buffer;
  redactFields?: string[] | undefined;
  redact?: Record<string, string[]> | undefined;
  ignoreFields?: Record<string, string[]> | string[] | undefined;
}

const REDACTED_REGEX = /^\[REDACTED:[0-9a-f]{4}\]$/;

/**
 * Returns true if the value is already a formatted redaction tag.
 */
export function isRedactedValue(val: unknown): boolean {
  return typeof val === 'string' && REDACTED_REGEX.test(val);
}

/**
 * Compute the deterministic 4-hex-char redaction tag for a field value.
 *
 * tag = hmac(deriveKey(key, 'redact'), model + '.' + field + ':' + stableStringify(value)).slice(0, 4)
 */
export function computeRedactionTag(
  key: string | Buffer,
  model: string,
  field: string,
  value: unknown,
): string {
  if (!key || (typeof key === 'string' && key.trim().length === 0)) {
    throw new AuditConfigError('HMAC key is required for computing redaction tags');
  }
  const derivedKey = deriveKey(key, 'redact');
  const message = `${model}.${field}:${stableStringify(value)}`;
  return hmac(derivedKey, message).slice(0, 4).toLowerCase();
}

/**
 * Recursively clone a plain record or array for redaction manipulation.
 */
function deepClone<T>(val: T): T {
  if (val === null || typeof val !== 'object') {
    return val;
  }
  if (val instanceof Date) {
    return new Date(val.getTime()) as unknown as T;
  }
  if (val instanceof Uint8Array) {
    return Buffer.from(val) as unknown as T;
  }
  if (Array.isArray(val)) {
    return val.map(deepClone) as unknown as T;
  }
  const copy: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(val as Record<string, unknown>)) {
    copy[k] = deepClone(v);
  }
  return copy as T;
}

/**
 * Delete a field from a target object, supporting dotted paths (e.g. 'profile.ssn').
 */
function deletePath(obj: Record<string, unknown>, path: string): void {
  const parts = path.split('.');
  const first = parts[0];
  if (parts.length === 1 && first !== undefined) {
    Reflect.deleteProperty(obj, first);
    return;
  }
  let current: unknown = obj;
  for (let i = 0; i < parts.length - 1; i++) {
    const key = parts[i];
    if (key === undefined || current === null || typeof current !== 'object' || Array.isArray(current)) {
      return;
    }
    current = (current as Record<string, unknown>)[key];
  }
  const last = parts[parts.length - 1];
  if (last !== undefined && current !== null && typeof current === 'object' && !Array.isArray(current)) {
    Reflect.deleteProperty(current as Record<string, unknown>, last);
  }
}

/**
 * Apply redaction to a target object at a path, supporting dotted paths.
 */
function redactPath(
  obj: Record<string, unknown>,
  path: string,
  key: string | Buffer,
  model: string,
): void {
  const parts = path.split('.');
  const first = parts[0];
  if (parts.length === 1 && first !== undefined) {
    if (Object.prototype.hasOwnProperty.call(obj, first) && obj[first] !== undefined) {
      const val: unknown = obj[first];
      if (isRedactedValue(val)) {
        return;
      }
      const tag = computeRedactionTag(key, model, first, val);
      obj[first] = `[REDACTED:${tag}]`;
    }
    return;
  }

  let current: unknown = obj;
  for (let i = 0; i < parts.length - 1; i++) {
    const partKey = parts[i];
    if (partKey === undefined || current === null || typeof current !== 'object' || Array.isArray(current)) {
      return;
    }
    current = (current as Record<string, unknown>)[partKey];
  }
  const last = parts[parts.length - 1];
  if (last !== undefined && current !== null && typeof current === 'object' && !Array.isArray(current)) {
    const targetObj = current as Record<string, unknown>;
    if (Object.prototype.hasOwnProperty.call(targetObj, last) && targetObj[last] !== undefined) {
      const val: unknown = targetObj[last];
      if (isRedactedValue(val)) {
        return;
      }
      const tag = computeRedactionTag(key, model, path, val);
      targetObj[last] = `[REDACTED:${tag}]`;
    }
  }
}

/**
 * Redact sensitive fields and strip ignored fields from a record.
 *
 * @param record - The source record to redact.
 * @param options - Redaction configuration.
 * @returns A new object with ignored fields removed and sensitive fields replaced by `[REDACTED:xxxx]`.
 */
export function redactRecord<T extends Record<string, unknown>>(
  record: T | null | undefined,
  options: RedactOptions,
): T | null {
  if (record === null || record === undefined) {
    return null;
  }
  if (typeof record !== 'object' || Array.isArray(record)) {
    return record;
  }

  const result = deepClone(record) as Record<string, unknown>;

  // 1. Strip ignoreFields
  const ignoredFields = new Set<string>();
  if (Array.isArray(options.ignoreFields)) {
    for (const f of options.ignoreFields) {
      ignoredFields.add(f);
    }
  } else if (options.ignoreFields && typeof options.ignoreFields === 'object') {
    const modelIgnored =
      options.ignoreFields[options.model] ??
      options.ignoreFields[options.model.toLowerCase()];
    if (Array.isArray(modelIgnored)) {
      for (const f of modelIgnored) {
        ignoredFields.add(f);
      }
    }
  }

  for (const field of ignoredFields) {
    deletePath(result, field);
  }

  // 2. Redact fields
  const fieldsToRedact = new Set<string>();
  if (Array.isArray(options.redactFields)) {
    for (const f of options.redactFields) {
      fieldsToRedact.add(f);
    }
  }
  if (options.redact && typeof options.redact === 'object') {
    const modelRedact =
      options.redact[options.model] ??
      options.redact[options.model.toLowerCase()];
    if (Array.isArray(modelRedact)) {
      for (const f of modelRedact) {
        fieldsToRedact.add(f);
      }
    }
  }

  for (const field of fieldsToRedact) {
    redactPath(result, field, options.key, options.model);
  }

  return result as T;
}
