/**
 * Diff computation for trailguard runtime audit log.
 *
 * Compares before and after states canonically using stableStringify.
 * - CREATE: diff = null
 * - DELETE: diff = null
 * - UPDATE: { [field]: { old, new } } for fields where canonical values differ
 *
 * @see context.md §7.7
 */

import { stableStringify } from '../core/canonical.js';
import type { AuditAction } from '../core/types.js';

export interface FieldDiff {
  old: unknown;
  new: unknown;
}

export type RecordDiff = Record<string, FieldDiff>;

/**
 * Compute the canonical field-level diff between before and after states.
 *
 * @param before - State before the operation (null for CREATE).
 * @param after  - State after the operation (null for DELETE).
 * @param action - The audit action (CREATE, UPDATE, DELETE). Inferred if omitted.
 * @returns Object mapping field names to { old, new }, or null for CREATE/DELETE.
 */
export function createDiff(
  before: Record<string, unknown> | null | undefined,
  after: Record<string, unknown> | null | undefined,
  action?: AuditAction,
): RecordDiff | null {
  // Explicit CREATE, DELETE, or READ always has null diff
  if (action === 'CREATE' || action === 'DELETE' || action === 'READ') {
    return null;
  }

  // If either before or after is missing, infer CREATE or DELETE
  if (before === null || before === undefined || after === null || after === undefined) {
    return null;
  }

  const diff: RecordDiff = {};
  const allKeys = Array.from(
    new Set([...Object.keys(before), ...Object.keys(after)]),
  ).sort();

  for (const key of allKeys) {
    const oldVal = before[key];
    const newVal = after[key];

    if (oldVal === undefined && newVal === undefined) {
      continue;
    }

    const oldStr = oldVal === undefined ? undefined : stableStringify(oldVal);
    const newStr = newVal === undefined ? undefined : stableStringify(newVal);

    if (oldStr !== newStr) {
      diff[key] = {
        old: oldVal === undefined ? null : oldVal,
        new: newVal === undefined ? null : newVal,
      };
    }
  }

  return diff;
}
