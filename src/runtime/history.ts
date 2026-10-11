/**
 * History query utility for trailguard runtime audit log.
 *
 * Queries audit entries for a given resource record ordered by sequence number.
 *
 * @see context.md §7.10, §7.12
 */

import type { AuditAction } from '../core/types.js';

export interface HistoryEntry {
  seq: bigint;
  model: string;
  recordId: string;
  action: AuditAction;
  actorId: string | null;
  actorRole: string | null;
  requestId: string | null;
  ipAddress: string | null;
  userAgent: string | null;
  payload: string;
  before: unknown;
  after: unknown;
  diff: unknown;
  prevHash: string;
  hash: string;
  keyId: string;
  createdAt: Date;
}

export interface HistoryPrismaClient {
  auditLog: {
    findMany: (args: {
      where: {
        model: string;
        recordId: string;
      };
      orderBy?: {
        seq: 'asc' | 'desc';
      };
      take?: number;
      skip?: number;
    }) => Promise<Array<Record<string, unknown>>>;
  };
}

export interface GetHistoryOptions {
  order?: 'asc' | 'desc' | undefined;
  limit?: number | undefined;
  skip?: number | undefined;
}

export interface RestorePreviewResult {
  model: string;
  recordId: string;
  action: AuditAction;
  seq: string;
  state: unknown;
}

/**
 * Retrieve the audit history for a specific model record.
 *
 * @param prisma - Prisma client instance.
 * @param model - Target model name (e.g. 'Student').
 * @param recordId - Target record ID.
 * @param options - Optional ordering and pagination parameters.
 * @returns Array of audit records ordered by seq.
 */
export async function getHistory(
  prisma: HistoryPrismaClient,
  model: string,
  recordId: string,
  options?: GetHistoryOptions,
): Promise<HistoryEntry[]> {
  const rows = await prisma.auditLog.findMany({
    where: {
      model,
      recordId,
    },
    orderBy: {
      seq: options?.order ?? 'asc',
    },
    ...(options?.limit !== undefined ? { take: options.limit } : {}),
    ...(options?.skip !== undefined ? { skip: options.skip } : {}),
  });

  return rows as unknown as HistoryEntry[];
}

/**
 * Retrieve the restore preview for a specific model record.
 * Uses the `before` state if the last recorded action was DELETE,
 * or the `after` state for CREATE/UPDATE.
 * Redacted fields remain in their stored redacted format.
 *
 * @param prisma - Prisma client instance.
 * @param model - Target model name.
 * @param recordId - Target record ID.
 * @returns RestorePreviewResult or null if record has never been audited.
 */
export async function getRestorePreview(
  prisma: HistoryPrismaClient,
  model: string,
  recordId: string,
): Promise<RestorePreviewResult | null> {
  const rows = await prisma.auditLog.findMany({
    where: {
      model,
      recordId,
    },
    orderBy: {
      seq: 'desc',
    },
    take: 1,
  });

  const lastEntry = rows[0];
  if (!lastEntry) {
    return null;
  }

  const rawState =
    lastEntry['action'] === 'DELETE' ? lastEntry['before'] : lastEntry['after'];

  let state = rawState;
  if (typeof state === 'string') {
    try {
      state = JSON.parse(state);
    } catch {
      // keep raw string
    }
  }

  const rawSeq = lastEntry['seq'];
  const seq =
    typeof rawSeq === 'bigint' || typeof rawSeq === 'number'
      ? rawSeq.toString()
      : typeof rawSeq === 'string'
        ? rawSeq
        : '';

  return {
    model,
    recordId,
    action: lastEntry['action'] as AuditAction,
    seq,
    state,
  };
}
