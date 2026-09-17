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
