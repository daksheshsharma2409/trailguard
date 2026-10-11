/**
 * AuditChainService — Class façade for trailguard runtime audit log.
 *
 * Provides a clean object-oriented interface for:
 * - Manual logging (`log(entry, tx?)`) which can participate in caller-managed transactions.
 * - History queries (`getHistory(model, recordId)`).
 * - Chain verification (`verify()`).
 * - On-demand signed checkpoints (`checkpoint()`).
 * - Log export queries (`exportLogs()`).
 *
 * @see context.md §7.12
 */

import { AuditWriteError } from '../core/errors.js';
import type {
  AuditAction,
  AuditOptions,
  Checkpoint,
  VerifyResult,
} from '../core/types.js';
import {
  appendAuditEntries,
  ensureHeadRow,
  isHeadInitialized,
  type AppendedRecord,
  type AuditPrismaTx,
} from './append.js';
import { createCheckpoint } from './checkpoint.js';
import { resolveKeys, type NormalizedKeys } from './client.js';
import { getAuditContext } from './context.js';
import { createDiff } from './diff.js';
import { getHistory, type GetHistoryOptions, type HistoryEntry, type HistoryPrismaClient } from './history.js';
import { redactRecord } from './redact.js';
import { verifyAuditChain, type VerifyOptions, type VerifyPrismaClient } from './verify.js';
import {
  exportAuditLogs,
  exportAuditLogsToFile,
  type ExportAuditLogsOptions,
  type ExportPrismaClient,
} from './export.js';

export interface ManualLogInput {
  model: string;
  recordId: string;
  action: AuditAction;
  actorId?: string | null | undefined;
  actorRole?: string | null | undefined;
  requestId?: string | null | undefined;
  ipAddress?: string | null | undefined;
  userAgent?: string | null | undefined;
  before?: unknown;
  after?: unknown;
  diff?: unknown;
}

export interface AuditServicePrismaClient {
  auditLog: {
    findMany: (args: Record<string, unknown>) => Promise<Array<Record<string, unknown>>>;
    create?: (args: Record<string, unknown>) => Promise<unknown>;
  };
  auditHead: {
    findUnique?: (args: { where: { id: number } }) => Promise<{ lastSeq: bigint; lastHash: string } | null>;
    update?: (args: { where: { id: number }; data: { lastSeq: bigint; lastHash: string } }) => Promise<unknown>;
    createMany?: (args: { data: Array<{ id: number; lastSeq: bigint; lastHash: string }>; skipDuplicates?: boolean }) => Promise<unknown>;
  };
  $queryRaw?: <T = unknown>(query: TemplateStringsArray, ...values: unknown[]) => Promise<T>;
  $transaction: (
    fn: (tx: unknown) => Promise<unknown>,
    options?: { maxWait?: number; timeout?: number },
  ) => Promise<unknown>;
}

export interface ExportLogsOptions {
  model?: string | undefined;
  since?: Date | string | undefined;
  limit?: number | undefined;
}

function isPlainObject(val: unknown): val is Record<string, unknown> {
  return typeof val === 'object' && val !== null && !Array.isArray(val);
}

/**
 * Service façade for trailguard runtime operations.
 */
export class AuditChainService {
  private readonly prisma: AuditServicePrismaClient;
  private readonly options: AuditOptions;
  private readonly keys: NormalizedKeys;

  /**
   * Initializes the audit chain service.
   *
   * @param prisma - PrismaClient instance.
   * @param options - Audit configuration options.
   */
  constructor(prisma: AuditServicePrismaClient, options: AuditOptions) {
    this.prisma = prisma;
    this.options = options;
    this.keys = resolveKeys(options);
  }

  /**
   * Manually append an audit entry.
   *
   * If a transaction `tx` is provided, the append participates in the caller's transaction
   * and will commit or roll back with it. If `tx` is omitted, the append is executed inside
   * an internal transaction.
   *
   * @param entry - Audit log entry input.
   * @param tx - Optional caller-managed Prisma transaction client.
   * @returns Appended audit record.
   */
  async log(entry: ManualLogInput, tx?: AuditPrismaTx): Promise<AppendedRecord> {
    if (!entry.model || !entry.recordId) {
      throw new AuditWriteError('model and recordId are required for manual audit log');
    }

    const context = getAuditContext(this.options.onMissingContext ?? 'system');
    const actorId = entry.actorId !== undefined ? entry.actorId : (context.actorId ?? null);
    const actorRole = entry.actorRole !== undefined ? entry.actorRole : (context.actorRole ?? null);
    const requestId = entry.requestId !== undefined ? entry.requestId : (context.requestId ?? null);
    const ipAddress = entry.ipAddress !== undefined ? entry.ipAddress : (context.ipAddress ?? null);
    const userAgent = entry.userAgent !== undefined ? entry.userAgent : (context.userAgent ?? null);

    const redactedBefore: Record<string, unknown> | null = isPlainObject(entry.before)
      ? redactRecord(entry.before, {
          model: entry.model,
          key: this.keys.currentKey,
          redactFields: this.options.redactFields,
          redact: this.options.redact,
          ignoreFields: this.options.ignoreFields,
        })
      : null;

    const redactedAfter: Record<string, unknown> | null = isPlainObject(entry.after)
      ? redactRecord(entry.after, {
          model: entry.model,
          key: this.keys.currentKey,
          redactFields: this.options.redactFields,
          redact: this.options.redact,
          ignoreFields: this.options.ignoreFields,
        })
      : null;

    let diff = entry.diff;
    if (diff === undefined) {
      if (entry.action === 'UPDATE' || (redactedBefore !== null && redactedAfter !== null)) {
        diff = createDiff(redactedBefore, redactedAfter, entry.action);
      } else {
        diff = null;
      }
    }

    const appendInput = {
      model: entry.model,
      recordId: entry.recordId,
      action: entry.action,
      actorId,
      actorRole,
      requestId,
      ipAddress,
      userAgent,
      before: redactedBefore,
      after: redactedAfter,
      diff,
    };

    if (tx) {
      const records = await appendAuditEntries(
        tx,
        [appendInput],
        {
          key: this.keys.currentKey,
          keyId: this.keys.currentKeyId,
          testHooks: this.options.testHooks,
        },
      );
      const record = records[0];
      if (!record) {
        throw new AuditWriteError('Failed to append audit record');
      }
      await this.emitCheckpointIfDue(record);
      return record;
    }

    if (!isHeadInitialized()) {
      await ensureHeadRow(this.prisma as unknown as AuditPrismaTx);
    }

    const txRes = (await this.prisma.$transaction(
      async (innerTx) => {
        const records = await appendAuditEntries(
          innerTx as unknown as AuditPrismaTx,
          [appendInput],
          {
            key: this.keys.currentKey,
            keyId: this.keys.currentKeyId,
            testHooks: this.options.testHooks,
          },
        );
        const record = records[0];
        if (!record) {
          throw new AuditWriteError('Failed to append audit record');
        }
        return record;
      },
      {
        maxWait: this.options.tx?.maxWait ?? 5000,
        timeout: this.options.tx?.timeout ?? 10000,
      },
    )) as AppendedRecord;

    await this.emitCheckpointIfDue(txRes);
    return txRes;
  }

  /**
   * Retrieve audit history for a specific model record.
   *
   * @param model - Model name.
   * @param recordId - Record ID.
   * @param options - Ordering and pagination options.
   * @returns Array of history entries ordered by seq.
   */
  async getHistory(
    model: string,
    recordId: string,
    options?: GetHistoryOptions,
  ): Promise<HistoryEntry[]> {
    return getHistory(
      this.prisma as unknown as HistoryPrismaClient,
      model,
      recordId,
      options,
    );
  }

  /**
   * Verify the integrity of the audit chain.
   *
   * @param opts - Verification options.
   * @returns Verification result.
   */
  async verify(
    opts?: Partial<Omit<VerifyOptions, 'prisma' | 'keys'>>,
  ): Promise<VerifyResult> {
    return verifyAuditChain({
      prisma: this.prisma as unknown as VerifyPrismaClient,
      keys: this.options.keys,
      ...opts,
    });
  }

  /**
   * Create an on-demand signed checkpoint for the current chain head.
   *
   * @param now - Optional timestamp override for deterministic testing.
   * @returns The generated Checkpoint.
   */
  async checkpoint(now?: Date): Promise<Checkpoint> {
    const rawTx = this.prisma as unknown as AuditPrismaTx;
    if (typeof rawTx.$queryRaw !== 'function') {
      throw new AuditWriteError('PrismaClient does not support $queryRaw for checkpoint reading');
    }

    const headRows = await rawTx.$queryRaw<Array<{ lastSeq: bigint; lastHash: string }>>`
      SELECT lastSeq, lastHash FROM trailguard_audit_head WHERE id = 1
    `;
    const head = headRows[0];
    if (!head) {
      throw new AuditWriteError('Cannot create checkpoint: audit head row does not exist');
    }

    const cp = createCheckpoint(
      { seq: head.lastSeq, hash: head.lastHash },
      this.keys.currentKey,
      this.keys.currentKeyId,
      now,
    );

    if (this.options.checkpoint?.sink) {
      try {
        await Promise.resolve(this.options.checkpoint.sink(cp));
      } catch (err) {
        if (typeof this.options.onError === 'function' && err instanceof Error) {
          this.options.onError(err);
        }
      }
    }

    return cp;
  }

  /**
   * Query audit logs for export.
   *
   * @param options - Filter options (model, since, limit).
   * @returns Array of audit log records.
   */
  async exportLogs(options?: ExportLogsOptions): Promise<HistoryEntry[]> {
    const where: Record<string, unknown> = {};
    if (options?.model) {
      where['model'] = options.model;
    }
    if (options?.since) {
      const sinceDate = typeof options.since === 'string' ? new Date(options.since) : options.since;
      where['createdAt'] = { gte: sinceDate };
    }

    const rows = await this.prisma.auditLog.findMany({
      where,
      orderBy: { seq: 'asc' },
      ...(options?.limit !== undefined ? { take: options.limit } : {}),
    });

    return rows as unknown as HistoryEntry[];
  }

  /**
   * Stream audit logs as JSON or CSV chunks.
   *
   * @param options - Export options (format, filters, batchSize).
   * @returns AsyncIterable of string chunks.
   */
  exportStream(options?: ExportAuditLogsOptions): AsyncIterable<string> {
    return exportAuditLogs(this.prisma as unknown as ExportPrismaClient, options);
  }

  /**
   * Export audit logs directly to a file on disk.
   *
   * @param filePath - Output file path.
   * @param options - Export options (format, filters, batchSize).
   */
  async exportToFile(filePath: string, options?: ExportAuditLogsOptions): Promise<void> {
    await exportAuditLogsToFile(this.prisma as unknown as ExportPrismaClient, options ?? {}, filePath);
  }

  private async emitCheckpointIfDue(record: AppendedRecord): Promise<void> {
    if (!this.options.checkpoint || this.options.checkpoint.every <= 0) return;
    const cadence = BigInt(this.options.checkpoint.every);
    if (record.seq % cadence === 0n) {
      try {
        const cp = createCheckpoint(record, this.keys.currentKey, this.keys.currentKeyId);
        await Promise.resolve(this.options.checkpoint.sink(cp));
      } catch (err) {
        if (typeof this.options.onError === 'function' && err instanceof Error) {
          this.options.onError(err);
        }
      }
    }
  }
}
