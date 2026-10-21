/**
 * Audited Prisma Client extension.
 *
 * Intercepts create, update, delete, upsert operations on configured models
 * and records tamper-evident, HMAC-chained audit log entries atomically.
 *
 * Provides $auditedTransaction(fn) for batch multi-operation interactive transactions
 * under a single AuditHead lock.
 *
 * @see context.md §7.5, tasks.md T3.14
 */

import { DEFAULT_KEY_ID, DEFAULT_MAX_BULK_ROWS } from '../core/constants.js';
import { AuditConfigError, AuditWriteError } from '../core/errors.js';
import type { AuditAction, AuditOptions, CheckpointSink } from '../core/types.js';
import {
  appendAuditEntries,
  ensureHeadRow,
  isHeadInitialized,
  type AppendedRecord,
  type AuditPrismaTx,
  type AppendEntryInput,
} from './append.js';
import { createCheckpoint } from './checkpoint.js';
import { getAuditContext } from './context.js';
import { createDiff } from './diff.js';
import { redactRecord } from './redact.js';

/**
 * Convert a model name to its Prisma client delegate name (e.g. Student -> student).
 */
export function toDelegateName(modelName: string): string {
  if (!modelName) return modelName;
  return modelName.charAt(0).toLowerCase() + modelName.slice(1);
}

export interface NormalizedKeys {
  currentKeyId: string;
  currentKey: string;
}

export function resolveKeys(options: AuditOptions): NormalizedKeys {
  if ('secret' in options.keys) {
    if (!options.keys.secret) {
      throw new AuditConfigError('Secret in options.keys.secret must not be empty');
    }
    return {
      currentKeyId: DEFAULT_KEY_ID,
      currentKey: options.keys.secret,
    };
  }

  const { current, secrets } = options.keys;
  if (!current || !secrets[current]) {
    throw new AuditConfigError(
      `Current key '${current}' not found in options.keys.secrets`,
    );
  }

  return {
    currentKeyId: current,
    currentKey: secrets[current],
  };
}

function safeStringVal(val: unknown): string {
  if (val === undefined || val === null) return '';
  if (typeof val === 'string') return val;
  if (typeof val === 'number' || typeof val === 'bigint' || typeof val === 'boolean') {
    return String(val);
  }
  return JSON.stringify(val);
}

function extractRecordId(
  model: string,
  row: Record<string, unknown> | null | undefined,
  where: Record<string, unknown> | undefined,
  idFieldsConfig?: Record<string, string | string[]>,
): string {
  const delegate = toDelegateName(model);
  const idDef = idFieldsConfig?.[model] ?? idFieldsConfig?.[delegate] ?? 'id';

  if (Array.isArray(idDef)) {
    const parts = idDef.map((field) => {
      const val = row?.[field] ?? where?.[field];
      return safeStringVal(val);
    });
    return parts.join(':');
  }

  const val = row?.[idDef] ?? where?.[idDef];
  return safeStringVal(val);
}

interface ModelDelegate {
  create: (args: Record<string, unknown>) => Promise<Record<string, unknown>>;
  update: (args: Record<string, unknown>) => Promise<Record<string, unknown>>;
  delete: (args: Record<string, unknown>) => Promise<Record<string, unknown>>;
  upsert: (args: Record<string, unknown>) => Promise<Record<string, unknown>>;
  findUnique: (args: Record<string, unknown>) => Promise<Record<string, unknown> | null>;
  findFirst?: (args: Record<string, unknown>) => Promise<Record<string, unknown> | null>;
  createMany?: (args: Record<string, unknown>) => Promise<{ count: number }>;
  updateMany: (args: Record<string, unknown>) => Promise<{ count: number }>;
  deleteMany: (args: Record<string, unknown>) => Promise<{ count: number }>;
  findMany: (args: Record<string, unknown>) => Promise<Array<Record<string, unknown>>>;
}

async function emitCheckpointsIfDue(
  records: AppendedRecord[],
  checkpointConfig: { every: number; sink: CheckpointSink } | undefined,
  currentKey: string,
  currentKeyId: string,
  onError?: (e: Error) => void,
): Promise<void> {
  if (!checkpointConfig || checkpointConfig.every <= 0) return;
  const cadence = BigInt(checkpointConfig.every);

  for (const rec of records) {
    if (rec.seq % cadence === 0n) {
      try {
        const cp = createCheckpoint(rec, currentKey, currentKeyId);
        await Promise.resolve(checkpointConfig.sink(cp));
      } catch (err) {
        if (typeof onError === 'function' && err instanceof Error) {
          onError(err);
        }
      }
    }
  }
}

async function executeCreateOp(
  txDelegate: ModelDelegate,
  model: string,
  args: Record<string, unknown>,
  options: AuditOptions,
  currentKey: string,
): Promise<{ result: unknown; entry: AppendEntryInput | null }> {
  const delegate = toDelegateName(model);
  const hasCustomSelection = Boolean(args['select'] || args['include']);
  const { select, include, ...strippedArgs } = args;
  const context = getAuditContext(options.onMissingContext ?? 'throw');

  const rawRow = await txDelegate.create(strippedArgs);
  const recordId = extractRecordId(model, rawRow, undefined, options.idFields);

  const redactedAfter = redactRecord(rawRow, {
    model,
    key: currentKey,
    redactFields: options.redactFields,
    redact: options.redact,
    ignoreFields: options.ignoreFields,
  });

  const entry: AppendEntryInput = {
    model,
    recordId,
    action: 'CREATE' as AuditAction,
    actorId: context.actorId ?? null,
    actorRole: context.actorRole ?? null,
    requestId: context.requestId ?? null,
    ipAddress: context.ipAddress ?? null,
    userAgent: context.userAgent ?? null,
    before: null,
    after: redactedAfter,
    diff: null,
  };

  let finalResult: unknown = rawRow;
  if (hasCustomSelection) {
    const idDef = options.idFields?.[model] ?? options.idFields?.[delegate] ?? 'id';
    const whereClause: Record<string, unknown> = {};
    if (Array.isArray(idDef)) {
      for (const f of idDef) whereClause[f] = rawRow[f];
    } else {
      whereClause[idDef] = rawRow[idDef];
    }
    finalResult = await txDelegate.findUnique({
      where: whereClause,
      select,
      include,
    });
  }

  return { result: finalResult, entry };
}

async function executeUpdateOp(
  txDelegate: ModelDelegate,
  model: string,
  args: Record<string, unknown>,
  options: AuditOptions,
  currentKey: string,
): Promise<{ result: unknown; entry: AppendEntryInput | null }> {
  const hasCustomSelection = Boolean(args['select'] || args['include']);
  const { select, include, ...strippedArgs } = args;
  const where = args['where'] as Record<string, unknown> | undefined;
  const context = getAuditContext(options.onMissingContext ?? 'throw');

  const before = where ? await txDelegate.findUnique({ where }) : null;
  if (before === null) {
    // Let Prisma throw standard P2025 by running strippedArgs
    const res = await txDelegate.update(strippedArgs);
    return { result: res, entry: null };
  }

  const rawRow = await txDelegate.update(strippedArgs);
  const recordId = extractRecordId(model, rawRow, where, options.idFields);

  const redactedBefore = redactRecord(before, {
    model,
    key: currentKey,
    redactFields: options.redactFields,
    redact: options.redact,
    ignoreFields: options.ignoreFields,
  });
  const redactedAfter = redactRecord(rawRow, {
    model,
    key: currentKey,
    redactFields: options.redactFields,
    redact: options.redact,
    ignoreFields: options.ignoreFields,
  });
  const diff = createDiff(redactedBefore, redactedAfter, 'UPDATE');

  const entry: AppendEntryInput = {
    model,
    recordId,
    action: 'UPDATE' as AuditAction,
    actorId: context.actorId ?? null,
    actorRole: context.actorRole ?? null,
    requestId: context.requestId ?? null,
    ipAddress: context.ipAddress ?? null,
    userAgent: context.userAgent ?? null,
    before: redactedBefore,
    after: redactedAfter,
    diff,
  };

  let finalResult: unknown = rawRow;
  if (hasCustomSelection && where) {
    finalResult = await txDelegate.findUnique({
      where,
      select,
      include,
    });
  }

  return { result: finalResult, entry };
}

async function executeDeleteOp(
  txDelegate: ModelDelegate,
  model: string,
  args: Record<string, unknown>,
  options: AuditOptions,
  currentKey: string,
): Promise<{ result: unknown; entry: AppendEntryInput | null }> {
  const hasCustomSelection = Boolean(args['select'] || args['include']);
  const { select, include, ...strippedArgs } = args;
  const where = args['where'] as Record<string, unknown> | undefined;
  const context = getAuditContext(options.onMissingContext ?? 'throw');

  let shapedReturn: unknown = null;
  if (hasCustomSelection && where) {
    shapedReturn = await txDelegate.findUnique({
      where,
      select,
      include,
    });
  }

  const before = where ? await txDelegate.findUnique({ where }) : null;
  if (before === null) {
    const res = await txDelegate.delete(args);
    return { result: res, entry: null };
  }

  const recordId = extractRecordId(model, before, where, options.idFields);
  await txDelegate.delete(strippedArgs);

  const redactedBefore = redactRecord(before, {
    model,
    key: currentKey,
    redactFields: options.redactFields,
    redact: options.redact,
    ignoreFields: options.ignoreFields,
  });

  const entry: AppendEntryInput = {
    model,
    recordId,
    action: 'DELETE' as AuditAction,
    actorId: context.actorId ?? null,
    actorRole: context.actorRole ?? null,
    requestId: context.requestId ?? null,
    ipAddress: context.ipAddress ?? null,
    userAgent: context.userAgent ?? null,
    before: redactedBefore,
    after: null,
    diff: null,
  };

  return { result: hasCustomSelection ? shapedReturn : before, entry };
}

async function executeUpsertOp(
  txDelegate: ModelDelegate,
  model: string,
  args: Record<string, unknown>,
  options: AuditOptions,
  currentKey: string,
): Promise<{ result: unknown; entry: AppendEntryInput | null }> {
  const delegate = toDelegateName(model);
  const hasCustomSelection = Boolean(args['select'] || args['include']);
  const { select, include, ...strippedArgs } = args;
  const where = args['where'] as Record<string, unknown> | undefined;
  const context = getAuditContext(options.onMissingContext ?? 'throw');

  const before = where ? await txDelegate.findUnique({ where }) : null;
  const action: AuditAction = before !== null ? 'UPDATE' : 'CREATE';

  const rawRow = await txDelegate.upsert(strippedArgs);
  const recordId = extractRecordId(model, rawRow, where, options.idFields);

  const redactedBefore = before
    ? redactRecord(before, {
        model,
        key: currentKey,
        redactFields: options.redactFields,
        redact: options.redact,
        ignoreFields: options.ignoreFields,
      })
    : null;

  const redactedAfter = redactRecord(rawRow, {
    model,
    key: currentKey,
    redactFields: options.redactFields,
    redact: options.redact,
    ignoreFields: options.ignoreFields,
  });

  const diff = before ? createDiff(redactedBefore, redactedAfter, action) : null;

  const entry: AppendEntryInput = {
    model,
    recordId,
    action,
    actorId: context.actorId ?? null,
    actorRole: context.actorRole ?? null,
    requestId: context.requestId ?? null,
    ipAddress: context.ipAddress ?? null,
    userAgent: context.userAgent ?? null,
    before: redactedBefore,
    after: redactedAfter,
    diff,
  };

  let finalResult: unknown = rawRow;
  if (hasCustomSelection && where) {
    const idDef = options.idFields?.[model] ?? options.idFields?.[delegate] ?? 'id';
    const whereClause: Record<string, unknown> = {};
    if (Array.isArray(idDef)) {
      for (const f of idDef) whereClause[f] = rawRow[f];
    } else {
      whereClause[idDef] = rawRow[idDef];
    }
    finalResult = await txDelegate.findUnique({
      where: whereClause,
      select,
      include,
    });
  }

  return { result: finalResult, entry };
}

async function executeCreateManyOp(
  txDelegate: ModelDelegate,
  model: string,
  args: Record<string, unknown>,
  options: AuditOptions,
  currentKey: string,
): Promise<{ result: { count: number }; entries: AppendEntryInput[] }> {
  if (args['skipDuplicates']) {
    throw new AuditConfigError('createMany with skipDuplicates is not supported on audited models');
  }

  const rawData = args['data'];
  const dataArray: Array<Record<string, unknown>> = Array.isArray(rawData)
    ? (rawData as Array<Record<string, unknown>>)
    : rawData
      ? [rawData as Record<string, unknown>]
      : [];

  const maxBulkRows = options.maxBulkRows ?? DEFAULT_MAX_BULK_ROWS;
  if (dataArray.length > maxBulkRows) {
    throw new AuditWriteError(
      `createMany exceeded maxBulkRows limit of ${maxBulkRows.toString()} (attempted ${dataArray.length.toString()})`,
    );
  }

  if (dataArray.length === 0) {
    return { result: { count: 0 }, entries: [] };
  }

  const context = getAuditContext(options.onMissingContext ?? 'throw');
  const entries: AppendEntryInput[] = [];

  for (const item of dataArray) {
    const rawRow = await txDelegate.create({ data: item });
    const recordId = extractRecordId(model, rawRow, item, options.idFields);

    const redactedAfter = redactRecord(rawRow, {
      model,
      key: currentKey,
      redactFields: options.redactFields,
      redact: options.redact,
      ignoreFields: options.ignoreFields,
    });

    entries.push({
      model,
      recordId,
      action: 'CREATE' as AuditAction,
      actorId: context.actorId ?? null,
      actorRole: context.actorRole ?? null,
      requestId: context.requestId ?? null,
      ipAddress: context.ipAddress ?? null,
      userAgent: context.userAgent ?? null,
      before: null,
      after: redactedAfter,
      diff: null,
    });
  }

  return { result: { count: dataArray.length }, entries };
}

async function executeUpdateManyOp(
  txDelegate: ModelDelegate,
  model: string,
  args: Record<string, unknown>,
  options: AuditOptions,
  currentKey: string,
): Promise<{ result: unknown; entries: AppendEntryInput[] }> {
  const delegate = toDelegateName(model);
  const where = (args['where'] as Record<string, unknown> | undefined) ?? {};
  const context = getAuditContext(options.onMissingContext ?? 'throw');
  const maxBulkRows = options.maxBulkRows ?? DEFAULT_MAX_BULK_ROWS;

  const beforeRows = await txDelegate.findMany({ where });
  if (beforeRows.length > maxBulkRows) {
    throw new AuditWriteError(
      `updateMany matched ${beforeRows.length.toString()} rows which exceeds maxBulkRows limit of ${maxBulkRows.toString()}`,
    );
  }

  if (beforeRows.length === 0) {
    const res = await txDelegate.updateMany(args);
    return { result: res, entries: [] };
  }

  const updateRes = await txDelegate.updateMany(args);
  const idDef = options.idFields?.[model] ?? options.idFields?.[delegate] ?? 'id';
  const entries: AppendEntryInput[] = [];

  for (const beforeRow of beforeRows) {
    const recordId = extractRecordId(model, beforeRow, undefined, options.idFields);

    const whereClause: Record<string, unknown> = {};
    if (Array.isArray(idDef)) {
      for (const f of idDef) whereClause[f] = beforeRow[f];
    } else {
      whereClause[idDef] = beforeRow[idDef];
    }

    const rawAfter = await txDelegate.findUnique({ where: whereClause });
    if (!rawAfter) continue;

    const redactedBefore = redactRecord(beforeRow, {
      model,
      key: currentKey,
      redactFields: options.redactFields,
      redact: options.redact,
      ignoreFields: options.ignoreFields,
    });
    const redactedAfter = redactRecord(rawAfter, {
      model,
      key: currentKey,
      redactFields: options.redactFields,
      redact: options.redact,
      ignoreFields: options.ignoreFields,
    });
    const diff = createDiff(redactedBefore, redactedAfter, 'UPDATE');

    entries.push({
      model,
      recordId,
      action: 'UPDATE' as AuditAction,
      actorId: context.actorId ?? null,
      actorRole: context.actorRole ?? null,
      requestId: context.requestId ?? null,
      ipAddress: context.ipAddress ?? null,
      userAgent: context.userAgent ?? null,
      before: redactedBefore,
      after: redactedAfter,
      diff,
    });
  }

  return { result: updateRes, entries };
}

async function executeDeleteManyOp(
  txDelegate: ModelDelegate,
  model: string,
  args: Record<string, unknown>,
  options: AuditOptions,
  currentKey: string,
): Promise<{ result: unknown; entries: AppendEntryInput[] }> {
  const where = (args['where'] as Record<string, unknown> | undefined) ?? {};
  const context = getAuditContext(options.onMissingContext ?? 'throw');
  const maxBulkRows = options.maxBulkRows ?? DEFAULT_MAX_BULK_ROWS;

  const beforeRows = await txDelegate.findMany({ where });
  if (beforeRows.length > maxBulkRows) {
    throw new AuditWriteError(
      `deleteMany matched ${beforeRows.length.toString()} rows which exceeds maxBulkRows limit of ${maxBulkRows.toString()}`,
    );
  }

  if (beforeRows.length === 0) {
    const res = await txDelegate.deleteMany(args);
    return { result: res, entries: [] };
  }

  const deleteRes = await txDelegate.deleteMany(args);
  const entries: AppendEntryInput[] = [];

  for (const beforeRow of beforeRows) {
    const recordId = extractRecordId(model, beforeRow, undefined, options.idFields);
    const redactedBefore = redactRecord(beforeRow, {
      model,
      key: currentKey,
      redactFields: options.redactFields,
      redact: options.redact,
      ignoreFields: options.ignoreFields,
    });

    entries.push({
      model,
      recordId,
      action: 'DELETE' as AuditAction,
      actorId: context.actorId ?? null,
      actorRole: context.actorRole ?? null,
      requestId: context.requestId ?? null,
      ipAddress: context.ipAddress ?? null,
      userAgent: context.userAgent ?? null,
      before: redactedBefore,
      after: null,
      diff: null,
    });
  }

  return { result: deleteRes, entries };
}

async function executeFindSingleOp(
  txDelegate: ModelDelegate,
  model: string,
  args: Record<string, unknown> | undefined,
  options: AuditOptions,
  currentKey: string,
  op: 'findUnique' | 'findFirst' = 'findUnique',
): Promise<{ result: unknown; entry: AppendEntryInput | null }> {
  const safeArgs = args ?? {};
  const queryFn =
    op === 'findFirst' && typeof txDelegate.findFirst === 'function'
      ? txDelegate.findFirst.bind(txDelegate)
      : txDelegate.findUnique.bind(txDelegate);

  const rawRow = (await queryFn(safeArgs)) as Record<string, unknown> | null;
  if (!rawRow) {
    return { result: null, entry: null };
  }

  const context = getAuditContext(options.onMissingContext ?? 'throw');
  const where = safeArgs['where'] as Record<string, unknown> | undefined;
  const recordId = extractRecordId(model, rawRow, where, options.idFields);

  const redactedAfter = redactRecord(rawRow, {
    model,
    key: currentKey,
    redactFields: options.redactFields,
    redact: options.redact,
    ignoreFields: options.ignoreFields,
  });

  const entry: AppendEntryInput = {
    model,
    recordId,
    action: 'READ' as AuditAction,
    actorId: context.actorId ?? null,
    actorRole: context.actorRole ?? null,
    requestId: context.requestId ?? null,
    ipAddress: context.ipAddress ?? null,
    userAgent: context.userAgent ?? null,
    before: null,
    after: redactedAfter,
    diff: null,
  };

  return { result: rawRow, entry };
}

async function executeFindManyOp(
  txDelegate: ModelDelegate,
  model: string,
  args: Record<string, unknown> | undefined,
  options: AuditOptions,
  currentKey: string,
): Promise<{ result: unknown; entries: AppendEntryInput[] }> {
  const safeArgs = args ?? {};
  const rows = (await txDelegate.findMany(safeArgs)) as Array<Record<string, unknown>>;
  if (rows.length === 0) {
    return { result: rows, entries: [] };
  }

  const context = getAuditContext(options.onMissingContext ?? 'throw');
  const entries: AppendEntryInput[] = [];

  for (const row of rows) {
    const recordId = extractRecordId(model, row, undefined, options.idFields);
    const redactedAfter = redactRecord(row, {
      model,
      key: currentKey,
      redactFields: options.redactFields,
      redact: options.redact,
      ignoreFields: options.ignoreFields,
    });

    entries.push({
      model,
      recordId,
      action: 'READ' as AuditAction,
      actorId: context.actorId ?? null,
      actorRole: context.actorRole ?? null,
      requestId: context.requestId ?? null,
      ipAddress: context.ipAddress ?? null,
      userAgent: context.userAgent ?? null,
      before: null,
      after: redactedAfter,
      diff: null,
    });
  }

  return { result: rows, entries };
}

export interface AuditedClientExtension {
  $auditedTransaction<T>(
    fn: (tx: Record<string, unknown>) => Promise<T>,
    txOptions?: { maxWait?: number; timeout?: number },
  ): Promise<T>;
}

/**
 * Creates an audited Prisma client extension.
 *
 * Intercepts create, update, delete, upsert, and bulk operations on configured models.
 * For interactive multi-op transactions that share one transaction and head lock,
 * use `auditClient.$auditedTransaction(async (tx) => { ... })`.
 *
 * @param prisma - The base PrismaClient instance.
 * @param options - Auditing configuration (models, keys, redaction, etc.).
 * @returns An extended PrismaClient equipped with $auditedTransaction.
 */
export function createAuditClient<
  TClient extends {
    $extends: (extension: unknown) => unknown;
    $transaction: (
      fn: (tx: unknown) => Promise<unknown>,
      options?: { maxWait?: number; timeout?: number },
    ) => Promise<unknown>;
  },
>(
  prisma: TClient,
  options: AuditOptions,
): ReturnType<TClient['$extends']> & AuditedClientExtension {
  if (options.models.length === 0) {
    throw new AuditConfigError(
      'createAuditClient requires at least one model in options.models',
    );
  }

  const { currentKeyId, currentKey } = resolveKeys(options);
  const auditedModelSet = new Set(options.models.map((m) => m.toLowerCase()));
  const readAuditedModelSet = new Set(
    (options.readAuditModels ?? []).map((m) => m.toLowerCase()),
  );

  function isAudited(model: string): boolean {
    return auditedModelSet.has(model.toLowerCase());
  }

  function isReadAudited(model: string): boolean {
    return readAuditedModelSet.has(model.toLowerCase());
  }

  return prisma.$extends({
    name: 'trailguard-audit',
    client: {
      async $auditedTransaction<T>(
        this: unknown,
        fn: (tx: Record<string, unknown>) => Promise<T>,
        txOptions?: { maxWait?: number; timeout?: number },
      ): Promise<T> {
        if (!isHeadInitialized()) {
          await ensureHeadRow(prisma as unknown as AuditPrismaTx);
        }

        const txRes = (await prisma.$transaction(
          async (tx: unknown) => {
            const stagedEntries: AppendEntryInput[] = [];
            const txObj = tx as Record<string, unknown>;

            const auditedTx = new Proxy(txObj, {
              get(target, prop, receiver) {
                if (typeof prop !== 'string') {
                  return Reflect.get(target, prop, receiver) as unknown;
                }

                if (prop === '$auditedTransaction') {
                  return (nestedFn: (nestedTx: Record<string, unknown>) => Promise<unknown>) =>
                    nestedFn(auditedTx);
                }

                const propLower = prop.toLowerCase();
                if (!auditedModelSet.has(propLower) && !readAuditedModelSet.has(propLower)) {
                  const rawProp = Reflect.get(target, prop, receiver) as unknown;
                  return typeof rawProp === 'function'
                    ? (rawProp as (...args: unknown[]) => unknown).bind(target)
                    : rawProp;
                }

                const modelName =
                  options.models.find((m) => m.toLowerCase() === propLower) ??
                  options.readAuditModels?.find((m) => m.toLowerCase() === propLower) ??
                  prop;
                const delegate =
                  (target[prop] as ModelDelegate | undefined) ??
                  (target[toDelegateName(prop)] as ModelDelegate | undefined) ??
                  (target[modelName] as ModelDelegate | undefined);

                if (!delegate || typeof delegate !== 'object') {
                  return Reflect.get(target, prop, receiver) as unknown;
                }

                return new Proxy(delegate, {
                  get(delTarget, method, delReceiver) {
                    if (typeof method !== 'string') {
                      return Reflect.get(delTarget, method, delReceiver) as unknown;
                    }

                    if (method === 'create') {
                      return async (args: Record<string, unknown>) => {
                        const { result, entry } = await executeCreateOp(
                          delTarget,
                          modelName,
                          args,
                          options,
                          currentKey,
                        );
                        if (entry) stagedEntries.push(entry);
                        return result;
                      };
                    }

                    if (method === 'update') {
                      return async (args: Record<string, unknown>) => {
                        const { result, entry } = await executeUpdateOp(
                          delTarget,
                          modelName,
                          args,
                          options,
                          currentKey,
                        );
                        if (entry) stagedEntries.push(entry);
                        return result;
                      };
                    }

                    if (method === 'delete') {
                      return async (args: Record<string, unknown>) => {
                        const { result, entry } = await executeDeleteOp(
                          delTarget,
                          modelName,
                          args,
                          options,
                          currentKey,
                        );
                        if (entry) stagedEntries.push(entry);
                        return result;
                      };
                    }

                    if (method === 'upsert') {
                      return async (args: Record<string, unknown>) => {
                        const { result, entry } = await executeUpsertOp(
                          delTarget,
                          modelName,
                          args,
                          options,
                          currentKey,
                        );
                        if (entry) stagedEntries.push(entry);
                        return result;
                      };
                    }

                    if (method === 'createMany') {
                      return async (args: Record<string, unknown>) => {
                        const { result, entries } = await executeCreateManyOp(
                          delTarget,
                          modelName,
                          args,
                          options,
                          currentKey,
                        );
                        stagedEntries.push(...entries);
                        return result;
                      };
                    }

                    if (method === 'updateMany') {
                      return async (args: Record<string, unknown>) => {
                        const { result, entries } = await executeUpdateManyOp(
                          delTarget,
                          modelName,
                          args,
                          options,
                          currentKey,
                        );
                        stagedEntries.push(...entries);
                        return result;
                      };
                    }

                    if (method === 'deleteMany') {
                      return async (args: Record<string, unknown>) => {
                        const { result, entries } = await executeDeleteManyOp(
                          delTarget,
                          modelName,
                          args,
                          options,
                          currentKey,
                        );
                        stagedEntries.push(...entries);
                        return result;
                      };
                    }

                    if (method === 'findUnique') {
                      if (isReadAudited(modelName)) {
                        return async (args?: Record<string, unknown>) => {
                          const { result, entry } = await executeFindSingleOp(
                            delTarget,
                            modelName,
                            args,
                            options,
                            currentKey,
                            'findUnique',
                          );
                          if (entry) stagedEntries.push(entry);
                          return result;
                        };
                      }
                      const rawMethod = Reflect.get(delTarget, method, delReceiver) as unknown;
                      return typeof rawMethod === 'function'
                        ? (rawMethod as (...args: unknown[]) => unknown).bind(delTarget)
                        : rawMethod;
                    }

                    if (method === 'findFirst') {
                      if (isReadAudited(modelName)) {
                        return async (args?: Record<string, unknown>) => {
                          const { result, entry } = await executeFindSingleOp(
                            delTarget,
                            modelName,
                            args,
                            options,
                            currentKey,
                            'findFirst',
                          );
                          if (entry) stagedEntries.push(entry);
                          return result;
                        };
                      }
                      const rawMethod = Reflect.get(delTarget, method, delReceiver) as unknown;
                      return typeof rawMethod === 'function'
                        ? (rawMethod as (...args: unknown[]) => unknown).bind(delTarget)
                        : rawMethod;
                    }

                    if (method === 'findMany') {
                      if (isReadAudited(modelName)) {
                        return async (args?: Record<string, unknown>) => {
                          const { result, entries } = await executeFindManyOp(
                            delTarget,
                            modelName,
                            args,
                            options,
                            currentKey,
                          );
                          stagedEntries.push(...entries);
                          return result;
                        };
                      }
                      const rawMethod = Reflect.get(delTarget, method, delReceiver) as unknown;
                      return typeof rawMethod === 'function'
                        ? (rawMethod as (...args: unknown[]) => unknown).bind(delTarget)
                        : rawMethod;
                    }

                    const rawMethod = Reflect.get(delTarget, method, delReceiver) as unknown;
                    return typeof rawMethod === 'function'
                      ? (rawMethod as (...args: unknown[]) => unknown).bind(delTarget)
                      : rawMethod;
                  },
                });
              },
            });

            const result = await fn(auditedTx as unknown as Record<string, unknown>);

            let appended: AppendedRecord[] = [];
            if (stagedEntries.length > 0) {
              appended = await appendAuditEntries(
                tx as unknown as AuditPrismaTx,
                stagedEntries,
                {
                  key: currentKey,
                  keyId: currentKeyId,
                  testHooks: options.testHooks,
                },
              );
            }

            return { result, appended };
          },
          {
            maxWait: txOptions?.maxWait ?? options.tx?.maxWait ?? 5000,
            timeout: txOptions?.timeout ?? options.tx?.timeout ?? 10000,
          },
        )) as { result: T; appended: AppendedRecord[] };

        await emitCheckpointsIfDue(
          txRes.appended,
          options.checkpoint,
          currentKey,
          currentKeyId,
          options.onError,
        );

        return txRes.result;
      },
    },
    query: {
      $allModels: {
        async create(
          this: unknown,
          {
            model,
            args,
            query,
          }: {
            model: string;
            args: Record<string, unknown>;
            query: (args: Record<string, unknown>) => Promise<unknown>;
          },
        ) {
          if (!isAudited(model)) {
            return query(args);
          }

          const delegate = toDelegateName(model);
          if (!isHeadInitialized()) {
            await ensureHeadRow(prisma as unknown as AuditPrismaTx);
          }

          const txRes = (await prisma.$transaction(
            async (tx: unknown) => {
              const txObj = tx as Record<string, ModelDelegate | undefined>;
              const txDelegate = txObj[delegate];
              if (!txDelegate) {
                return { result: await query(args), appended: [] };
              }

              const { result, entry } = await executeCreateOp(
                txDelegate,
                model,
                args,
                options,
                currentKey,
              );

              let appended: AppendedRecord[] = [];
              if (entry) {
                appended = await appendAuditEntries(
                  tx as unknown as AuditPrismaTx,
                  [entry],
                  {
                    key: currentKey,
                    keyId: currentKeyId,
                    testHooks: options.testHooks,
                  },
                );
              }

              return { result, appended };
            },
            {
              maxWait: options.tx?.maxWait ?? 5000,
              timeout: options.tx?.timeout ?? 10000,
            },
          )) as { result: unknown; appended: AppendedRecord[] };

          await emitCheckpointsIfDue(
            txRes.appended,
            options.checkpoint,
            currentKey,
            currentKeyId,
            options.onError,
          );

          return txRes.result;
        },

        async update(
          this: unknown,
          {
            model,
            args,
            query,
          }: {
            model: string;
            args: Record<string, unknown>;
            query: (args: Record<string, unknown>) => Promise<unknown>;
          },
        ) {
          if (!isAudited(model)) {
            return query(args);
          }

          const delegate = toDelegateName(model);
          if (!isHeadInitialized()) {
            await ensureHeadRow(prisma as unknown as AuditPrismaTx);
          }

          const txRes = (await prisma.$transaction(
            async (tx: unknown) => {
              const txObj = tx as Record<string, ModelDelegate | undefined>;
              const txDelegate = txObj[delegate];
              if (!txDelegate) {
                return { result: await query(args), appended: [] };
              }

              const { result, entry } = await executeUpdateOp(
                txDelegate,
                model,
                args,
                options,
                currentKey,
              );

              let appended: AppendedRecord[] = [];
              if (entry) {
                appended = await appendAuditEntries(
                  tx as unknown as AuditPrismaTx,
                  [entry],
                  {
                    key: currentKey,
                    keyId: currentKeyId,
                    testHooks: options.testHooks,
                  },
                );
              }

              return { result, appended };
            },
            {
              maxWait: options.tx?.maxWait ?? 5000,
              timeout: options.tx?.timeout ?? 10000,
            },
          )) as { result: unknown; appended: AppendedRecord[] };

          await emitCheckpointsIfDue(
            txRes.appended,
            options.checkpoint,
            currentKey,
            currentKeyId,
            options.onError,
          );

          return txRes.result;
        },

        async delete(
          this: unknown,
          {
            model,
            args,
            query,
          }: {
            model: string;
            args: Record<string, unknown>;
            query: (args: Record<string, unknown>) => Promise<unknown>;
          },
        ) {
          if (!isAudited(model)) {
            return query(args);
          }

          const delegate = toDelegateName(model);
          if (!isHeadInitialized()) {
            await ensureHeadRow(prisma as unknown as AuditPrismaTx);
          }

          const txRes = (await prisma.$transaction(
            async (tx: unknown) => {
              const txObj = tx as Record<string, ModelDelegate | undefined>;
              const txDelegate = txObj[delegate];
              if (!txDelegate) {
                return { result: await query(args), appended: [] };
              }

              const { result, entry } = await executeDeleteOp(
                txDelegate,
                model,
                args,
                options,
                currentKey,
              );

              let appended: AppendedRecord[] = [];
              if (entry) {
                appended = await appendAuditEntries(
                  tx as unknown as AuditPrismaTx,
                  [entry],
                  {
                    key: currentKey,
                    keyId: currentKeyId,
                    testHooks: options.testHooks,
                  },
                );
              }

              return { result, appended };
            },
            {
              maxWait: options.tx?.maxWait ?? 5000,
              timeout: options.tx?.timeout ?? 10000,
            },
          )) as { result: unknown; appended: AppendedRecord[] };

          await emitCheckpointsIfDue(
            txRes.appended,
            options.checkpoint,
            currentKey,
            currentKeyId,
            options.onError,
          );

          return txRes.result;
        },

        async upsert(
          this: unknown,
          {
            model,
            args,
            query,
          }: {
            model: string;
            args: Record<string, unknown>;
            query: (args: Record<string, unknown>) => Promise<unknown>;
          },
        ) {
          if (!isAudited(model)) {
            return query(args);
          }

          const delegate = toDelegateName(model);
          if (!isHeadInitialized()) {
            await ensureHeadRow(prisma as unknown as AuditPrismaTx);
          }

          const txRes = (await prisma.$transaction(
            async (tx: unknown) => {
              const txObj = tx as Record<string, ModelDelegate | undefined>;
              const txDelegate = txObj[delegate];
              if (!txDelegate) {
                return { result: await query(args), appended: [] };
              }

              const { result, entry } = await executeUpsertOp(
                txDelegate,
                model,
                args,
                options,
                currentKey,
              );

              let appended: AppendedRecord[] = [];
              if (entry) {
                appended = await appendAuditEntries(
                  tx as unknown as AuditPrismaTx,
                  [entry],
                  {
                    key: currentKey,
                    keyId: currentKeyId,
                    testHooks: options.testHooks,
                  },
                );
              }

              return { result, appended };
            },
            {
              maxWait: options.tx?.maxWait ?? 5000,
              timeout: options.tx?.timeout ?? 10000,
            },
          )) as { result: unknown; appended: AppendedRecord[] };

          await emitCheckpointsIfDue(
            txRes.appended,
            options.checkpoint,
            currentKey,
            currentKeyId,
            options.onError,
          );

          return txRes.result;
        },

        async createMany(
          this: unknown,
          {
            model,
            args,
            query,
          }: {
            model: string;
            args: Record<string, unknown>;
            query: (args: Record<string, unknown>) => Promise<unknown>;
          },
        ) {
          if (!isAudited(model)) {
            return query(args);
          }

          const delegate = toDelegateName(model);
          if (!isHeadInitialized()) {
            await ensureHeadRow(prisma as unknown as AuditPrismaTx);
          }

          const txRes = (await prisma.$transaction(
            async (tx: unknown) => {
              const txObj = tx as Record<string, ModelDelegate | undefined>;
              const txDelegate = txObj[delegate];
              if (!txDelegate) {
                return { result: await query(args), appended: [] };
              }

              const { result, entries } = await executeCreateManyOp(
                txDelegate,
                model,
                args,
                options,
                currentKey,
              );

              let appended: AppendedRecord[] = [];
              if (entries.length > 0) {
                appended = await appendAuditEntries(
                  tx as unknown as AuditPrismaTx,
                  entries,
                  {
                    key: currentKey,
                    keyId: currentKeyId,
                    testHooks: options.testHooks,
                  },
                );
              }

              return { result, appended };
            },
            {
              maxWait: options.tx?.maxWait ?? 5000,
              timeout: options.tx?.timeout ?? 10000,
            },
          )) as { result: unknown; appended: AppendedRecord[] };

          await emitCheckpointsIfDue(
            txRes.appended,
            options.checkpoint,
            currentKey,
            currentKeyId,
            options.onError,
          );

          return txRes.result;
        },

        async updateMany(
          this: unknown,
          {
            model,
            args,
            query,
          }: {
            model: string;
            args: Record<string, unknown>;
            query: (args: Record<string, unknown>) => Promise<unknown>;
          },
        ) {
          if (!isAudited(model)) {
            return query(args);
          }

          const delegate = toDelegateName(model);
          if (!isHeadInitialized()) {
            await ensureHeadRow(prisma as unknown as AuditPrismaTx);
          }

          const txRes = (await prisma.$transaction(
            async (tx: unknown) => {
              const txObj = tx as Record<string, ModelDelegate | undefined>;
              const txDelegate = txObj[delegate];
              if (!txDelegate) {
                return { result: await query(args), appended: [] };
              }

              const { result, entries } = await executeUpdateManyOp(
                txDelegate,
                model,
                args,
                options,
                currentKey,
              );

              let appended: AppendedRecord[] = [];
              if (entries.length > 0) {
                appended = await appendAuditEntries(
                  tx as unknown as AuditPrismaTx,
                  entries,
                  {
                    key: currentKey,
                    keyId: currentKeyId,
                    testHooks: options.testHooks,
                  },
                );
              }

              return { result, appended };
            },
            {
              maxWait: options.tx?.maxWait ?? 5000,
              timeout: options.tx?.timeout ?? 10000,
            },
          )) as { result: unknown; appended: AppendedRecord[] };

          await emitCheckpointsIfDue(
            txRes.appended,
            options.checkpoint,
            currentKey,
            currentKeyId,
            options.onError,
          );

          return txRes.result;
        },

        async deleteMany(
          this: unknown,
          {
            model,
            args,
            query,
          }: {
            model: string;
            args: Record<string, unknown>;
            query: (args: Record<string, unknown>) => Promise<unknown>;
          },
        ) {
          if (!isAudited(model)) {
            return query(args);
          }

          const delegate = toDelegateName(model);
          if (!isHeadInitialized()) {
            await ensureHeadRow(prisma as unknown as AuditPrismaTx);
          }

          const txRes = (await prisma.$transaction(
            async (tx: unknown) => {
              const txObj = tx as Record<string, ModelDelegate | undefined>;
              const txDelegate = txObj[delegate];
              if (!txDelegate) {
                return { result: await query(args), appended: [] };
              }

              const { result, entries } = await executeDeleteManyOp(
                txDelegate,
                model,
                args,
                options,
                currentKey,
              );

              let appended: AppendedRecord[] = [];
              if (entries.length > 0) {
                appended = await appendAuditEntries(
                  tx as unknown as AuditPrismaTx,
                  entries,
                  {
                    key: currentKey,
                    keyId: currentKeyId,
                    testHooks: options.testHooks,
                  },
                );
              }

              return { result, appended };
            },
            {
              maxWait: options.tx?.maxWait ?? 5000,
              timeout: options.tx?.timeout ?? 10000,
            },
          )) as { result: unknown; appended: AppendedRecord[] };

          await emitCheckpointsIfDue(
            txRes.appended,
            options.checkpoint,
            currentKey,
            currentKeyId,
            options.onError,
          );

          return txRes.result;
        },

        async findUnique(
          this: unknown,
          {
            model,
            args,
            query,
          }: {
            model: string;
            args: Record<string, unknown>;
            query: (args: Record<string, unknown>) => Promise<unknown>;
          },
        ) {
          if (!isReadAudited(model)) {
            return query(args);
          }

          const delegate = toDelegateName(model);
          if (!isHeadInitialized()) {
            await ensureHeadRow(prisma as unknown as AuditPrismaTx);
          }

          const txRes = (await prisma.$transaction(
            async (tx: unknown) => {
              const txObj = tx as Record<string, ModelDelegate | undefined>;
              const txDelegate = txObj[delegate];
              if (!txDelegate) {
                return { result: await query(args), appended: [] };
              }

              const { result, entry } = await executeFindSingleOp(
                txDelegate,
                model,
                args,
                options,
                currentKey,
                'findUnique',
              );

              let appended: AppendedRecord[] = [];
              if (entry) {
                appended = await appendAuditEntries(
                  tx as unknown as AuditPrismaTx,
                  [entry],
                  {
                    key: currentKey,
                    keyId: currentKeyId,
                    testHooks: options.testHooks,
                  },
                );
              }

              return { result, appended };
            },
            {
              maxWait: options.tx?.maxWait ?? 5000,
              timeout: options.tx?.timeout ?? 10000,
            },
          )) as { result: unknown; appended: AppendedRecord[] };

          await emitCheckpointsIfDue(
            txRes.appended,
            options.checkpoint,
            currentKey,
            currentKeyId,
            options.onError,
          );

          return txRes.result;
        },

        async findFirst(
          this: unknown,
          {
            model,
            args,
            query,
          }: {
            model: string;
            args: Record<string, unknown>;
            query: (args: Record<string, unknown>) => Promise<unknown>;
          },
        ) {
          if (!isReadAudited(model)) {
            return query(args);
          }

          const delegate = toDelegateName(model);
          if (!isHeadInitialized()) {
            await ensureHeadRow(prisma as unknown as AuditPrismaTx);
          }

          const txRes = (await prisma.$transaction(
            async (tx: unknown) => {
              const txObj = tx as Record<string, ModelDelegate | undefined>;
              const txDelegate = txObj[delegate];
              if (!txDelegate) {
                return { result: await query(args), appended: [] };
              }

              const { result, entry } = await executeFindSingleOp(
                txDelegate,
                model,
                args,
                options,
                currentKey,
                'findFirst',
              );

              let appended: AppendedRecord[] = [];
              if (entry) {
                appended = await appendAuditEntries(
                  tx as unknown as AuditPrismaTx,
                  [entry],
                  {
                    key: currentKey,
                    keyId: currentKeyId,
                    testHooks: options.testHooks,
                  },
                );
              }

              return { result, appended };
            },
            {
              maxWait: options.tx?.maxWait ?? 5000,
              timeout: options.tx?.timeout ?? 10000,
            },
          )) as { result: unknown; appended: AppendedRecord[] };

          await emitCheckpointsIfDue(
            txRes.appended,
            options.checkpoint,
            currentKey,
            currentKeyId,
            options.onError,
          );

          return txRes.result;
        },

        async findMany(
          this: unknown,
          {
            model,
            args,
            query,
          }: {
            model: string;
            args: Record<string, unknown>;
            query: (args: Record<string, unknown>) => Promise<unknown>;
          },
        ) {
          if (!isReadAudited(model)) {
            return query(args);
          }

          const delegate = toDelegateName(model);
          if (!isHeadInitialized()) {
            await ensureHeadRow(prisma as unknown as AuditPrismaTx);
          }

          const txRes = (await prisma.$transaction(
            async (tx: unknown) => {
              const txObj = tx as Record<string, ModelDelegate | undefined>;
              const txDelegate = txObj[delegate];
              if (!txDelegate) {
                return { result: await query(args), appended: [] };
              }

              const { result, entries } = await executeFindManyOp(
                txDelegate,
                model,
                args,
                options,
                currentKey,
              );

              let appended: AppendedRecord[] = [];
              if (entries.length > 0) {
                appended = await appendAuditEntries(
                  tx as unknown as AuditPrismaTx,
                  entries,
                  {
                    key: currentKey,
                    keyId: currentKeyId,
                    testHooks: options.testHooks,
                  },
                );
              }

              return { result, appended };
            },
            {
              maxWait: options.tx?.maxWait ?? 5000,
              timeout: options.tx?.timeout ?? 10000,
            },
          )) as { result: unknown; appended: AppendedRecord[] };

          await emitCheckpointsIfDue(
            txRes.appended,
            options.checkpoint,
            currentKey,
            currentKeyId,
            options.onError,
          );

          return txRes.result;
        },
      },
    },
  }) as ReturnType<TClient['$extends']> & AuditedClientExtension;
}
