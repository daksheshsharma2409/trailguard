/**
 * Audited Prisma Client extension.
 *
 * Intercepts create, update, delete, upsert operations on configured models
 * and records tamper-evident, HMAC-chained audit log entries atomically.
 *
 * @see context.md §7.5
 */

import { DEFAULT_KEY_ID, DEFAULT_MAX_BULK_ROWS } from '../core/constants.js';
import { AuditConfigError, AuditWriteError } from '../core/errors.js';
import type { AuditAction, AuditOptions, CheckpointSink } from '../core/types.js';
import { appendAuditEntries, ensureHeadRow, isHeadInitialized, type AppendedRecord, type AuditPrismaTx } from './append.js';
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

/**
 * Creates an audited Prisma client extension.
 *
 * **Known limitation:** Each audited operation runs in its own interactive transaction.
 * Operations invoked inside a caller-managed `$transaction` on the extended client are
 * not currently linked to that outer transaction.
 *
 * @param prisma - The base PrismaClient instance.
 * @param options - Auditing configuration (models, keys, redaction, etc.).
 * @returns An extended PrismaClient.
 */
export function createAuditClient<
  TClient extends {
    $extends: (extension: unknown) => unknown;
    $transaction: (
      fn: (tx: unknown) => Promise<unknown>,
      options?: { maxWait?: number; timeout?: number },
    ) => Promise<unknown>;
  },
>(prisma: TClient, options: AuditOptions): ReturnType<TClient['$extends']> {
  if (options.models.length === 0) {
    throw new AuditConfigError(
      'createAuditClient requires at least one model in options.models',
    );
  }

  const { currentKeyId, currentKey } = resolveKeys(options);
  const auditedModelSet = new Set(options.models.map((m) => m.toLowerCase()));

  function isAudited(model: string): boolean {
    return auditedModelSet.has(model.toLowerCase());
  }

  return prisma.$extends({
    name: 'trailguard-audit',
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
          const hasCustomSelection = Boolean(args['select'] || args['include']);
          const { select, include, ...strippedArgs } = args;
          const context = getAuditContext(options.onMissingContext ?? 'throw');

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

              const rawRow = await txDelegate.create(strippedArgs);
              const recordId = extractRecordId(model, rawRow, undefined, options.idFields);

              const redactedAfter = redactRecord(rawRow, {
                model,
                key: currentKey,
                redactFields: options.redactFields,
                redact: options.redact,
                ignoreFields: options.ignoreFields,
              });

              const appended = await appendAuditEntries(
                tx as unknown as AuditPrismaTx,
                [
                  {
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
                  },
                ],
                {
                  key: currentKey,
                  keyId: currentKeyId,
                  testHooks: options.testHooks,
                },
              );

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

              return { result: finalResult, appended };
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
          const hasCustomSelection = Boolean(args['select'] || args['include']);
          const { select, include, ...strippedArgs } = args;
          const where = args['where'] as Record<string, unknown> | undefined;
          const context = getAuditContext(options.onMissingContext ?? 'throw');

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

              const before = where ? await txDelegate.findUnique({ where }) : null;
              if (before === null) {
                // Let Prisma throw standard P2025 error
                return { result: await query(args), appended: [] };
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

              const appended = await appendAuditEntries(
                tx as unknown as AuditPrismaTx,
                [
                  {
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
                  },
                ],
                {
                  key: currentKey,
                  keyId: currentKeyId,
                  testHooks: options.testHooks,
                },
              );

              let finalResult: unknown = rawRow;
              if (hasCustomSelection && where) {
                finalResult = await txDelegate.findUnique({
                  where,
                  select,
                  include,
                });
              }

              return { result: finalResult, appended };
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
          const hasCustomSelection = Boolean(args['select'] || args['include']);
          const { select, include, ...strippedArgs } = args;
          const where = args['where'] as Record<string, unknown> | undefined;
          const context = getAuditContext(options.onMissingContext ?? 'throw');

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
                return { result: await query(args), appended: [] };
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

              const appended = await appendAuditEntries(
                tx as unknown as AuditPrismaTx,
                [
                  {
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
                  },
                ],
                {
                  key: currentKey,
                  keyId: currentKeyId,
                  testHooks: options.testHooks,
                },
              );

              return {
                result: hasCustomSelection ? shapedReturn : before,
                appended,
              };
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
          const hasCustomSelection = Boolean(args['select'] || args['include']);
          const { select, include, ...strippedArgs } = args;
          const where = args['where'] as Record<string, unknown> | undefined;
          const context = getAuditContext(options.onMissingContext ?? 'throw');

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

              const before = where ? await txDelegate.findUnique({ where }) : null;
              const action: AuditAction = before !== null ? 'UPDATE' : 'CREATE';

              const rawRow = await txDelegate.upsert(strippedArgs);
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
              const diff = createDiff(redactedBefore, redactedAfter, action);

              const appended = await appendAuditEntries(
                tx as unknown as AuditPrismaTx,
                [
                  {
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
                  },
                ],
                {
                  key: currentKey,
                  keyId: currentKeyId,
                  testHooks: options.testHooks,
                },
              );

              let finalResult: unknown = rawRow;
              if (hasCustomSelection && where) {
                finalResult = await txDelegate.findUnique({
                  where,
                  select,
                  include,
                });
              }

              return { result: finalResult, appended };
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
            return { count: 0 };
          }

          const delegate = toDelegateName(model);
          const context = getAuditContext(options.onMissingContext ?? 'throw');

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

              const entries = [];
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

              const appended = await appendAuditEntries(
                tx as unknown as AuditPrismaTx,
                entries,
                {
                  key: currentKey,
                  keyId: currentKeyId,
                  testHooks: options.testHooks,
                },
              );

              return { result: { count: dataArray.length }, appended };
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
          const where = (args['where'] as Record<string, unknown> | undefined) ?? {};
          const context = getAuditContext(options.onMissingContext ?? 'throw');
          const maxBulkRows = options.maxBulkRows ?? DEFAULT_MAX_BULK_ROWS;

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

              const beforeRows = await txDelegate.findMany({ where });
              if (beforeRows.length > maxBulkRows) {
                throw new AuditWriteError(
                  `updateMany matched ${beforeRows.length.toString()} rows which exceeds maxBulkRows limit of ${maxBulkRows.toString()}`,
                );
              }

              if (beforeRows.length === 0) {
                const res = await txDelegate.updateMany(args);
                return { result: res, appended: [] };
              }

              const updateRes = await txDelegate.updateMany(args);

              const idDef = options.idFields?.[model] ?? options.idFields?.[delegate] ?? 'id';
              const entries = [];

              for (const beforeRow of beforeRows) {
                const recordId = extractRecordId(model, beforeRow, undefined, options.idFields);

                const whereClause: Record<string, unknown> = {};
                if (Array.isArray(idDef)) {
                  for (const f of idDef) whereClause[f] = beforeRow[f];
                } else {
                  whereClause[idDef] = beforeRow[idDef];
                }

                const afterRow = (await txDelegate.findUnique({ where: whereClause })) ?? {
                  ...beforeRow,
                  ...(args['data'] as Record<string, unknown>),
                };

                const redactedBefore = redactRecord(beforeRow, {
                  model,
                  key: currentKey,
                  redactFields: options.redactFields,
                  redact: options.redact,
                  ignoreFields: options.ignoreFields,
                });
                const redactedAfter = redactRecord(afterRow, {
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

              const appended = await appendAuditEntries(
                tx as unknown as AuditPrismaTx,
                entries,
                {
                  key: currentKey,
                  keyId: currentKeyId,
                  testHooks: options.testHooks,
                },
              );

              return { result: updateRes, appended };
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
          const where = (args['where'] as Record<string, unknown> | undefined) ?? {};
          const context = getAuditContext(options.onMissingContext ?? 'throw');
          const maxBulkRows = options.maxBulkRows ?? DEFAULT_MAX_BULK_ROWS;

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

              const beforeRows = await txDelegate.findMany({ where });
              if (beforeRows.length > maxBulkRows) {
                throw new AuditWriteError(
                  `deleteMany matched ${beforeRows.length.toString()} rows which exceeds maxBulkRows limit of ${maxBulkRows.toString()}`,
                );
              }

              if (beforeRows.length === 0) {
                const res = await txDelegate.deleteMany(args);
                return { result: res, appended: [] };
              }

              const deleteRes = await txDelegate.deleteMany(args);
              const entries = [];

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

              const appended = await appendAuditEntries(
                tx as unknown as AuditPrismaTx,
                entries,
                {
                  key: currentKey,
                  keyId: currentKeyId,
                  testHooks: options.testHooks,
                },
              );

              return { result: deleteRes, appended };
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
  }) as ReturnType<TClient['$extends']>;
}
