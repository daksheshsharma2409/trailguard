/**
 * Audited Prisma Client extension.
 *
 * Intercepts create, update, delete, upsert operations on configured models
 * and records tamper-evident, HMAC-chained audit log entries atomically.
 *
 * @see context.md §7.5
 */

import { DEFAULT_KEY_ID } from '../core/constants.js';
import { AuditConfigError } from '../core/errors.js';
import type { AuditAction, AuditOptions } from '../core/types.js';
import { appendAuditEntries, type AuditPrismaTx } from './append.js';
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

interface NormalizedKeys {
  currentKeyId: string;
  currentKey: string;
}

function resolveKeys(options: AuditOptions): NormalizedKeys {
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

          return prisma.$transaction(
            async (tx: unknown) => {
              const txObj = tx as Record<string, ModelDelegate | undefined>;
              const txDelegate = txObj[delegate];
              if (!txDelegate) {
                return query(args);
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

              await appendAuditEntries(
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

              if (hasCustomSelection) {
                const idDef = options.idFields?.[model] ?? options.idFields?.[delegate] ?? 'id';
                const whereClause: Record<string, unknown> = {};
                if (Array.isArray(idDef)) {
                  for (const f of idDef) whereClause[f] = rawRow[f];
                } else {
                  whereClause[idDef] = rawRow[idDef];
                }
                return txDelegate.findUnique({
                  where: whereClause,
                  select,
                  include,
                });
              }

              return rawRow;
            },
            {
              maxWait: options.tx?.maxWait ?? 5000,
              timeout: options.tx?.timeout ?? 10000,
            },
          );
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

          return prisma.$transaction(
            async (tx: unknown) => {
              const txObj = tx as Record<string, ModelDelegate | undefined>;
              const txDelegate = txObj[delegate];
              if (!txDelegate) {
                return query(args);
              }

              const before = where ? await txDelegate.findUnique({ where }) : null;
              if (before === null) {
                // Let Prisma throw standard P2025 error
                return query(args);
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

              await appendAuditEntries(
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

              if (hasCustomSelection && where) {
                return txDelegate.findUnique({
                  where,
                  select,
                  include,
                });
              }

              return rawRow;
            },
            {
              maxWait: options.tx?.maxWait ?? 5000,
              timeout: options.tx?.timeout ?? 10000,
            },
          );
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

          return prisma.$transaction(
            async (tx: unknown) => {
              const txObj = tx as Record<string, ModelDelegate | undefined>;
              const txDelegate = txObj[delegate];
              if (!txDelegate) {
                return query(args);
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
                return query(args);
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

              await appendAuditEntries(
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

              return hasCustomSelection ? shapedReturn : before;
            },
            {
              maxWait: options.tx?.maxWait ?? 5000,
              timeout: options.tx?.timeout ?? 10000,
            },
          );
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

          return prisma.$transaction(
            async (tx: unknown) => {
              const txObj = tx as Record<string, ModelDelegate | undefined>;
              const txDelegate = txObj[delegate];
              if (!txDelegate) {
                return query(args);
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

              await appendAuditEntries(
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

              if (hasCustomSelection && where) {
                return txDelegate.findUnique({
                  where,
                  select,
                  include,
                });
              }

              return rawRow;
            },
            {
              maxWait: options.tx?.maxWait ?? 5000,
              timeout: options.tx?.timeout ?? 10000,
            },
          );
        },
      },
    },
  }) as ReturnType<TClient['$extends']>;
}
