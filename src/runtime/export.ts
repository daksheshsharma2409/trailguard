/**
 * exportAuditLogs — Streamed JSON and CSV export for audit logs.
 *
 * Implements cursor-based batching to export large audit log histories without
 * exhausting memory.
 * Sanitizes CSV values against formula injection (DDE attacks) by prefixing
 * cells that begin with =, +, -, @, \t, \r with a single quote (').
 * Properly escapes commas, double quotes, and newlines per RFC 4180.
 *
 * @see context.md §7.10, tasks.md T3.11
 */

import * as fs from 'node:fs';
import { once } from 'node:events';
import type { Writable } from 'node:stream';
import type { AuditAction } from '../core/types.js';

export interface ExportPrismaClient {
  auditLog: {
    findMany: (args: Record<string, unknown>) => Promise<Array<Record<string, unknown>>>;
  };
}

export interface ExportAuditLogsOptions {
  format?: 'json' | 'csv' | undefined;
  model?: string | undefined;
  recordId?: string | undefined;
  actorId?: string | undefined;
  action?: AuditAction | undefined;
  from?: Date | string | undefined;
  to?: Date | string | undefined;
  batchSize?: number | undefined;
}

export const CSV_COLUMNS = [
  'seq',
  'model',
  'recordId',
  'action',
  'actorId',
  'actorRole',
  'requestId',
  'ipAddress',
  'userAgent',
  'before',
  'after',
  'diff',
  'prevHash',
  'hash',
  'keyId',
  'createdAt',
] as const;

/**
 * Sanitize and escape a single CSV cell value.
 *
 * 1. Converts BigInt, Date, Objects to string.
 * 2. Prefixes cells beginning with =, +, -, @, \t, \r with a single quote (')
 *    to prevent spreadsheet formula injection.
 * 3. Encloses in double quotes and escapes existing quotes if cell contains
 *    commas, quotes, or newlines.
 */
export function escapeCsvCell(val: unknown): string {
  if (val === null || val === undefined) {
    return '';
  }

  let str: string;
  if (typeof val === 'bigint') {
    str = val.toString();
  } else if (val instanceof Date) {
    str = val.toISOString();
  } else if (typeof val === 'string') {
    str = val;
  } else if (typeof val === 'number' || typeof val === 'boolean') {
    str = String(val);
  } else if (typeof val === 'object') {
    str = JSON.stringify(val);
  } else {
    str = '';
  }

  // Formula injection prefix: prefix with ' if first character is =, +, -, @, \t, \r
  const firstChar = str.charAt(0);
  if (firstChar === '=' || firstChar === '+' || firstChar === '-' || firstChar === '@' || firstChar === '\t' || firstChar === '\r') {
    str = `'${str}`;
  }

  // Quote if contains comma, quote, or newline
  if (str.includes(',') || str.includes('"') || str.includes('\n') || str.includes('\r')) {
    return `"${str.replace(/"/g, '""')}"`;
  }

  return str;
}

/**
 * Serialize an audit row for JSON output, converting BigInt to string and Date to ISO.
 */
export function serializeRowForJson(row: Record<string, unknown>): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(row)) {
    if (typeof value === 'bigint') {
      result[key] = value.toString();
    } else if (value instanceof Date) {
      result[key] = value.toISOString();
    } else {
      result[key] = value;
    }
  }
  return result;
}

/**
 * Stream audit logs in cursor-paginated batches as JSON or CSV chunks.
 *
 * @param prisma - Prisma client with auditLog model.
 * @param options - Export options (format, filters, batchSize).
 * @returns AsyncIterable of string chunks.
 */
export async function* exportAuditLogs(
  prisma: ExportPrismaClient,
  options: ExportAuditLogsOptions = {},
): AsyncIterable<string> {
  const format = options.format ?? 'json';
  const batchSize = Math.max(1, Math.min(options.batchSize ?? 500, 5000));

  const where: Record<string, unknown> = {};
  if (options.model) where['model'] = options.model;
  if (options.recordId) where['recordId'] = options.recordId;
  if (options.actorId) where['actorId'] = options.actorId;
  if (options.action) where['action'] = options.action;

  if (options.from || options.to) {
    const createdAtFilter: Record<string, Date> = {};
    if (options.from) {
      createdAtFilter['gte'] = typeof options.from === 'string' ? new Date(options.from) : options.from;
    }
    if (options.to) {
      createdAtFilter['lte'] = typeof options.to === 'string' ? new Date(options.to) : options.to;
    }
    where['createdAt'] = createdAtFilter;
  }

  let lastSeq: bigint | undefined = undefined;
  let isFirstRecord = true;

  if (format === 'json') {
    yield '[\n';
  } else {
    yield CSV_COLUMNS.join(',') + '\n';
  }

  for (;;) {
    const findArgs: Record<string, unknown> = {
      where,
      orderBy: { seq: 'asc' },
      take: batchSize,
    };

    if (lastSeq !== undefined) {
      findArgs['cursor'] = { seq: lastSeq };
      findArgs['skip'] = 1;
    }

    const rows = await prisma.auditLog.findMany(findArgs);
    if (rows.length === 0) {
      break;
    }

    for (const row of rows) {
      if (format === 'json') {
        const serialized = serializeRowForJson(row);
        const jsonStr = JSON.stringify(serialized, null, 2)
          .split('\n')
          .map((line) => '  ' + line)
          .join('\n');

        if (!isFirstRecord) {
          yield ',\n' + jsonStr;
        } else {
          yield jsonStr;
          isFirstRecord = false;
        }
      } else {
        const line = CSV_COLUMNS.map((col) => escapeCsvCell(row[col])).join(',');
        yield line + '\n';
      }

      const seqVal = row['seq'];
      if (typeof seqVal === 'bigint') {
        lastSeq = seqVal;
      } else if (typeof seqVal === 'number' || typeof seqVal === 'string') {
        lastSeq = BigInt(seqVal);
      }
    }

    if (rows.length < batchSize) {
      break;
    }
  }

  if (format === 'json') {
    yield '\n]\n';
  }
}

/**
 * Stream exported audit logs directly to a Writable stream (e.g. Express Response or fs stream).
 */
export async function exportAuditLogsToStream(
  prisma: ExportPrismaClient,
  options: ExportAuditLogsOptions,
  writable: Writable,
): Promise<void> {
  for await (const chunk of exportAuditLogs(prisma, options)) {
    if (!writable.write(chunk)) {
      await once(writable, 'drain');
    }
  }
}

/**
 * Stream exported audit logs directly to a file on disk.
 */
export async function exportAuditLogsToFile(
  prisma: ExportPrismaClient,
  options: ExportAuditLogsOptions,
  filePath: string,
): Promise<void> {
  const stream = fs.createWriteStream(filePath, { encoding: 'utf-8' });
  const finishPromise = once(stream, 'finish');
  await exportAuditLogsToStream(prisma, options, stream);
  stream.end();
  await finishPromise;
}
