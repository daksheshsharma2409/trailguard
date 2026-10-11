/**
 * CLI command runner for `trailguard export`.
 *
 * Streams audit log records to stdout or a file in JSON or CSV format.
 *
 * @see tasks.md T3.11, T5.3
 */

import * as path from 'node:path';
import { resolvePrismaClient } from './prisma-client.js';
import {
  exportAuditLogsToStream,
  exportAuditLogsToFile,
  type ExportAuditLogsOptions,
  type ExportPrismaClient,
} from '../runtime/export.js';

export interface ExportCommandOptions {
  config?: string | undefined;
  format?: 'json' | 'csv' | undefined;
  out?: string | undefined;
  model?: string | undefined;
  recordId?: string | undefined;
  actorId?: string | undefined;
  from?: string | undefined;
  to?: string | undefined;
  cwd?: string | undefined;
}

export async function runExportCommand(
  opts: ExportCommandOptions = {},
): Promise<{ exitCode: number; message?: string }> {
  const cwd = opts.cwd ?? process.cwd();
  const format = opts.format ?? 'json';

  const prisma = await resolvePrismaClient(cwd);

  try {
    const exportOpts: ExportAuditLogsOptions = {
      format,
      model: opts.model,
      recordId: opts.recordId,
      actorId: opts.actorId,
      from: opts.from,
      to: opts.to,
    };

    if (opts.out) {
      const outPath = path.isAbsolute(opts.out) ? opts.out : path.resolve(cwd, opts.out);
      await exportAuditLogsToFile(prisma as unknown as ExportPrismaClient, exportOpts, outPath);
      return { exitCode: 0, message: `Exported audit logs to ${outPath}` };
    }

    // Stream to stdout
    await exportAuditLogsToStream(
      prisma as unknown as ExportPrismaClient,
      exportOpts,
      process.stdout,
    );

    return { exitCode: 0 };
  } finally {
    const disconnectable = prisma as unknown as { $disconnect?: () => Promise<void> };
    if (typeof disconnectable.$disconnect === 'function') {
      try {
        await disconnectable.$disconnect();
      } catch {
        // ignore disconnect error
      }
    }
  }
}
