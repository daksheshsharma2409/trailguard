/**
 * Core implementation of `trailguard ci` CLI command.
 *
 * Runs scan → verify → drift in sequence:
 * - Collects results from each stage into one summary table
 * - Exit code is max(sub-exit codes): 0 if all pass, 1 if findings/tampered, 2 if tool error
 * - `--no-db` skips verify and drift with a loud visible warning
 * - `--format` and `--out` apply to the scan report
 *
 * @see context.md §4.4, §4.5, tasks.md T5.2
 */

import * as path from 'node:path';
import { scan, type ScanOutput } from '../scan/index.js';
import { runVerifyCommand, type VerifyCommandOutcome } from './verify-command.js';
import { runDriftCommand, type DriftCommandOutcome } from './drift-command.js';
import type { Risk } from '../core/types.js';
import type { VerifyPrismaClient } from '../runtime/verify.js';
import type { DriftPrismaClient } from '../scan/drift.js';
import { resolvePrismaClient } from './prisma-client.js';
import { loadDotenvIfPresent } from './env.js';

export interface CiCommandOptions {
  config?: string | undefined;
  src?: string | undefined;
  noDb?: boolean | undefined;
  db?: boolean | undefined; // Passed from commander when --no-db is handled
  format?: 'md' | 'json' | 'sarif' | undefined;
  out?: string | undefined;
  failOn?: Risk | 'none' | undefined;
  baseline?: string | undefined;
  updateBaseline?: boolean | undefined;
  checkpoints?: string | undefined;
  keyEnv?: string | undefined;
  all?: boolean | undefined;
  verbose?: boolean | undefined;
  cwd?: string | undefined;
  prisma?: VerifyPrismaClient | undefined;
}

export interface CiStageResult {
  name: string;
  status: 'PASS' | 'FAIL' | 'ERROR' | 'SKIPPED';
  exitCode: 0 | 1 | 2;
  details: string;
}

export interface CiCommandOutcome {
  exitCode: 0 | 1 | 2;
  stages: CiStageResult[];
  summaryTable: string;
  warning?: string | undefined;
  scanOutput?: ScanOutput | undefined;
  verifyOutcome?: VerifyCommandOutcome | undefined;
  driftOutcome?: DriftCommandOutcome | undefined;
}

function pad(str: string, len: number): string {
  if (str.length >= len) {
    return str.slice(0, len);
  }
  return str + ' '.repeat(len - str.length);
}

export function formatSummaryTable(stages: CiStageResult[], exitCode: 0 | 1 | 2): string {
  const stageCol = 18;
  const statusCol = 12;
  const detailsCol = 58;

  const top = `┌${'─'.repeat(stageCol)}┬${'─'.repeat(statusCol)}┬${'─'.repeat(detailsCol)}┐`;
  const mid = `├${'─'.repeat(stageCol)}┼${'─'.repeat(statusCol)}┼${'─'.repeat(detailsCol)}┤`;
  const bot = `└${'─'.repeat(stageCol)}┴${'─'.repeat(statusCol)}┴${'─'.repeat(detailsCol)}┘`;

  const header = `│ ${pad('Stage', stageCol - 2)} │ ${pad('Status', statusCol - 2)} │ ${pad('Details', detailsCol - 2)} │`;

  const rows = stages.map((s) => {
    const details =
      s.details.length > detailsCol - 2
        ? s.details.slice(0, detailsCol - 5) + '...'
        : s.details;
    return `│ ${pad(s.name, stageCol - 2)} │ ${pad(s.status, statusCol - 2)} │ ${pad(details, detailsCol - 2)} │`;
  });

  const statusLabel = exitCode === 0 ? 'PASS' : exitCode === 1 ? 'FAIL' : 'ERROR';
  const resultLine = `Result: ${statusLabel} (exit code: ${String(exitCode)})`;

  return [
    'Trailguard CI Summary',
    top,
    header,
    mid,
    ...rows,
    bot,
    resultLine,
  ].join('\n');
}

export async function runCiCommand(opts: CiCommandOptions): Promise<CiCommandOutcome> {
  const cwd = opts.cwd ?? process.cwd();
  let configDir = cwd;
  if (opts.config) {
    const configPath = path.isAbsolute(opts.config) ? opts.config : path.resolve(cwd, opts.config);
    configDir = path.dirname(configPath);
  }
  loadDotenvIfPresent([configDir, cwd]);

  const skipDb = opts.noDb === true || opts.db === false;
  const stages: CiStageResult[] = [];
  let warning: string | undefined;

  if (skipDb) {
    warning = '⚠️  WARNING: --no-db specified. Skipping database verification and drift detection.';
  }

  // ── Stage 1: Static Scan ───────────────────────────────────────────────────
  let scanOutput: ScanOutput | undefined;
  const failOn = opts.failOn ?? 'high';

  try {
    scanOutput = await scan({
      config: opts.config,
      src: opts.src,
      format: opts.format,
      out: opts.out,
      failOn,
      baseline: opts.baseline,
      updateBaseline: opts.updateBaseline,
      verbose: opts.verbose,
    });

    if (scanOutput.exitCode === 0) {
      const count = scanOutput.findings.length;
      const details =
        count === 0
          ? `0 findings (threshold: ${failOn})`
          : `${String(count)} finding(s) (below ${failOn} threshold)`;
      stages.push({
        name: 'Static Scan',
        status: 'PASS',
        exitCode: 0,
        details,
      });
    } else {
      const unsuppressed = scanOutput.findings.filter((f) => !f.suppressed);
      stages.push({
        name: 'Static Scan',
        status: 'FAIL',
        exitCode: 1,
        details: `${String(unsuppressed.length)} unsuppressed finding(s) exceeded threshold (${failOn})`,
      });
    }
  } catch (err) {
    stages.push({
      name: 'Static Scan',
      status: 'ERROR',
      exitCode: 2,
      details: err instanceof Error ? err.message : String(err),
    });
  }

  // ── Shared DB connection for Stage 2 & Stage 3 ─────────────────────────────
  let sharedPrisma = opts.prisma;
  let shouldDisconnectPrisma = false;
  if (!skipDb && !sharedPrisma) {
    try {
      sharedPrisma = await resolvePrismaClient(cwd);
      shouldDisconnectPrisma = true;
    } catch {
      // If resolving fails here, let stage 2 / stage 3 report the error
    }
  }

  let verifyOutcome: VerifyCommandOutcome | undefined;
  let driftOutcome: DriftCommandOutcome | undefined;

  try {
    // ── Stage 2: Audit Verify ──────────────────────────────────────────────────
    if (skipDb) {
      stages.push({
        name: 'Audit Verify',
        status: 'SKIPPED',
        exitCode: 0,
        details: 'Skipped (--no-db)',
      });
    } else {
      try {
        verifyOutcome = await runVerifyCommand({
          config: opts.config,
          checkpoints: opts.checkpoints,
          keyEnv: opts.keyEnv,
          all: opts.all,
          cwd,
          prisma: sharedPrisma,
        });

        const status =
          verifyOutcome.exitCode === 0
            ? 'PASS'
            : verifyOutcome.exitCode === 1
              ? 'FAIL'
              : 'ERROR';

        stages.push({
          name: 'Audit Verify',
          status,
          exitCode: verifyOutcome.exitCode,
          details: verifyOutcome.message,
        });
      } catch (err) {
        stages.push({
          name: 'Audit Verify',
          status: 'ERROR',
          exitCode: 2,
          details: err instanceof Error ? err.message : String(err),
        });
      }
    }

    // ── Stage 3: Drift Check ───────────────────────────────────────────────────
    if (skipDb) {
      stages.push({
        name: 'Drift Check',
        status: 'SKIPPED',
        exitCode: 0,
        details: 'Skipped (--no-db)',
      });
    } else {
      try {
        driftOutcome = await runDriftCommand({
          config: opts.config,
          baseline: opts.baseline,
          failOn: opts.failOn,
          cwd,
          prisma: sharedPrisma as unknown as DriftPrismaClient | undefined,
        });

        const status =
          driftOutcome.exitCode === 0
            ? 'PASS'
            : driftOutcome.exitCode === 1
              ? 'FAIL'
              : 'ERROR';

        let details: string;
        if (driftOutcome.result) {
          const count = driftOutcome.result.findings.filter((f) => !f.suppressed).length;
          if (count === 0) {
            details = '0 drift findings';
          } else if (driftOutcome.exitCode === 0) {
            details = `${String(count)} drift finding(s) (below ${failOn} threshold)`;
          } else {
            details = `${String(count)} unsuppressed drift finding(s) exceeded threshold (${failOn})`;
          }
        } else {
          details = driftOutcome.message.split('\n')[0] ?? driftOutcome.message;
        }

        stages.push({
          name: 'Drift Check',
          status,
          exitCode: driftOutcome.exitCode,
          details,
        });
      } catch (err) {
        stages.push({
          name: 'Drift Check',
          status: 'ERROR',
          exitCode: 2,
          details: err instanceof Error ? err.message : String(err),
        });
      }
    }
  } finally {
    if (
      shouldDisconnectPrisma &&
      sharedPrisma &&
      typeof (sharedPrisma as { $disconnect?: () => Promise<void> }).$disconnect === 'function'
    ) {
      try {
        await (sharedPrisma as { $disconnect?: () => Promise<void> }).$disconnect?.();
      } catch {
        // ignore disconnect errors
      }
    }
  }

  // ── Overall Result ─────────────────────────────────────────────────────────
  const subCodes = stages.map((s) => s.exitCode);
  const maxCode = Math.max(0, ...subCodes);
  const exitCode = (maxCode > 2 ? 2 : maxCode) as 0 | 1 | 2;

  const summaryTable = formatSummaryTable(stages, exitCode);

  return {
    exitCode,
    stages,
    summaryTable,
    warning,
    scanOutput,
    verifyOutcome,
    driftOutcome,
  };
}
