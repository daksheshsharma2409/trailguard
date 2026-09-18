/**
 * Core implementation of `trailguard verify` CLI command.
 *
 * Resolves configuration, HMAC key from environment, checkpoints file,
 * and user's Prisma client, then runs the audit verification algorithm.
 *
 * @see context.md §4.4, §4.5, §7.9, tasks.md T5.1
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { loadConfig } from '../config/load.js';
import type { Config } from '../config/schema.js';
import type { Checkpoint, VerifyResult } from '../core/types.js';
import { verifyAuditChain, type VerifyPrismaClient } from '../runtime/verify.js';
import { resolvePrismaClient } from './prisma-client.js';

export interface VerifyCommandOptions {
  config?: string | undefined;
  checkpoints?: string | undefined;
  keyEnv?: string | undefined;
  all?: boolean | undefined;
  cwd?: string | undefined;
  prisma?: VerifyPrismaClient | undefined;
}

export interface VerifyCommandOutcome {
  exitCode: 0 | 1 | 2;
  message: string;
  result?: VerifyResult | undefined;
}

export function loadCheckpointsFile(filePath: string): Checkpoint[] {
  if (!fs.existsSync(filePath)) {
    throw new Error(`Checkpoints file not found: ${filePath}`);
  }
  const content = fs.readFileSync(filePath, 'utf-8');
  const lines = content.split('\n').map((l) => l.trim()).filter((l) => l.length > 0);
  const checkpoints: Checkpoint[] = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!line) continue;
    try {
      const parsed = JSON.parse(line) as Checkpoint;
      checkpoints.push(parsed);
    } catch (err) {
      throw new Error(`Invalid JSON in checkpoints file at line ${String(i + 1)}: ${(err as Error).message}`);
    }
  }
  return checkpoints;
}

export async function runVerifyCommand(
  opts: VerifyCommandOptions,
): Promise<VerifyCommandOutcome> {
  const cwd = opts.cwd ?? process.cwd();

  // 1. Resolve configuration if provided or found
  let config: Config | undefined;
  if (opts.config) {
    try {
      config = await loadConfig(path.isAbsolute(opts.config) ? opts.config : path.resolve(cwd, opts.config));
    } catch (err) {
      return {
        exitCode: 2,
        message: `Error loading config file: ${(err as Error).message}`,
      };
    }
  } else {
    try {
      config = await loadConfig();
    } catch {
      // Config is optional for verify; continue with defaults if not found
    }
  }

  // 2. Resolve HMAC key from environment variable
  const keyEnv = opts.keyEnv ?? config?.keyEnv ?? 'TRAILGUARD_KEY';
  const key = process.env[keyEnv];
  if (!key || key.trim() === '') {
    return {
      exitCode: 2,
      message: `Error: Environment variable '${keyEnv}' is not set or empty.`,
    };
  }

  // 3. Resolve checkpoints if specified
  const checkpointsPath = opts.checkpoints ?? config?.checkpoints.file;
  let checkpoints: Checkpoint[] | undefined;
  if (checkpointsPath) {
    const resolvedPath = path.isAbsolute(checkpointsPath)
      ? checkpointsPath
      : path.resolve(cwd, checkpointsPath);
    try {
      checkpoints = loadCheckpointsFile(resolvedPath);
    } catch (err) {
      return {
        exitCode: 2,
        message: `Error reading checkpoints: ${(err as Error).message}`,
      };
    }
  }

  // 4. Resolve Prisma client
  let prisma: VerifyPrismaClient;
  let shouldDisconnect = false;
  if (opts.prisma) {
    prisma = opts.prisma;
  } else {
    try {
      prisma = await resolvePrismaClient(cwd);
      shouldDisconnect = true;
    } catch (err) {
      return {
        exitCode: 2,
        message: `Error: ${(err as Error).message}`,
      };
    }
  }

  // 5. Run verification
  try {
    const result = await verifyAuditChain({
      prisma,
      keys: { secret: key },
      all: opts.all ?? false,
      checkpoints,
    });

    if (result.valid) {
      return {
        exitCode: 0,
        message: `✔ valid (${String(result.checkedRecords)} records)`,
        result,
      };
    }

    const brokenSeq = result.brokenAt ?? result.problems[0]?.seq ?? 'unknown';
    const code = result.problems[0]?.code;
    const reason = result.reason ?? result.problems[0]?.message ?? code ?? 'unknown';
    const formattedReason = code && !reason.includes(code) ? `[${code}] ${reason}` : reason;
    let message = `✖ broken at seq ${brokenSeq}: ${formattedReason}`;

    if (opts.all && result.problems.length > 1) {
      for (const p of result.problems.slice(1)) {
        message += `\n  - seq ${p.seq ?? '?'}: [${p.code}] ${p.message}`;
      }
    }

    return {
      exitCode: 1,
      message,
      result,
    };
  } catch (err) {
    return {
      exitCode: 2,
      message: `Verification failed unexpectedly: ${(err as Error).message}`,
    };
  } finally {
    if (shouldDisconnect && typeof (prisma as { $disconnect?: () => Promise<void> }).$disconnect === 'function') {
      try {
        await (prisma as { $disconnect?: () => Promise<void> }).$disconnect?.();
      } catch {
        // ignore disconnect errors
      }
    }
  }
}
