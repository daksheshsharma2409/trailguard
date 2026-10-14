/**
 * Core implementation of `trailguard checkpoint` CLI command.
 *
 * Emits an on-demand signed Checkpoint for the current audit head.
 * Sinks to configured checkpoints file, custom --out file, or stdout.
 *
 * @see context.md §4.4, §7.8, tasks.md T5.3
 */

import * as path from 'node:path';
import { loadConfig } from '../config/load.js';
import type { Config } from '../config/schema.js';
import { DEFAULT_KEY_ENV, DEFAULT_KEY_ID } from '../core/constants.js';
import type { Checkpoint } from '../core/types.js';
import { createCheckpoint, fileSink, stdoutSink } from '../runtime/checkpoint.js';
import type { VerifyPrismaClient } from '../runtime/verify.js';
import { resolvePrismaClient } from './prisma-client.js';

export interface CheckpointCommandOptions {
  config?: string | undefined;
  keyEnv?: string | undefined;
  out?: string | undefined;
  cwd?: string | undefined;
  prisma?: VerifyPrismaClient | undefined;
}

export interface CheckpointCommandOutcome {
  exitCode: 0 | 2;
  message: string;
  checkpoint?: Checkpoint | undefined;
}

export async function runCheckpointCommand(
  opts: CheckpointCommandOptions,
): Promise<CheckpointCommandOutcome> {
  const cwd = opts.cwd ?? process.cwd();

  // 1. Resolve configuration
  let config: Config | undefined;
  if (opts.config) {
    try {
      const configPath = path.isAbsolute(opts.config)
        ? opts.config
        : path.resolve(cwd, opts.config);
      config = await loadConfig(configPath);
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
      // Config is optional; defaults will apply
    }
  }

  // 2. Resolve HMAC key from environment variable
  const keyEnv = opts.keyEnv ?? config?.keyEnv ?? DEFAULT_KEY_ENV;
  const key = process.env[keyEnv];
  if (!key || key.trim() === '') {
    return {
      exitCode: 2,
      message: `Error: Environment variable '${keyEnv}' is not set or empty.`,
    };
  }

  // 3. Resolve Prisma Client
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
        message: `Database connection error: ${(err as Error).message}`,
      };
    }
  }

  try {
    // 4. Query current audit head
    const head = await prisma.auditHead.findUnique({ where: { id: 1 } });

    if (!head) {
      return {
        exitCode: 2,
        message: 'Cannot create checkpoint: audit head is not initialized or database has no audit entries',
      };
    }

    // 5. Create signed checkpoint
    const checkpoint = createCheckpoint(
      { seq: head.lastSeq, hash: head.lastHash },
      key,
      DEFAULT_KEY_ID,
    );

    // 6. Emit to sink
    const targetFile = opts.out ?? config?.checkpoints.file;
    if (targetFile) {
      const resolvedPath = path.isAbsolute(targetFile)
        ? targetFile
        : path.resolve(cwd, targetFile);
      const sink = fileSink(resolvedPath);
      await Promise.resolve(sink(checkpoint));
    } else {
      const sink = stdoutSink();
      await Promise.resolve(sink(checkpoint));
    }

    return {
      exitCode: 0,
      message: `✔ Checkpoint emitted for seq ${checkpoint.seq} (hash: ${checkpoint.hash.slice(0, 16)}...)`,
      checkpoint,
    };
  } catch (err) {
    return {
      exitCode: 2,
      message: `Checkpoint error: ${(err as Error).message}`,
    };
  } finally {
    const disconnectable = prisma as { $disconnect?: () => Promise<void> };
    if (shouldDisconnect && typeof disconnectable.$disconnect === 'function') {
      try {
        await disconnectable.$disconnect();
      } catch {
        // ignore disconnect errors
      }
    }
  }
}
