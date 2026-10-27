/**
 * Core implementation of `trailguard drift` CLI command.
 *
 * Compares static RBAC access matrix derived from Express routes against
 * actual AuditLog behavior observed in MySQL.
 *
 * @see context.md §8, tasks.md T4.5, T5.3
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { loadConfig } from '../config/load.js';
import type { Config } from '../config/schema.js';
import type { Risk } from '../core/types.js';
import { createProject } from '../scan/project.js';
import { composeMounts } from '../scan/mounts.js';
import { loadPrismaSchema, parsePrismaSchema } from '../scan/prisma-schema.js';
import { buildRouteNodes, loadBaseline } from '../scan/findings.js';
import { deriveMatrix } from '../scan/matrix.js';
import {
  detectDrift,
  formatDriftReport,
  type DriftOptions,
  type DriftPrismaClient,
  type DriftResult,
} from '../scan/drift.js';
import { resolvePrismaClient } from './prisma-client.js';

import { loadDotenvIfPresent } from './env.js';

export interface DriftCommandOptions {
  config?: string | undefined;
  since?: string | undefined;
  failOn?: Risk | 'none' | undefined;
  baseline?: string | undefined;
  cwd?: string | undefined;
  prisma?: DriftPrismaClient | undefined;
}

export interface DriftCommandOutcome {
  exitCode: 0 | 1 | 2;
  message: string;
  result?: DriftResult | undefined;
}

export async function runDriftCommand(
  opts: DriftCommandOptions,
): Promise<DriftCommandOutcome> {
  const cwd = opts.cwd ?? process.cwd();

  // 1. Resolve configuration
  let config: Config;
  let configDir = cwd;
  try {
    if (opts.config) {
      const configPath = path.isAbsolute(opts.config)
        ? opts.config
        : path.resolve(cwd, opts.config);
      configDir = path.dirname(configPath);
      config = await loadConfig(configPath);
    } else {
      config = await loadConfig();
    }
  } catch (err) {
    return {
      exitCode: 2,
      message: `Error loading config file: ${(err as Error).message}`,
    };
  }

  loadDotenvIfPresent([configDir, cwd]);

  // 2. Resolve Prisma Client
  let prisma: DriftPrismaClient;
  let shouldDisconnect = false;
  if (opts.prisma) {
    prisma = opts.prisma;
  } else {
    try {
      prisma = (await resolvePrismaClient(cwd)) as unknown as DriftPrismaClient;
      shouldDisconnect = true;
    } catch (err) {
      return {
        exitCode: 2,
        message: `Database connection error: ${(err as Error).message}`,
      };
    }
  }

  // 3. Derive static access matrix
  let matrix: DriftOptions['matrix'];
  try {
    const project = createProject(config);
    const { routes: composed } = composeMounts(project);
    const schemaPath = path.isAbsolute(config.prismaSchema)
      ? config.prismaSchema
      : path.resolve(configDir, config.prismaSchema);
    const schema = fs.existsSync(schemaPath)
      ? loadPrismaSchema(schemaPath)
      : parsePrismaSchema('');
    const routeNodes = buildRouteNodes(composed, config, schema);
    matrix = deriveMatrix(routeNodes, config.audit.models);
  } catch (err) {
    if (shouldDisconnect && typeof (prisma as { $disconnect?: () => Promise<void> }).$disconnect === 'function') {
      try {
        await (prisma as { $disconnect?: () => Promise<void> }).$disconnect?.();
      } catch {
        // ignore
      }
    }
    return {
      exitCode: 2,
      message: `Error analyzing route structure: ${(err as Error).message}`,
    };
  }

  // 4. Resolve baseline if specified
  const baselinePath = opts.baseline ?? config.baseline;
  let baseline: ReturnType<typeof loadBaseline> = null;
  if (baselinePath) {
    try {
      const resolvedBaselinePath = path.isAbsolute(baselinePath)
        ? baselinePath
        : path.resolve(cwd, baselinePath);
      baseline = loadBaseline(resolvedBaselinePath);
    } catch (err) {
      if (shouldDisconnect && typeof (prisma as { $disconnect?: () => Promise<void> }).$disconnect === 'function') {
        try {
          await (prisma as { $disconnect?: () => Promise<void> }).$disconnect?.();
        } catch {
          // ignore
        }
      }
      return {
        exitCode: 2,
        message: `Error loading baseline file: ${(err as Error).message}`,
      };
    }
  }

  // 5. Run drift detection
  try {
    const result = await detectDrift({
      prisma,
      config,
      matrix,
      since: opts.since,
      baseline: baseline ?? undefined,
      failOn: opts.failOn ?? 'high',
    });

    const message = formatDriftReport(result);

    return {
      exitCode: result.exitCode,
      message,
      result,
    };
  } catch (err) {
    return {
      exitCode: 2,
      message: `Drift detection error: ${(err as Error).message}`,
    };
  } finally {
    if (shouldDisconnect && typeof (prisma as { $disconnect?: () => Promise<void> }).$disconnect === 'function') {
      try {
        await (prisma as { $disconnect?: () => Promise<void> }).$disconnect?.();
      } catch {
        // ignore disconnect error
      }
    }
  }
}
