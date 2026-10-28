/**
 * trailguard/scan main orchestrator.
 *
 * Runs the complete static analysis pipeline:
 * loadConfig → createProject → composeMounts → loadPrismaSchema → buildRouteNodes
 * → runRules → applyBaseline/updateBaseline → deriveMatrix → calculateScanStats
 * → format report → return ScanOutput with exitCode.
 *
 * @see context.md §6.1, §4.3
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { loadConfig } from '../config/load.js';
import { ConfigSchema, type Config, type UserConfig } from '../config/schema.js';
import { createProject } from './project.js';
import { composeMounts } from './mounts.js';
import { loadPrismaSchema, parsePrismaSchema } from './prisma-schema.js';
import {
  buildRouteNodes,
  calculateScanStats,
  loadBaseline,
  applyBaseline,
  writeBaseline,
  isThresholdExceeded,
} from './findings.js';
import { runRules } from './rules/index.js';
import { findPrismaWrites } from './prisma-writes.js';
import { deriveMatrix } from './matrix.js';
import { formatMarkdownReport } from './report/markdown.js';
import { formatJsonReport } from './report/json.js';
import { formatSarifReport } from './report/sarif.js';
import { getPackageVersion } from '../core/version.js';
import type { Risk, ScanResult } from '../core/types.js';

export interface ScanOptions {
  /** Path to config file, or an already loaded Config/UserConfig object. */
  config?: string | Config | UserConfig | undefined;
  /** Entry path override (e.g. from CLI positional arg). */
  src?: string | undefined;
  /** Output report format (default: 'md'). */
  format?: 'md' | 'json' | 'sarif' | undefined;
  /** File path to write report to (in addition to returning it). */
  out?: string | undefined;
  /** Risk threshold to trigger failure exit code 1 (default: 'high'). */
  failOn?: Risk | 'none' | undefined;
  /** Baseline file path override. */
  baseline?: string | undefined;
  /** Rewrite the baseline file with current findings. */
  updateBaseline?: boolean | undefined;
  /** Verbose output logging. */
  verbose?: boolean | undefined;
}

export interface ScanOutput extends ScanResult {
  report: string;
  exitCode: 0 | 1;
  thresholdExceeded: boolean;
}

/**
 * Execute a trailguard static analysis scan.
 *
 * @param options - Configuration path or overrides.
 */
export async function scan(options: ScanOptions = {}): Promise<ScanOutput> {
  // 1. Resolve configuration
  let config: Config;
  let configFilePath: string | undefined;

  if (typeof options.config === 'object') {
    config = ConfigSchema.parse(options.config);
  } else if (typeof options.config === 'string') {
    configFilePath = options.config;
    config = await loadConfig(configFilePath);
  } else {
    config = await loadConfig();
  }

  // CLI overrides
  if (options.src !== undefined && options.src !== '') {
    config = { ...config, entry: [options.src] };
  }
  if (options.baseline !== undefined && options.baseline !== '') {
    config = { ...config, baseline: options.baseline };
  }

  const baseDir = configFilePath ? path.dirname(path.resolve(configFilePath)) : process.cwd();

  // 2. Create ts-morph project and parse entry files
  const project = createProject(config);

  // 3. Mount composition and route extraction
  const { routes: composedRoutes } = composeMounts(project);

  // 4. Parse Prisma schema if available
  const schemaPath = path.isAbsolute(config.prismaSchema)
    ? config.prismaSchema
    : path.resolve(baseDir, config.prismaSchema);

  let prismaSchema;
  if (fs.existsSync(schemaPath)) {
    prismaSchema = loadPrismaSchema(schemaPath, config.ownership.ownerFields);
  } else {
    // If schema file does not exist, proceed with empty schema per spec §6.5
    prismaSchema = parsePrismaSchema('');
  }

  // 5. Build enriched route nodes
  const routeNodes = buildRouteNodes(composedRoutes, config, prismaSchema);

  // 6. Prisma write discovery
  const prismaWrites = findPrismaWrites(project, config, routeNodes);

  // 7. Run static rules
  let findings = runRules({
    routes: routeNodes,
    config,
    prismaSchema,
    prismaWrites,
    project,
  });

  // 7. Handle baseline
  const baselineRawPath = options.baseline ?? config.baseline;
  if (options.updateBaseline && baselineRawPath) {
    const baselinePath = path.isAbsolute(baselineRawPath)
      ? baselineRawPath
      : path.resolve(baseDir, baselineRawPath);
    writeBaseline(baselinePath, findings);
    const reloaded = loadBaseline(baselinePath);
    if (reloaded) {
      findings = applyBaseline(findings, reloaded);
    }
  } else if (baselineRawPath) {
    const baselinePath = path.isAbsolute(baselineRawPath)
      ? baselineRawPath
      : path.resolve(baseDir, baselineRawPath);
    const baseline = loadBaseline(baselinePath);
    if (baseline) {
      findings = applyBaseline(findings, baseline);
    }
  }

  // 8. Derive access matrix
  const models = Array.from(prismaSchema.keys());
  const matrix = deriveMatrix(routeNodes, models);

  // 9. Calculate stats
  const stats = calculateScanStats(routeNodes, findings);

  // 10. Assemble ScanResult
  const scanResult: ScanResult = {
    version: getPackageVersion(),
    routes: routeNodes,
    findings,
    matrix,
    models,
    stats,
  };

  // 11. Format output report
  const fmt = options.format ?? 'md';
  let report: string;
  if (fmt === 'json') {
    report = formatJsonReport(scanResult);
  } else if (fmt === 'sarif') {
    report = formatSarifReport(scanResult);
  } else {
    report = formatMarkdownReport(scanResult, {
      version: scanResult.version,
      configPath: configFilePath,
    });
  }

  // Write report to file if --out was specified
  if (options.out) {
    const outPath = path.isAbsolute(options.out) ? options.out : path.resolve(process.cwd(), options.out);
    fs.writeFileSync(outPath, report, 'utf-8');
  }

  // 12. Evaluate exit threshold
  const failOn = options.failOn ?? 'high';
  const thresholdExceeded = isThresholdExceeded(findings, failOn);
  const exitCode = thresholdExceeded ? 1 : 0;

  return {
    ...scanResult,
    report,
    exitCode,
    thresholdExceeded,
  };
}
