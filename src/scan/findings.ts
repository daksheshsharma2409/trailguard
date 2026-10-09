/**
 * Findings model, stable fingerprint generation, baseline suppression, and rule context.
 *
 * Fingerprints are stable hashes over ruleId, method, and composed path (or file/model/op),
 * intentionally omitting line numbers so they survive unrelated source edits.
 *
 * Baseline files (`.trailguard-baseline.json`) suppress matching findings and exclude them
 * from the exit threshold.
 *
 * @see context.md §6.10, §6.11
 */

import * as fs from 'node:fs';
import { z } from 'zod';
import { sha256Hex } from '../core/crypto.js';
import { ScanConfigError } from '../core/errors.js';
import type { Finding, Risk, RouteNode } from '../core/types.js';
import type { Config } from '../config/schema.js';
import type { PrismaSchemaResult } from './prisma-schema.js';
import type { ComposedRoute } from './mounts.js';
import { normalizePath } from './mounts.js';
import { classifyMiddleware } from './classify.js';
import { mapResource } from './resources.js';
import { checkOwnershipHeuristic } from './ownership.js';

import type { Project } from 'ts-morph';
import type { PrismaWriteDiscoveryResult } from './prisma-writes.js';

export interface RuleContext {
  routes: RouteNode[];
  config: Config;
  prismaSchema: PrismaSchemaResult;
  prismaWrites?: PrismaWriteDiscoveryResult | undefined;
  project?: Project | undefined;
}

export interface Rule {
  id: string;
  title: string;
  defaultRisk: Risk;
  run(ctx: RuleContext): Finding[];
}

/**
 * Numeric levels for evaluating --fail-on thresholds.
 */
export const RISK_LEVELS: Record<Risk, number> = {
  low: 1,
  medium: 2,
  high: 3,
};

// ── Baseline Schema & Types ──────────────────────────────────────────────────

export const BaselineEntrySchema = z
  .object({
    fingerprint: z.string().min(1, 'Baseline entry must have a fingerprint'),
    ruleId: z.string().min(1, 'Baseline entry must have a ruleId'),
    note: z.string().optional(),
  })
  .passthrough();

export interface BaselineEntry {
  fingerprint: string;
  ruleId: string;
  note?: string | undefined;
}

export const BaselineFileSchema = z
  .object({
    version: z.literal(1),
    entries: z.array(BaselineEntrySchema),
  })
  .strict();

export interface BaselineFile {
  version: 1;
  entries: BaselineEntry[];
}

/**
 * Parse and validate baseline file JSON content.
 * Throws ScanConfigError on syntax or schema errors.
 */
export function parseBaseline(content: string, filePath = '<string>'): BaselineFile {
  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch (err) {
    throw new ScanConfigError(`Failed to parse baseline file ${filePath}: invalid JSON`, {
      filePath,
      cause: err,
    });
  }

  const result = BaselineFileSchema.safeParse(parsed);
  if (!result.success) {
    const msg = result.error.errors.map((e) => `${e.path.join('.')}: ${e.message}`).join(', ');
    throw new ScanConfigError(`Invalid baseline file ${filePath}: ${msg}`, { filePath });
  }

  return {
    version: 1,
    entries: result.data.entries.map((e) => ({
      fingerprint: e.fingerprint,
      ruleId: e.ruleId,
      note: e.note,
    })),
  };
}

/**
 * Load baseline file from disk if it exists. Returns null if file does not exist.
 * Throws ScanConfigError if file exists but contains invalid data.
 */
export function loadBaseline(filePath: string): BaselineFile | null {
  if (!fs.existsSync(filePath)) {
    return null;
  }
  const content = fs.readFileSync(filePath, 'utf-8');
  return parseBaseline(content, filePath);
}

/**
 * Apply baseline to a list of findings, marking matching findings as `suppressed: true`.
 * Pure function returning new finding objects.
 */
export function applyBaseline(
  findings: Finding[],
  baseline?: BaselineFile | BaselineEntry[] | Set<string> | null,
): Finding[] {
  if (!baseline) {
    return findings;
  }

  const suppressedSet = new Set<string>();
  if (baseline instanceof Set) {
    for (const fp of baseline) {
      suppressedSet.add(fp);
    }
  } else if (Array.isArray(baseline)) {
    for (const entry of baseline) {
      suppressedSet.add(entry.fingerprint);
    }
  } else if ('entries' in baseline && Array.isArray(baseline.entries)) {
    for (const entry of baseline.entries) {
      suppressedSet.add(entry.fingerprint);
    }
  }

  return findings.map((f) => {
    if (suppressedSet.has(f.fingerprint)) {
      return {
        ...f,
        suppressed: true,
      };
    }
    return f;
  });
}

/**
 * Generate a sorted BaselineFile object from current findings.
 * Deduplicates by fingerprint, and sorts entries by ruleId ascending, then fingerprint ascending.
 */
export function generateBaseline(findings: Finding[]): BaselineFile {
  const entryMap = new Map<string, BaselineEntry>();

  for (const f of findings) {
    if (!entryMap.has(f.fingerprint)) {
      entryMap.set(f.fingerprint, {
        fingerprint: f.fingerprint,
        ruleId: f.ruleId,
      });
    }
  }

  const sortedEntries = Array.from(entryMap.values()).sort((a, b) => {
    const cmp = a.ruleId.localeCompare(b.ruleId);
    if (cmp !== 0) return cmp;
    return a.fingerprint.localeCompare(b.fingerprint);
  });

  return {
    version: 1,
    entries: sortedEntries,
  };
}

/**
 * Format a baseline file (or list of findings) as deterministic, sorted JSON with trailing newline.
 */
export function formatBaseline(baselineOrFindings: BaselineFile | Finding[]): string {
  const baseline = Array.isArray(baselineOrFindings)
    ? generateBaseline(baselineOrFindings)
    : baselineOrFindings;

  const sortedEntries = [...baseline.entries].sort((a, b) => {
    const cmp = a.ruleId.localeCompare(b.ruleId);
    if (cmp !== 0) return cmp;
    return a.fingerprint.localeCompare(b.fingerprint);
  });

  const sortedBaseline: BaselineFile = {
    version: 1,
    entries: sortedEntries,
  };

  return `${JSON.stringify(sortedBaseline, null, 2)}\n`;
}

/**
 * Write a baseline file to disk with deterministic sorting.
 */
export function writeBaseline(
  filePath: string,
  baselineOrFindings: BaselineFile | Finding[],
): void {
  const content = formatBaseline(baselineOrFindings);
  fs.writeFileSync(filePath, content, 'utf-8');
}

/**
 * Check whether any unsuppressed findings meet or exceed the `--fail-on` threshold.
 */
export function isThresholdExceeded(
  findings: Finding[],
  failOn: Risk | 'none' = 'high',
): boolean {
  if (failOn === 'none') {
    return false;
  }
  const minRank = RISK_LEVELS[failOn];
  return findings.some((f) => !f.suppressed && RISK_LEVELS[f.risk] >= minRank);
}

/**
 * Calculate scan statistics for ScanResult.
 */
export function calculateScanStats(
  routes: RouteNode[],
  findings: Finding[],
): {
  routes: number;
  protectedRoutes: number;
  unprotectedRoutes: number;
  byRisk: Record<Risk, number>;
  suppressed: number;
} {
  let protectedRoutes = 0;
  let unprotectedRoutes = 0;

  for (const r of routes) {
    const hasAuthOrRole = r.chain.some(
      (m) => m.class.kind === 'auth' || m.class.kind === 'role',
    );
    if (hasAuthOrRole) {
      protectedRoutes++;
    } else {
      unprotectedRoutes++;
    }
  }

  const byRisk: Record<Risk, number> = {
    high: 0,
    medium: 0,
    low: 0,
  };

  let suppressed = 0;
  for (const f of findings) {
    if (f.suppressed) {
      suppressed++;
    } else {
      byRisk[f.risk]++;
    }
  }

  return {
    routes: routes.length,
    protectedRoutes,
    unprotectedRoutes,
    byRisk,
    suppressed,
  };
}

// ── Fingerprints ─────────────────────────────────────────────────────────────

/**
 * Compute a stable fingerprint for a route-based finding.
 *
 * sha256(ruleId | method | composedPath) — strictly no line numbers.
 */
export function computeRouteFingerprint(
  ruleId: string,
  method: string,
  composedPath: string,
): string {
  const normPath = normalizePath(composedPath);
  const raw = `${ruleId}|${method.toUpperCase()}|${normPath}`;
  return sha256Hex(raw);
}

/**
 * Compute a stable fingerprint for a code/write-based finding.
 *
 * sha256(ruleId | relativeFile | model.op | enclosingFn) — strictly no line numbers.
 */
export function computeWriteFingerprint(
  ruleId: string,
  relativeFile: string,
  modelOp: string,
  enclosingFn?: string,
): string {
  const raw = `${ruleId}|${relativeFile}|${modelOp}|${enclosingFn ?? ''}`;
  return sha256Hex(raw);
}

/**
 * Resolve effective risk for a rule considering user configuration overrides.
 * Returns 'off' if rule is disabled.
 */
export function resolveEffectiveRisk(
  ruleId: string,
  defaultRisk: Risk,
  configRules: Record<string, Risk | 'off'> = {},
): Risk | 'off' {
  const override = configRules[ruleId];
  if (override !== undefined) {
    return override;
  }
  return defaultRisk;
}

/**
 * Construct enriched RouteNode objects from composed routes, schema, and config.
 */
export function buildRouteNodes(
  composedRoutes: ComposedRoute[],
  config: Config,
  prismaSchema: PrismaSchemaResult,
): RouteNode[] {
  return composedRoutes.map((cr) => {
    // 1. Classify middleware chain
    const chain = cr.middlewareArgs.flatMap((mw) => classifyMiddleware(mw, config));

    // 2. Resource mapping
    const resMap = mapResource(cr.path, config.resources, prismaSchema);

    // 3. Ownership detection
    const model = resMap.model ? prismaSchema.get(resMap.model) : undefined;
    const ownerFields = model?.ownerFields ?? config.ownership.ownerFields;
    const ownership = checkOwnershipHeuristic(cr.resolvedHandler, {
      signals: config.ownership.signals,
      ownerFields,
    });

    return {
      method: cr.method,
      path: cr.path,
      rawPath: cr.rawPath,
      confidence: cr.confidence,
      chain,
      handler: cr.resolvedHandler
        ? {
            name: cr.resolvedHandler.name,
            file: cr.resolvedHandler.file,
            line: cr.resolvedHandler.line,
            resolved: cr.resolvedHandler.resolved,
          }
        : undefined,
      file: cr.file,
      line: cr.line,
      resource: resMap.model
        ? {
            model: resMap.model,
            source: resMap.source,
          }
        : undefined,
      ownership,
      orphan: cr.orphan ? true : undefined,
    };
  });
}
