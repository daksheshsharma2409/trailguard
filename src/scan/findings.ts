/**
 * Findings model, stable fingerprint generation, and rule context.
 *
 * Fingerprints are stable hashes over ruleId, method, and composed path (or file/model/op),
 * intentionally omitting line numbers so they survive unrelated source edits.
 *
 * @see context.md §6.10, §6.11
 */

import { sha256Hex } from '../core/crypto.js';
import type { Finding, Risk, RouteNode } from '../core/types.js';
import type { Config } from '../config/schema.js';
import type { PrismaSchemaResult } from './prisma-schema.js';
import type { ComposedRoute } from './mounts.js';
import { normalizePath } from './mounts.js';
import { classifyMiddleware } from './classify.js';
import { mapResource } from './resources.js';
import { checkOwnershipHeuristic } from './ownership.js';

export interface RuleContext {
  routes: RouteNode[];
  config: Config;
  prismaSchema: PrismaSchemaResult;
}

export interface Rule {
  id: string;
  title: string;
  defaultRisk: Risk;
  run(ctx: RuleContext): Finding[];
}

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
    };
  });
}
