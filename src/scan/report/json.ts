/**
 * JSON report generator for static analysis scan results.
 *
 * Validates against ScanResult schema and generates deterministic,
 * stable-ordered JSON.
 *
 * @see context.md §6.12
 */

import { z } from 'zod';
import type { ScanResult } from '../../core/types.js';

const HttpMethodSchema = z.enum([
  'GET',
  'POST',
  'PUT',
  'PATCH',
  'DELETE',
  'HEAD',
  'OPTIONS',
  'ALL',
]);

const ConfidenceSchema = z.enum(['high', 'medium', 'low']);
const RiskSchema = z.enum(['high', 'medium', 'low']);
const ActionSchema = z.enum(['create', 'read', 'update', 'delete']);

const MiddlewareClassSchema = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('auth') }),
  z.object({ kind: z.literal('role'), value: z.string() }),
  z.object({ kind: z.literal('ownership') }),
  z.object({ kind: z.literal('neutral') }),
  z.object({ kind: z.literal('unknown') }),
]);

const MiddlewareRefSchema = z.object({
  text: z.string(),
  name: z.string(),
  args: z.array(z.string()),
  class: MiddlewareClassSchema,
  file: z.string(),
  line: z.number(),
});

const RouteNodeSchema = z.object({
  method: HttpMethodSchema,
  path: z.string(),
  rawPath: z.string(),
  confidence: ConfidenceSchema,
  chain: z.array(MiddlewareRefSchema),
  handler: z
    .object({
      name: z.string(),
      file: z.string().optional(),
      line: z.number().optional(),
      resolved: z.boolean(),
    })
    .optional(),
  file: z.string(),
  line: z.number(),
  resource: z
    .object({
      model: z.string().nullable(),
      source: z.enum(['config', 'heuristic']),
    })
    .optional(),
  ownership: z.enum(['probable', 'none', 'unknown']),
});

const FindingSchema = z.object({
  ruleId: z.string(),
  risk: RiskSchema,
  confidence: ConfidenceSchema,
  message: z.string(),
  file: z.string(),
  line: z.number(),
  route: z
    .object({
      method: z.string(),
      path: z.string(),
      handler: z.string().optional(),
    })
    .optional(),
  resource: z
    .object({
      model: z.string().nullable(),
      source: z.enum(['config', 'heuristic']),
    })
    .optional(),
  fingerprint: z.string(),
  suppressed: z.boolean().optional(),
});

const MatrixCellSchema = z.object({
  resource: z.string(),
  action: ActionSchema,
  anonymous: z.boolean(),
  anyAuthenticated: z.boolean(),
  roles: z.array(z.string()),
  own: z.boolean(),
  uncertain: z.boolean(),
});

export const ScanResultSchema = z.object({
  version: z.string(),
  routes: z.array(RouteNodeSchema),
  findings: z.array(FindingSchema),
  matrix: z.array(MatrixCellSchema),
  models: z.array(z.string()),
  stats: z.object({
    routes: z.number(),
    protectedRoutes: z.number(),
    unprotectedRoutes: z.number(),
    byRisk: z.object({
      high: z.number(),
      medium: z.number(),
      low: z.number(),
    }),
    suppressed: z.number(),
  }),
});

/**
 * Validate that an object strictly adheres to the ScanResult schema.
 */
export function validateScanResult(data: unknown): ScanResult {
  return ScanResultSchema.parse(data) as unknown as ScanResult;
}

/**
 * Format a ScanResult into stable, pretty-printed JSON with trailing newline.
 */
export function formatJsonReport(scanResult: ScanResult): string {
  // Validate against schema first
  validateScanResult(scanResult);

  // Construct with explicit key order
  const orderedResult: ScanResult = {
    version: scanResult.version,
    routes: scanResult.routes,
    findings: scanResult.findings,
    matrix: scanResult.matrix,
    models: scanResult.models,
    stats: scanResult.stats,
  };

  return `${JSON.stringify(orderedResult, null, 2)}\n`;
}

/**
 * Parse and validate a JSON report string into a ScanResult object.
 */
export function parseJsonReport(jsonString: string): ScanResult {
  const parsed = JSON.parse(jsonString) as unknown;
  return validateScanResult(parsed);
}
