/**
 * Drift detection engine.
 *
 * Compares statically declared RBAC access matrix against runtime AuditLog behavior.
 * Detects:
 * - DRIFT001: Runtime action not allowed by static matrix (e.g. TEACHER deleting User when ADMIN-only).
 * - DRIFT002: Unknown / undeclared actor role or action on undeclared resource.
 *
 * @see context.md §8
 */

import { sha256Hex } from '../core/crypto.js';
import type { Finding, MatrixCell, Risk } from '../core/types.js';
import type { Config } from '../config/schema.js';
import { applyBaseline, loadBaseline, type BaselineFile, type BaselineEntry } from './findings.js';

export interface DriftPrismaClient {
  auditLog: {
    findMany: (args: Record<string, unknown>) => Promise<Array<Record<string, unknown>>>;
  };
}

export interface DriftOptions {
  prisma: DriftPrismaClient;
  config: Config;
  matrix: MatrixCell[];
  since?: string | Date | undefined;
  baseline?: string | BaselineFile | BaselineEntry[] | Set<string> | null | undefined;
  failOn?: Risk | 'none' | undefined;
}

export interface DriftResult {
  findings: Finding[];
  totalAuditedRows: number;
  distinctCombinations: number;
  exitCode: 0 | 1;
}

export function computeDriftFingerprint(
  ruleId: 'DRIFT001' | 'DRIFT002',
  role: string,
  model: string,
  action: string,
): string {
  const raw = `${ruleId}|${role}|${model}|${action}`;
  return sha256Hex(raw);
}

interface AuditRowSample {
  seq: bigint | number | string;
  actorId: string | null;
  actorRole: string | null;
  requestId: string | null;
}

interface DistinctGroup {
  actorRole: string | null;
  model: string;
  action: string;
  samples: AuditRowSample[];
}

/**
 * Detect runtime drift between the declared access matrix and actual audit logs.
 *
 * @param options - Drift options including prisma client, config, and access matrix.
 * @returns DriftResult with findings, summary counts, and exit code.
 */
export async function detectDrift(options: DriftOptions): Promise<DriftResult> {
  const { prisma, config, matrix, since, baseline, failOn = 'high' } = options;

  const where: Record<string, unknown> = {};
  if (since) {
    const sinceDate = typeof since === 'string' ? new Date(since) : since;
    where['createdAt'] = { gte: sinceDate };
  }

  const rows = await prisma.auditLog.findMany({
    where,
    orderBy: { seq: 'asc' },
  });

  const totalAuditedRows = rows.length;
  if (totalAuditedRows === 0) {
    return {
      findings: [],
      totalAuditedRows: 0,
      distinctCombinations: 0,
      exitCode: 0,
    };
  }

  // Group by (actorRole, model, action)
  const groups = new Map<string, DistinctGroup>();

  for (const row of rows) {
    const actorRole = (row['actorRole'] as string | null | undefined) ?? null;
    const model = (row['model'] as string | undefined) ?? '';
    const rawAction = (row['action'] as string | undefined) ?? '';
    const action = rawAction.toLowerCase();

    const key = `${actorRole ?? 'null'}|${model.toLowerCase()}|${action}`;
    let group = groups.get(key);
    if (!group) {
      group = {
        actorRole,
        model,
        action,
        samples: [],
      };
      groups.set(key, group);
    }

    if (group.samples.length < 3) {
      group.samples.push({
        seq: (row['seq'] as bigint | number | string | undefined) ?? '',
        actorId: (row['actorId'] as string | null | undefined) ?? null,
        actorRole,
        requestId: (row['requestId'] as string | null | undefined) ?? null,
      });
    }
  }

  const findings: Finding[] = [];
  const allowRoles = new Set(config.drift.allowRoles);
  const knownRoles = new Set(config.roles.known);

  for (const group of groups.values()) {
    const { actorRole, model, action, samples } = group;
    const sampleSeqs = samples.map((s) => s.seq.toString());
    const firstSeqNum = Number(samples[0]?.seq ?? 1);

    // 1. Check if role is unrecognized (DRIFT002)
    const roleName = actorRole ?? 'null';
    const isAllowedSpecialRole =
      allowRoles.has(actorRole ?? 'SYSTEM') || (actorRole !== null && allowRoles.has(actorRole));

    if (!isAllowedSpecialRole && (!actorRole || !knownRoles.has(actorRole))) {
      findings.push({
        ruleId: 'DRIFT002',
        risk: 'medium',
        confidence: 'high',
        message: `Observed action '${action}' on '${model}' by unrecognized role '${roleName}' (seqs: ${sampleSeqs.join(', ')}).`,
        file: 'audit',
        line: firstSeqNum,
        resource: {
          model,
          source: 'config',
        },
        fingerprint: computeDriftFingerprint('DRIFT002', roleName, model, action),
      });
    }

    // 2. Look up matching cell in static access matrix
    const cell = matrix.find(
      (c) =>
        c.resource.toLowerCase() === model.toLowerCase() &&
        c.action.toLowerCase() === action.toLowerCase(),
    );

    if (!cell) {
      // Cell missing in matrix
      if (config.drift.strict) {
        findings.push({
          ruleId: 'DRIFT002',
          risk: 'medium',
          confidence: 'high',
          message: `Observed action '${action}' on '${model}' has no static route declaration in matrix.`,
          file: 'audit',
          line: firstSeqNum,
          resource: {
            model,
            source: 'config',
          },
          fingerprint: computeDriftFingerprint('DRIFT002', 'undeclared', model, action),
        });
      } else {
        // Spec: "Cell missing → DRIFT002-style 'undeclared' (LOW info) unless config drift.strict."
        findings.push({
          ruleId: 'DRIFT002',
          risk: 'low',
          confidence: 'medium',
          message: `Observed action '${action}' on '${model}' has no static route declaration in matrix.`,
          file: 'audit',
          line: firstSeqNum,
          resource: {
            model,
            source: 'config',
          },
          fingerprint: computeDriftFingerprint('DRIFT002', 'undeclared', model, action),
        });
      }
      continue;
    }

    // Cell exists. Check permissions.
    // If role is SYSTEM or in allowRoles, it's allowed by drift config
    if (isAllowedSpecialRole) {
      continue;
    }

    // If cell allows anonymous:
    if (cell.anonymous) {
      continue;
    }

    // If cell allows any-authenticated and actorRole is provided:
    if (cell.anyAuthenticated && actorRole !== null) {
      continue;
    }

    // If cell allows this specific role:
    if (actorRole && (cell.roles.includes(actorRole) || cell.roles.includes('*'))) {
      continue;
    }

    // Otherwise, DRIFT001!
    const allowedRolesDesc = cell.roles.length > 0 ? cell.roles.join(', ') : 'none';

    findings.push({
      ruleId: 'DRIFT001',
      risk: 'high',
      confidence: 'high',
      message: `Observed role '${roleName}' performing '${action}' on '${model}' (seqs: ${sampleSeqs.join(', ')}), but static access matrix restricts this action to: ${allowedRolesDesc}.`,
      file: 'audit',
      line: firstSeqNum,
      resource: {
        model,
        source: 'config',
      },
      fingerprint: computeDriftFingerprint('DRIFT001', roleName, model, action),
    });
  }

  // Apply baseline suppression
  const resolvedBaseline = typeof baseline === 'string' ? loadBaseline(baseline) : baseline;
  const finalFindings = applyBaseline(findings, resolvedBaseline);

  // Evaluate threshold
  const hasViolations =
    failOn !== 'none' &&
    finalFindings.some((f) => {
      if (f.suppressed) return false;
      const rank = f.risk === 'high' ? 3 : f.risk === 'medium' ? 2 : 1;
      const thresholdRank = failOn === 'high' ? 3 : failOn === 'medium' ? 2 : 1;
      return rank >= thresholdRank;
    });

  return {
    findings: finalFindings,
    totalAuditedRows,
    distinctCombinations: groups.size,
    exitCode: hasViolations ? 1 : 0,
  };
}

/**
 * Format drift detection findings into a readable terminal report.
 */
export function formatDriftReport(result: DriftResult): string {
  const { findings, totalAuditedRows } = result;
  if (findings.length === 0) {
    return `✔ No RBAC drift detected across ${String(totalAuditedRows)} audit log entries.`;
  }

  const unsuppressed = findings.filter((f) => !f.suppressed);
  const lines = [
    `✖ RBAC Drift Detected (${String(unsuppressed.length)} active finding${unsuppressed.length === 1 ? '' : 's'} across ${String(totalAuditedRows)} audit log entries):`,
    '',
  ];

  for (const f of findings) {
    const icon = f.risk === 'high' ? '✖' : '⚠';
    const tag = f.suppressed ? ' [SUPPRESSED]' : '';
    lines.push(`  ${icon} ${f.ruleId} (${f.risk.toUpperCase()})${tag}: ${f.message}`);
  }

  return lines.join('\n');
}

export const drift = detectDrift;
