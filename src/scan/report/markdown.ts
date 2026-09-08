/**
 * Markdown report generator for static analysis scan results.
 *
 * Generates deterministic GitHub-flavored markdown with:
 * - Header (version, optional date/clock, config path, "derived statically" caveat)
 * - Summary statistics (routes, by risk, suppressed count)
 * - Findings table (# | Risk | Rule | Route/Location | Auth | Role | Ownership | Resource | Handler | Confidence)
 * - RBAC access matrix table (✅ ❌ ⚠️ own, (public) for anonymous)
 * - Honest limitations footer
 *
 * @see context.md §6.12, §14
 */

import { MATRIX_DISCLAIMER } from '../matrix.js';
import { RISK_LEVELS } from '../findings.js';
import type { Finding, MatrixCell, RouteNode, ScanResult } from '../../core/types.js';

export interface MarkdownReportOptions {
  /** Injectable tool version string (default: scanResult.version or '0.1.0'). */
  version?: string | undefined;
  /** Injectable date/timestamp. Pass null or undefined to omit timestamp line for snapshot stability. */
  date?: string | Date | null | undefined;
  /** Path to config file for header display. */
  configPath?: string | undefined;
}

export const REPORT_CAVEAT =
  'This report is derived statically from route and middleware declarations. It does not execute handlers or prove runtime safety.' as const;

export const REPORT_LIMITATIONS = [
  '**Static analysis is heuristic:** dynamic routes, spread middleware, runtime-registered routes, and aliased clients can be missed or marked low-confidence.',
  '**Ownership is probable, never proven:** static heuristics detect code patterns, not runtime guarantees.',
  '**The matrix is derived from declarations:** it does not execute handlers.',
  '**Audit chain is tamper-evident, not tamper-proof:** the application holds HMAC keys; external checkpoints are required to detect truncation.',
  '**Audited writes serialize on one head row:** creates a throughput ceiling under extreme concurrency.',
] as const;

function getFindingLocation(finding: Finding): string {
  if (finding.route) {
    return `${finding.route.method.toUpperCase()} ${finding.route.path}`;
  }
  return `${finding.file}:${String(finding.line)}`;
}

function findRouteForFinding(finding: Finding, routes: RouteNode[]): RouteNode | undefined {
  if (!finding.route) return undefined;
  const route = finding.route;
  return routes.find(
    (r) =>
      r.method.toLowerCase() === route.method.toLowerCase() &&
      r.path === route.path,
  );
}

function getFindingAuth(finding: Finding, route?: RouteNode): string {
  if (route) {
    const hasAuth = route.chain.some((m) => m.class.kind === 'auth');
    return hasAuth ? 'yes' : 'no';
  }
  if (finding.ruleId === 'RBAC001') return 'no';
  return '-';
}

function getFindingRole(finding: Finding, route?: RouteNode): string {
  if (route) {
    const roles = route.chain
      .filter((m) => m.class.kind === 'role' && m.class.value !== 'unknown')
      .map((m) => (m.class as { kind: 'role'; value: string }).value);
    if (roles.length > 0) return roles.join(', ');
    return '-';
  }
  return '-';
}

function getFindingOwnership(finding: Finding, route?: RouteNode): string {
  if (route) {
    return route.ownership;
  }
  return '-';
}

function getFindingResource(finding: Finding, route?: RouteNode): string {
  return finding.resource?.model ?? route?.resource?.model ?? '-';
}

function getFindingHandler(finding: Finding, route?: RouteNode): string {
  return finding.route?.handler ?? route?.handler?.name ?? '-';
}

function formatMatrixCell(cell: MatrixCell | undefined): string {
  if (!cell) {
    return '❌';
  }
  const parts: string[] = [];
  if (cell.anonymous) {
    parts.push('(public)');
  }
  if (cell.anyAuthenticated) {
    parts.push('(authenticated)');
  }
  if (cell.roles.length > 0) {
    parts.push(cell.roles.join(', '));
  }

  if (parts.length === 0) {
    return '❌';
  }

  let text = `✅ ${parts.join(', ')}`;
  if (cell.own) {
    text += ' ⚠️ own';
  }
  if (cell.uncertain) {
    text += ' ⚠️ uncertain';
  }
  return text;
}

/**
 * Generate deterministic Markdown report from a ScanResult.
 */
export function formatMarkdownReport(
  scanResult: ScanResult,
  options: MarkdownReportOptions = {},
): string {
  const version = options.version ?? scanResult.version;
  const configPath = options.configPath ?? 'trailguard.config.ts';

  const lines: string[] = [];

  // 1. Header
  lines.push('# Trailguard Scan Report');
  lines.push('');
  lines.push(`- **Tool version:** trailguard v${version}`);
  if (options.date !== null && options.date !== undefined && options.date !== '') {
    const dateStr = options.date instanceof Date ? options.date.toISOString() : options.date;
    lines.push(`- **Date:** ${dateStr}`);
  }
  lines.push(`- **Config:** \`${configPath}\``);
  lines.push('');
  lines.push(`> ⚠️ **Note:** ${REPORT_CAVEAT}`);
  lines.push('');

  // 2. Summary stats
  const { stats } = scanResult;
  lines.push('## Summary');
  lines.push('');
  lines.push(`- **Routes:** ${String(stats.routes)} total (${String(stats.protectedRoutes)} protected, ${String(stats.unprotectedRoutes)} unprotected)`);
  lines.push(
    `- **Findings by Risk:** High: ${String(stats.byRisk.high)}, Medium: ${String(stats.byRisk.medium)}, Low: ${String(stats.byRisk.low)}`,
  );
  lines.push(`- **Suppressed (baselined):** ${String(stats.suppressed)}`);
  lines.push('');

  // 3. RBAC Access Matrix Table
  lines.push('## RBAC Access Matrix');
  lines.push('');
  lines.push(`*${MATRIX_DISCLAIMER}*`);
  lines.push('');

  const resources = Array.from(new Set(scanResult.matrix.map((c) => c.resource))).sort((a, b) =>
    a.localeCompare(b),
  );

  if (resources.length === 0) {
    lines.push('_No resources mapped._');
  } else {
    lines.push('| Resource | Create | Read | Update | Delete |');
    lines.push('|---|---|---|---|---|');

    for (const res of resources) {
      const createCell = scanResult.matrix.find((c) => c.resource === res && c.action === 'create');
      const readCell = scanResult.matrix.find((c) => c.resource === res && c.action === 'read');
      const updateCell = scanResult.matrix.find((c) => c.resource === res && c.action === 'update');
      const deleteCell = scanResult.matrix.find((c) => c.resource === res && c.action === 'delete');

      lines.push(
        `| ${res} | ${formatMatrixCell(createCell)} | ${formatMatrixCell(readCell)} | ${formatMatrixCell(updateCell)} | ${formatMatrixCell(deleteCell)} |`,
      );
    }
  }
  lines.push('');

  // 4. Findings Table
  lines.push('## Findings');
  lines.push('');

  if (scanResult.findings.length === 0) {
    lines.push('_No findings detected._');
  } else {
    // Sort findings deterministically: risk desc, rule asc, location asc
    const sortedFindings = [...scanResult.findings].sort((a, b) => {
      const riskDiff = RISK_LEVELS[b.risk] - RISK_LEVELS[a.risk];
      if (riskDiff !== 0) return riskDiff;
      const ruleDiff = a.ruleId.localeCompare(b.ruleId);
      if (ruleDiff !== 0) return ruleDiff;
      const locA = getFindingLocation(a);
      const locB = getFindingLocation(b);
      return locA.localeCompare(locB);
    });

    lines.push('| # | Risk | Rule | Route/Location | Auth | Role | Ownership | Resource | Handler | Confidence |');
    lines.push('|---|---|---|---|---|---|---|---|---|---|');

    sortedFindings.forEach((f, idx) => {
      const route = findRouteForFinding(f, scanResult.routes);
      const riskText = f.suppressed ? `${f.risk.toUpperCase()} (suppressed)` : f.risk.toUpperCase();
      const loc = getFindingLocation(f);
      const auth = getFindingAuth(f, route);
      const role = getFindingRole(f, route);
      const own = getFindingOwnership(f, route);
      const res = getFindingResource(f, route);
      const handler = getFindingHandler(f, route);

      lines.push(
        `| ${String(idx + 1)} | ${riskText} | ${f.ruleId} | ${loc} | ${auth} | ${role} | ${own} | ${res} | ${handler} | ${f.confidence} |`,
      );
    });
  }
  lines.push('');

  // 5. Limitations Footer
  lines.push('## Limitations');
  lines.push('');
  REPORT_LIMITATIONS.forEach((lim, idx) => {
    lines.push(`${String(idx + 1)}. ${lim}`);
  });
  lines.push('');

  return `${lines.join('\n')}\n`;
}
