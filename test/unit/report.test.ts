/**
 * Unit and snapshot tests for Markdown and JSON reporters.
 *
 * Tests:
 * - Deterministic Markdown snapshot tests on 3 fixtures: clean, missing-auth, baseline
 * - Report includes "derived statically" caveat
 * - Report includes honest limitations footer
 * - JSON report validates against its TypeScript type
 *
 * @see context.md §6.12, §14
 */

import * as path from 'node:path';
import { describe, it, expect } from 'vitest';
import { loadFixture } from '../helpers/fixture.js';
import { composeMounts } from '../../src/scan/mounts.js';
import { loadPrismaSchema, parsePrismaSchema } from '../../src/scan/prisma-schema.js';
import {
  buildRouteNodes,
  calculateScanStats,
  loadBaseline,
  applyBaseline,
} from '../../src/scan/findings.js';
import { runRules } from '../../src/scan/rules/index.js';
import { deriveMatrix } from '../../src/scan/matrix.js';
import {
  formatMarkdownReport,
  REPORT_CAVEAT,
  REPORT_LIMITATIONS,
} from '../../src/scan/report/markdown.js';
import {
  formatJsonReport,
  parseJsonReport,
  validateScanResult,
} from '../../src/scan/report/json.js';
import type { ScanResult } from '../../src/core/types.js';

async function runScanOnFixture(fixtureName: string): Promise<ScanResult> {
  const { fixtureDir, project, config } = await loadFixture(fixtureName);
  const { routes: composed } = composeMounts(project);

  let schema;
  try {
    schema = loadPrismaSchema(config.prismaSchema, config.ownership.ownerFields);
  } catch {
    schema = parsePrismaSchema('');
  }

  const routeNodes = buildRouteNodes(composed, config, schema);
  let findings = runRules({
    routes: routeNodes,
    config,
    prismaSchema: schema,
  });

  if (config.baseline) {
    const baselinePath = path.resolve(fixtureDir, config.baseline);
    const baseline = loadBaseline(baselinePath);
    if (baseline) {
      findings = applyBaseline(findings, baseline);
    }
  }

  const models = Array.from(schema.keys());
  const matrix = deriveMatrix(routeNodes, models);
  const stats = calculateScanStats(routeNodes, findings);

  return {
    version: '0.1.0',
    routes: routeNodes,
    findings,
    matrix,
    models,
    stats,
  };
}

describe('Markdown reporter - Snapshot tests on 3 fixtures', () => {
  it('generates expected snapshot for clean fixture', async () => {
    const scanResult = await runScanOnFixture('clean');
    const report = formatMarkdownReport(scanResult, {
      version: '0.1.0',
      date: null, // omit timestamp for stable snapshot
      configPath: 'test/fixtures/clean/trailguard.config.ts',
    });

    // Check required caveat and limitations
    expect(report).toContain(REPORT_CAVEAT);
    for (const lim of REPORT_LIMITATIONS) {
      expect(report).toContain(lim);
    }

    expect(report).toMatchSnapshot();
  });

  it('generates expected snapshot for missing-auth fixture', async () => {
    const scanResult = await runScanOnFixture('missing-auth');
    const report = formatMarkdownReport(scanResult, {
      version: '0.1.0',
      date: null,
      configPath: 'test/fixtures/missing-auth/trailguard.config.ts',
    });

    expect(report).toContain(REPORT_CAVEAT);
    expect(report).toContain('RBAC001');
    expect(report).toContain('DELETE /api/posts/:id');

    expect(report).toMatchSnapshot();
  });

  it('generates expected snapshot for baseline fixture (suppressed findings)', async () => {
    const scanResult = await runScanOnFixture('baseline');
    const report = formatMarkdownReport(scanResult, {
      version: '0.1.0',
      date: null,
      configPath: 'test/fixtures/baseline/trailguard.config.ts',
    });

    expect(report).toContain(REPORT_CAVEAT);
    expect(report).toContain('**Suppressed (baselined):** 1');
    expect(report).toContain('HIGH (suppressed)');

    expect(report).toMatchSnapshot();
  });
});

describe('Markdown reporter options', () => {
  it('injects custom date when provided', async () => {
    const scanResult = await runScanOnFixture('clean');
    const report = formatMarkdownReport(scanResult, {
      version: '0.1.0',
      date: '2026-10-26T12:00:00.000Z',
    });

    expect(report).toContain('- **Date:** 2026-10-26T12:00:00.000Z');
  });

  it('formats Date object when provided', async () => {
    const scanResult = await runScanOnFixture('clean');
    const dateObj = new Date('2026-05-15T08:30:00.000Z');
    const report = formatMarkdownReport(scanResult, {
      version: '0.1.0',
      date: dateObj,
    });

    expect(report).toContain('- **Date:** 2026-05-15T08:30:00.000Z');
  });
});

describe('JSON reporter', () => {
  it('validates and formats full ScanResult against its TypeScript schema', async () => {
    const scanResult = await runScanOnFixture('missing-auth');

    // Validates without throwing
    const validated = validateScanResult(scanResult);
    expect(validated.version).toBe('0.1.0');
    expect(validated.findings.length).toBe(1);

    // Formats into valid JSON
    const jsonString = formatJsonReport(scanResult);
    expect(jsonString.endsWith('\n')).toBe(true);

    // Parses back to identical ScanResult
    const parsed = parseJsonReport(jsonString);
    expect(parsed.version).toBe(scanResult.version);
    expect(parsed.findings.length).toBe(scanResult.findings.length);
    expect(parsed.matrix.length).toBe(scanResult.matrix.length);
    expect(parsed.stats).toEqual(scanResult.stats);
  });

  it('throws validation error when ScanResult is missing required fields', () => {
    const invalidResult = {
      version: '0.1.0',
      // missing routes, findings, matrix, stats
    };

    expect(() => formatJsonReport(invalidResult as unknown as ScanResult)).toThrow();
  });
});
