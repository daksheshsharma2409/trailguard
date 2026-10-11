/**
 * Unit tests for scan() and scan options (scan/scan.ts).
 *
 * Tests:
 * - config as object vs config as file path
 * - format options: sarif, json, markdown, terminal
 * - out option to write report to file
 * - baseline loading and baseline update
 * - failOn thresholds (high, medium, low, none)
 * - src CLI override
 * - non-existent prismaSchema falling back to empty schema
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { describe, it, expect } from 'vitest';
import { scan } from '../../src/scan/index.js';

describe('Unit: scan() options and reporters (scan/scan.ts)', () => {
  const cleanFixtureConfig = path.resolve('test/fixtures/clean/trailguard.config.ts');
  const missingAuthConfig = path.resolve('test/fixtures/missing-auth/trailguard.config.ts');
  const cleanAppEntry = path.resolve('test/fixtures/clean/src/app.ts');
  const cleanPrismaSchema = path.resolve('test/fixtures/clean/prisma/schema.prisma');

  it('runs scan with config path and terminal format', async () => {
    const result = await scan({
      config: cleanFixtureConfig,
      format: 'terminal',
    });

    expect(result.exitCode).toBe(0);
    expect(result.report).toContain('No findings detected');
  });

  it('formats report as JSON', async () => {
    const result = await scan({
      config: missingAuthConfig,
      format: 'json',
    });

    expect(result.exitCode).toBe(1);
    const parsed = JSON.parse(result.report) as { findings: unknown[]; version: string };
    expect(parsed.findings).toBeDefined();
    expect(parsed.version).toBeDefined();
  });

  it('formats report as SARIF', async () => {
    const result = await scan({
      config: missingAuthConfig,
      format: 'sarif',
    });

    expect(result.exitCode).toBe(1);
    const sarif = JSON.parse(result.report) as { version: string; runs: Array<{ results: unknown[] }> };
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs[0]?.results.length).toBeGreaterThan(0);
  });

  it('formats report as Markdown', async () => {
    const result = await scan({
      config: missingAuthConfig,
      format: 'markdown',
    });

    expect(result.exitCode).toBe(1);
    expect(result.report).toContain('# Trailguard Scan Report');
  });

  it('writes output to a file when out option is provided', async () => {
    const tempFile = path.join(os.tmpdir(), `tg-scan-out-${String(Date.now())}.txt`);

    try {
      const result = await scan({
        config: cleanFixtureConfig,
        out: tempFile,
      });

      expect(result.exitCode).toBe(0);
      expect(fs.existsSync(tempFile)).toBe(true);
      const content = fs.readFileSync(tempFile, 'utf8');
      expect(content).toContain('No findings detected');
    } finally {
      if (fs.existsSync(tempFile)) {
        fs.unlinkSync(tempFile);
      }
    }
  });

  it('supports inline Config object instead of file path', async () => {
    const result = await scan({
      config: {
        entry: [cleanAppEntry],
        auth: {
          middleware: ['authenticate'],
        },
        roles: {
          middleware: ['requireRole'],
          extractor: 'firstStringArg',
          known: ['ADMIN', 'USER'],
        },
        audit: {
          models: [],
        },
        ownership: {
          middleware: [],
          ownerFields: ['userId'],
        },
        prismaSchema: cleanPrismaSchema,
        ignore: [],
      },
    });

    expect(result.exitCode).toBe(0);
  });

  it('falls back to empty schema when prismaSchema file does not exist', async () => {
    const result = await scan({
      config: {
        entry: [cleanAppEntry],
        auth: {
          middleware: ['authenticate'],
        },
        roles: {
          middleware: ['requireRole'],
          extractor: 'firstStringArg',
          known: ['ADMIN', 'USER'],
        },
        audit: {
          models: [],
        },
        ownership: {
          middleware: [],
          ownerFields: ['userId'],
        },
        prismaSchema: 'non/existent/schema.prisma',
        ignore: [],
      },
    });

    expect(result.exitCode).toBe(0);
  });

  it('respects failOn threshold levels', async () => {
    const failOnHigh = await scan({
      config: missingAuthConfig,
      failOn: 'high',
    });
    expect(failOnHigh.exitCode).toBe(1);

    const failOnLow = await scan({
      config: missingAuthConfig,
      failOn: 'low',
    });
    expect(failOnLow.exitCode).toBe(1);

    const failOnNone = await scan({
      config: missingAuthConfig,
      failOn: 'none',
    });
    expect(failOnNone.exitCode).toBe(0);
  });

  it('creates and updates baseline file via updateBaseline option', async () => {
    const tempBaseline = path.join(os.tmpdir(), `tg-baseline-${String(Date.now())}.json`);

    try {
      // 1. Initial scan with updateBaseline writes the baseline
      await scan({
        config: missingAuthConfig,
        baseline: tempBaseline,
        updateBaseline: true,
      });

      expect(fs.existsSync(tempBaseline)).toBe(true);
      const baselineData = JSON.parse(fs.readFileSync(tempBaseline, 'utf8')) as {
        entries: Array<{ ruleId: string; fingerprint: string }>;
      };
      expect(baselineData.entries.length).toBeGreaterThan(0);

      // 2. Subsequent scan with baseline suppresses the findings
      const suppressedResult = await scan({
        config: missingAuthConfig,
        baseline: tempBaseline,
      });

      expect(suppressedResult.exitCode).toBe(0);
      const activeFindings = suppressedResult.findings.filter((f) => !f.suppressed);
      expect(activeFindings.length).toBe(0);
    } finally {
      if (fs.existsSync(tempBaseline)) {
        fs.unlinkSync(tempBaseline);
      }
    }
  });

  it('overrides entry via src option', async () => {
    const result = await scan({
      config: cleanFixtureConfig,
      src: cleanAppEntry,
    });

    expect(result.exitCode).toBe(0);
  });

  it('formats SARIF report with suppressed findings and relative baseline path', async () => {
    const relBaseline = 'tmp-test-rel-baseline.json';
    try {
      // Create relative baseline
      await scan({
        config: missingAuthConfig,
        baseline: relBaseline,
        updateBaseline: true,
      });

      // Scan with SARIF format and relative baseline
      const sarifResult = await scan({
        config: missingAuthConfig,
        baseline: relBaseline,
        format: 'sarif',
      });

      expect(sarifResult.report).toContain('suppressions');
    } finally {
      const fixtureBaseline = path.join(path.dirname(missingAuthConfig), relBaseline);
      if (fs.existsSync(fixtureBaseline)) {
        fs.unlinkSync(fixtureBaseline);
      }
      if (fs.existsSync(relBaseline)) {
        fs.unlinkSync(relBaseline);
      }
    }
  });
});
