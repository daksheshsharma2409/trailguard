/**
 * Unit tests for SARIF 2.1.0 reporter (T5.5).
 *
 * Asserts:
 *  - Output validates against the OASIS SARIF 2.1.0 schema (vendored in test/fixtures/sarif-schema-2.1.0.json).
 *  - Rules descriptors include id, name, descriptions, and defaultConfiguration.
 *  - Results include level, locations, and partialFingerprints.
 *  - Suppressions emitted for baseline-suppressed findings.
 *  - End-to-end static scan() with format: 'sarif' validates against schema.
 *
 * @see tasks.md T5.5, context.md §6.12
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { describe, it, expect, beforeAll } from 'vitest';
import Ajv from 'ajv';
import draft4MetaSchema from 'ajv/lib/refs/json-schema-draft-04.json';
import { formatSarifReport, type SarifLog } from '../../src/scan/report/sarif.js';
import { scan } from '../../src/scan/index.js';
import type { Finding, ScanResult } from '../../src/core/types.js';

describe('SARIF 2.1.0 reporter (T5.5)', () => {
  let validateSarif: Ajv.ValidateFunction;

  beforeAll(() => {
    const schemaPath = path.resolve('test/fixtures/sarif-schema-2.1.0.json');
    const rawSchema = JSON.parse(fs.readFileSync(schemaPath, 'utf8')) as object;

    const ajv = new Ajv({ schemaId: 'auto', allErrors: true });
    ajv.addMetaSchema(draft4MetaSchema);
    validateSarif = ajv.compile(rawSchema);
  });

  const mockFindings: Finding[] = [
    {
      ruleId: 'RBAC001',
      risk: 'high',
      file: 'src/routes/users.ts',
      line: 42,
      message: 'Mutation route POST /api/users does not have authentication middleware',
      fingerprint: 'a1b2c3d4e5f60001',
      suppressed: false,
    },
    {
      ruleId: 'AUD001',
      risk: 'high',
      file: 'src/services/billing.ts',
      line: 88,
      message: 'Direct write to audited model Payment bypasses audit client',
      fingerprint: 'b2c3d4e5f6a10002',
      suppressed: true,
    },
    {
      ruleId: 'RBAC005',
      risk: 'medium',
      file: 'src/routes/reports.ts',
      line: 15,
      message: 'Read route GET /api/reports without role check',
      fingerprint: 'c3d4e5f6a1b20003',
      suppressed: false,
    },
  ];

  const mockScanResult: ScanResult = {
    version: '0.1.0',
    routes: [],
    findings: mockFindings,
    matrix: [],
    models: ['Payment', 'User'],
    stats: {
      routes: 10,
      protectedRoutes: 8,
      unprotectedRoutes: 2,
      byRisk: {
        high: 2,
        medium: 1,
        low: 0,
      },
      suppressed: 1,
    },
  };

  it('generates SARIF that validates against OASIS SARIF 2.1.0 schema', () => {
    const reportStr = formatSarifReport(mockScanResult);
    const parsed = JSON.parse(reportStr) as SarifLog;

    const isValid = validateSarif(parsed);
    if (!isValid) {
      console.error('SARIF validation errors:', validateSarif.errors);
    }
    expect(isValid).toBe(true);
    expect(parsed.version).toBe('2.1.0');
    expect(parsed.$schema).toContain('sarif-schema-2.1.0.json');
  });

  it('includes driver rules descriptors with default configuration', () => {
    const reportStr = formatSarifReport(mockScanResult);
    const parsed = JSON.parse(reportStr) as SarifLog;

    const driver = parsed.runs[0]?.tool.driver;
    expect(driver).toBeDefined();
    expect(driver?.name).toBe('trailguard');
    expect(driver?.version).toBe('0.1.0');

    // Asserts rules descriptors exist
    expect(driver?.rules.length).toBeGreaterThanOrEqual(11);
    const rbac001 = driver?.rules.find((r) => r.id === 'RBAC001');
    expect(rbac001).toBeDefined();
    expect(rbac001?.defaultConfiguration.level).toBe('error');
    expect(rbac001?.shortDescription.text).toBeDefined();

    const rbac005 = driver?.rules.find((r) => r.id === 'RBAC005');
    expect(rbac005?.defaultConfiguration.level).toBe('warning');
  });

  it('maps findings to results with locations, partialFingerprints, and suppressions', () => {
    const reportStr = formatSarifReport(mockScanResult);
    const parsed = JSON.parse(reportStr) as SarifLog;

    const results = parsed.runs[0]?.results ?? [];
    expect(results).toHaveLength(3);

    // Unsuppressed finding
    const res1 = results.find((r) => r.ruleId === 'RBAC001');
    expect(res1).toBeDefined();
    expect(res1?.level).toBe('error');
    expect(res1?.partialFingerprints['primaryLocationLineHash']).toBe('a1b2c3d4e5f60001');
    expect(res1?.locations[0]?.physicalLocation.artifactLocation.uri).toBe('src/routes/users.ts');
    expect(res1?.locations[0]?.physicalLocation.region.startLine).toBe(42);
    expect(res1?.suppressions).toBeUndefined();

    // Suppressed finding
    const res2 = results.find((r) => r.ruleId === 'AUD001');
    expect(res2).toBeDefined();
    expect(res2?.partialFingerprints['primaryLocationLineHash']).toBe('b2c3d4e5f6a10002');
    expect(res2?.suppressions).toBeDefined();
    expect(res2?.suppressions?.[0]?.kind).toBe('external');
    expect(res2?.suppressions?.[0]?.status).toBe('accepted');
  });

  it('validates actual scan() output formatted as SARIF against schema', async () => {
    const fixtureConfig = path.resolve('test/fixtures/missing-auth/trailguard.config.ts');
    const scanOut = await scan({
      config: fixtureConfig,
      format: 'sarif',
    });

    const parsed = JSON.parse(scanOut.report) as SarifLog;
    const isValid = validateSarif(parsed);
    if (!isValid) {
      console.error('Scan SARIF validation errors:', validateSarif.errors);
    }
    expect(isValid).toBe(true);
    expect(parsed.runs[0]?.results.length).toBeGreaterThan(0);
    expect(parsed.runs[0]?.results[0]?.partialFingerprints['primaryLocationLineHash']).toBeDefined();
  });
});
