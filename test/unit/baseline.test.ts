/**
 * Unit tests for baseline file parsing, loading, suppression, formatting,
 * exit threshold exclusion, and stats computation.
 *
 * @see context.md §6.11
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { describe, it, expect } from 'vitest';
import { loadFixture } from '../helpers/fixture.js';
import { composeMounts } from '../../src/scan/mounts.js';
import { parsePrismaSchema } from '../../src/scan/prisma-schema.js';
import {
  buildRouteNodes,
  parseBaseline,
  loadBaseline,
  applyBaseline,
  generateBaseline,
  formatBaseline,
  writeBaseline,
  isThresholdExceeded,
  calculateScanStats,
  computeRouteFingerprint,
} from '../../src/scan/findings.js';
import { runRules } from '../../src/scan/rules/index.js';
import { ScanConfigError } from '../../src/core/errors.js';
import type { Finding } from '../../src/core/types.js';

describe('Baseline parsing and loading', () => {
  it('parses a valid baseline file content', () => {
    const raw = JSON.stringify({
      version: 1,
      entries: [
        {
          fingerprint: 'abcdef123456',
          ruleId: 'RBAC001',
          note: 'Acceptable risk for v1',
        },
      ],
    });

    const parsed = parseBaseline(raw);
    expect(parsed.version).toBe(1);
    expect(parsed.entries.length).toBe(1);
    expect(parsed.entries[0]?.fingerprint).toBe('abcdef123456');
    expect(parsed.entries[0]?.ruleId).toBe('RBAC001');
    expect(parsed.entries[0]?.note).toBe('Acceptable risk for v1');
  });

  it('throws ScanConfigError on syntax error in JSON', () => {
    expect(() => parseBaseline('{ invalid json')).toThrow(ScanConfigError);
    expect(() => parseBaseline('{ invalid json')).toThrow(/invalid JSON/);
  });

  it('throws ScanConfigError when version is not 1', () => {
    const raw = JSON.stringify({
      version: 2,
      entries: [],
    });
    expect(() => parseBaseline(raw)).toThrow(ScanConfigError);
  });

  it('throws ScanConfigError when entries are missing or invalid', () => {
    const rawNoEntries = JSON.stringify({ version: 1 });
    expect(() => parseBaseline(rawNoEntries)).toThrow(ScanConfigError);

    const rawBadEntries = JSON.stringify({
      version: 1,
      entries: [{ missingFingerprint: true }],
    });
    expect(() => parseBaseline(rawBadEntries)).toThrow(ScanConfigError);
  });

  it('loadBaseline returns null if file does not exist', () => {
    const nonExistent = path.join(os.tmpdir(), `non-existent-baseline-${String(Date.now())}.json`);
    expect(loadBaseline(nonExistent)).toBeNull();
  });
});

describe('Baseline suppression and stats', () => {
  const mockFindings: Finding[] = [
    {
      ruleId: 'RBAC001',
      risk: 'high',
      confidence: 'high',
      message: 'Mutating route missing auth',
      file: 'src/app.ts',
      line: 10,
      fingerprint: 'fp-rbac-001',
    },
    {
      ruleId: 'RBAC005',
      risk: 'medium',
      confidence: 'medium',
      message: 'Owner field missing check',
      file: 'src/app.ts',
      line: 20,
      fingerprint: 'fp-rbac-005',
    },
  ];

  it('marks matching findings as suppressed: true', () => {
    const baseline = {
      version: 1 as const,
      entries: [
        {
          fingerprint: 'fp-rbac-001',
          ruleId: 'RBAC001',
        },
      ],
    };

    const suppressed = applyBaseline(mockFindings, baseline);
    expect(suppressed[0]?.suppressed).toBe(true);
    expect(suppressed[1]?.suppressed).toBeUndefined();
  });

  it('leaves findings untouched when baseline is null or empty', () => {
    const untouched = applyBaseline(mockFindings, null);
    expect(untouched[0]?.suppressed).toBeUndefined();
    expect(untouched[1]?.suppressed).toBeUndefined();
  });

  it('excludes suppressed findings from fail-on exit threshold', () => {
    // Unsuppressed mockFindings contains high risk -> threshold exceeded
    expect(isThresholdExceeded(mockFindings, 'high')).toBe(true);
    expect(isThresholdExceeded(mockFindings, 'medium')).toBe(true);

    // When high finding is suppressed, threshold is NOT exceeded for 'high'
    const baseline = {
      version: 1 as const,
      entries: [{ fingerprint: 'fp-rbac-001', ruleId: 'RBAC001' }],
    };
    const suppressed = applyBaseline(mockFindings, baseline);

    // Active findings only has medium risk now
    expect(isThresholdExceeded(suppressed, 'high')).toBe(false);
    expect(isThresholdExceeded(suppressed, 'medium')).toBe(true);
    expect(isThresholdExceeded(suppressed, 'none')).toBe(false);
  });

  it('computes scan stats correctly with suppressed findings', () => {
    const baseline = {
      version: 1 as const,
      entries: [{ fingerprint: 'fp-rbac-001', ruleId: 'RBAC001' }],
    };
    const suppressed = applyBaseline(mockFindings, baseline);

    const stats = calculateScanStats([], suppressed);
    expect(stats.suppressed).toBe(1);
    // Only unsuppressed medium finding is counted in byRisk
    expect(stats.byRisk.high).toBe(0);
    expect(stats.byRisk.medium).toBe(1);
    expect(stats.byRisk.low).toBe(0);
  });
});

describe('Baseline generation, sorting, and update rewrite', () => {
  it('deduplicates findings and sorts entries by ruleId then fingerprint', () => {
    const findings: Finding[] = [
      {
        ruleId: 'RBAC005',
        risk: 'medium',
        confidence: 'high',
        message: 'msg',
        file: 'file.ts',
        line: 1,
        fingerprint: 'zzz-fp',
      },
      {
        ruleId: 'RBAC001',
        risk: 'high',
        confidence: 'high',
        message: 'msg',
        file: 'file.ts',
        line: 2,
        fingerprint: 'bbb-fp',
      },
      {
        ruleId: 'RBAC001',
        risk: 'high',
        confidence: 'high',
        message: 'msg duplicate',
        file: 'file.ts',
        line: 3,
        fingerprint: 'bbb-fp', // duplicate
      },
      {
        ruleId: 'RBAC001',
        risk: 'high',
        confidence: 'high',
        message: 'msg',
        file: 'file.ts',
        line: 4,
        fingerprint: 'aaa-fp',
      },
    ];

    const baseline = generateBaseline(findings);
    expect(baseline.version).toBe(1);
    expect(baseline.entries.length).toBe(3);

    // Sorted by ruleId, then fingerprint
    expect(baseline.entries[0]?.ruleId).toBe('RBAC001');
    expect(baseline.entries[0]?.fingerprint).toBe('aaa-fp');

    expect(baseline.entries[1]?.ruleId).toBe('RBAC001');
    expect(baseline.entries[1]?.fingerprint).toBe('bbb-fp');

    expect(baseline.entries[2]?.ruleId).toBe('RBAC005');
    expect(baseline.entries[2]?.fingerprint).toBe('zzz-fp');
  });

  it('formatBaseline produces deterministic, sorted JSON with trailing newline', () => {
    const findings: Finding[] = [
      {
        ruleId: 'RBAC002',
        risk: 'high',
        confidence: 'high',
        message: 'msg',
        file: 'file.ts',
        line: 1,
        fingerprint: 'fp-2',
      },
      {
        ruleId: 'RBAC001',
        risk: 'high',
        confidence: 'high',
        message: 'msg',
        file: 'file.ts',
        line: 2,
        fingerprint: 'fp-1',
      },
    ];

    const formatted1 = formatBaseline(findings);
    const formatted2 = formatBaseline([...findings].reverse());

    // Both must be identical strings
    expect(formatted1).toBe(formatted2);
    expect(formatted1.endsWith('\n')).toBe(true);

    const parsed = JSON.parse(formatted1) as { version: number; entries: { ruleId: string }[] };
    expect(parsed.version).toBe(1);
    expect(parsed.entries[0]?.ruleId).toBe('RBAC001');
    expect(parsed.entries[1]?.ruleId).toBe('RBAC002');
  });

  it('writeBaseline writes stable JSON file to disk that can be loaded back', () => {
    const tmpFile = path.join(os.tmpdir(), `test-write-baseline-${String(Date.now())}.json`);
    try {
      const findings: Finding[] = [
        {
          ruleId: 'RBAC001',
          risk: 'high',
          confidence: 'high',
          message: 'msg',
          file: 'file.ts',
          line: 1,
          fingerprint: 'fp-123',
        },
      ];

      writeBaseline(tmpFile, findings);
      expect(fs.existsSync(tmpFile)).toBe(true);

      const loaded = loadBaseline(tmpFile);
      expect(loaded).not.toBeNull();
      expect(loaded?.version).toBe(1);
      expect(loaded?.entries[0]?.fingerprint).toBe('fp-123');
    } finally {
      if (fs.existsSync(tmpFile)) {
        fs.unlinkSync(tmpFile);
      }
    }
  });
});

describe('Fixture baseline verification', () => {
  it('suppresses findings in baseline fixture, excluding from exit threshold and counting in stats', async () => {
    const { fixtureDir, project, config } = await loadFixture('baseline');
    const { routes: composed } = composeMounts(project);
    const schema = parsePrismaSchema('');
    const routeNodes = buildRouteNodes(composed, config, schema);

    const rawFindings = runRules({
      routes: routeNodes,
      config,
      prismaSchema: schema,
    });

    expect(rawFindings.length).toBe(1);
    expect(rawFindings[0]?.ruleId).toBe('RBAC001');
    expect(rawFindings[0]?.fingerprint).toBe(
      computeRouteFingerprint('RBAC001', 'DELETE', '/api/posts/:id'),
    );

    // Before applying baseline: threshold would be exceeded
    expect(isThresholdExceeded(rawFindings, 'high')).toBe(true);

    // Load baseline specified in config
    const baselinePath = path.resolve(fixtureDir, config.baseline!);
    const baseline = loadBaseline(baselinePath);
    expect(baseline).not.toBeNull();

    // Apply baseline
    const findings = applyBaseline(rawFindings, baseline);
    expect(findings.length).toBe(1);
    expect(findings[0]?.suppressed).toBe(true);

    // Suppressed finding is excluded from exit threshold!
    expect(isThresholdExceeded(findings, 'high')).toBe(false);

    // Counted in stats!
    const stats = calculateScanStats(routeNodes, findings);
    expect(stats.suppressed).toBe(1);
    expect(stats.byRisk.high).toBe(0);

    // Update baseline simulation writes sorted, stable JSON
    const updatedFormatted = formatBaseline(findings);
    const reloaded = parseBaseline(updatedFormatted);
    expect(reloaded.entries.length).toBe(1);
    expect(reloaded.entries[0]?.fingerprint).toBe(rawFindings[0]?.fingerprint);
  });

  it('handles applyBaseline with Set and BaselineEntry array', () => {
    const findings: Finding[] = [
      {
        ruleId: 'RBAC001',
        risk: 'high',
        confidence: 'high',
        message: 'msg',
        file: 'app.ts',
        line: 10,
        fingerprint: 'fp1',
      },
    ];

    // With Set
    const fromSet = applyBaseline(findings, new Set(['fp1']));
    expect(fromSet[0]?.suppressed).toBe(true);

    // With BaselineEntry[]
    const fromEntries = applyBaseline(findings, [{ fingerprint: 'fp1', ruleId: 'RBAC001' }]);
    expect(fromEntries[0]?.suppressed).toBe(true);

    // With undefined
    const fromUndef = applyBaseline(findings, undefined);
    expect(fromUndef[0]?.suppressed).toBeUndefined();
  });

  it('handles formatBaseline with BaselineFile object', () => {
    const formatted = formatBaseline({
      version: 1,
      entries: [
        { fingerprint: 'b', ruleId: 'RBAC002' },
        { fingerprint: 'a', ruleId: 'RBAC001' },
      ],
    });
    expect(formatted).toContain('RBAC001');
  });

  it('handles failOn none', () => {
    const findings: Finding[] = [
      {
        ruleId: 'RBAC001',
        risk: 'high',
        confidence: 'high',
        message: 'msg',
        file: 'app.ts',
        line: 10,
        fingerprint: 'fp1',
      },
    ];
    expect(isThresholdExceeded(findings, 'none')).toBe(false);
  });
});
