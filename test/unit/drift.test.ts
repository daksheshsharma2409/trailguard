/**
 * Unit tests for Drift Detection Engine (scan/drift.ts and cli/drift-command.ts).
 *
 * @see context.md §8, tasks.md T4.5, T5.3
 */

import { describe, it, expect } from 'vitest';
import { ConfigSchema } from '../../src/config/schema.js';
import type { MatrixCell } from '../../src/core/types.js';
import {
  detectDrift,
  formatDriftReport,
  computeDriftFingerprint,
  type DriftPrismaClient,
} from '../../src/scan/drift.js';
import { runDriftCommand } from '../../src/cli/drift-command.js';

describe('Unit: Drift Detection Engine (scan/drift.ts)', () => {
  const baseConfig = ConfigSchema.parse({
    entry: ['app.ts'],
    roles: {
      known: ['ADMIN', 'TEACHER', 'STUDENT'],
    },
    audit: {
      models: ['User', 'Student'],
    },
    drift: {
      strict: false,
      allowRoles: ['SYSTEM'],
    },
  });

  const matrix: MatrixCell[] = [
    {
      resource: 'User',
      action: 'delete',
      anonymous: false,
      anyAuthenticated: false,
      roles: ['ADMIN'],
      own: false,
      uncertain: false,
    },
    {
      resource: 'User',
      action: 'read',
      anonymous: false,
      anyAuthenticated: true,
      roles: ['ADMIN', 'TEACHER', 'STUDENT'],
      own: false,
      uncertain: false,
    },
    {
      resource: 'Student',
      action: 'create',
      anonymous: false,
      anyAuthenticated: false,
      roles: ['ADMIN', 'TEACHER'],
      own: false,
      uncertain: false,
    },
  ];

  it('detects DRIFT001 when a TEACHER deletes a User (ADMIN-only) with sample seqs and exit code 1', async () => {
    const mockPrisma: DriftPrismaClient = {
      auditLog: {
        findMany: async () => [
          {
            seq: 101n,
            actorRole: 'TEACHER',
            actorId: 'teacher-1',
            model: 'User',
            action: 'DELETE',
            requestId: 'req-abc',
            createdAt: new Date('2026-10-20T10:00:00Z'),
          },
          {
            seq: 102n,
            actorRole: 'TEACHER',
            actorId: 'teacher-1',
            model: 'User',
            action: 'DELETE',
            requestId: 'req-def',
            createdAt: new Date('2026-10-20T10:05:00Z'),
          },
        ],
      },
    };

    const result = await detectDrift({
      prisma: mockPrisma,
      config: baseConfig,
      matrix,
    });

    expect(result.exitCode).toBe(1);
    expect(result.findings).toHaveLength(1);
    const finding = result.findings[0]!;
    expect(finding.ruleId).toBe('DRIFT001');
    expect(finding.risk).toBe('high');
    expect(finding.confidence).toBe('high');
    expect(finding.message).toContain("Observed role 'TEACHER' performing 'delete' on 'User'");
    expect(finding.message).toContain('seqs: 101, 102');
    expect(finding.message).toContain('restricts this action to: ADMIN');
    expect(finding.fingerprint).toBe(computeDriftFingerprint('DRIFT001', 'TEACHER', 'User', 'delete'));
  });

  it('reports 0 findings and exit code 0 when activity is allowed by matrix', async () => {
    const mockPrisma: DriftPrismaClient = {
      auditLog: {
        findMany: async () => [
          {
            seq: 1n,
            actorRole: 'ADMIN',
            actorId: 'admin-1',
            model: 'User',
            action: 'DELETE',
            requestId: 'req-1',
            createdAt: new Date(),
          },
          {
            seq: 2n,
            actorRole: 'TEACHER',
            actorId: 'teacher-1',
            model: 'Student',
            action: 'CREATE',
            requestId: 'req-2',
            createdAt: new Date(),
          },
        ],
      },
    };

    const result = await detectDrift({
      prisma: mockPrisma,
      config: baseConfig,
      matrix,
    });

    expect(result.exitCode).toBe(0);
    expect(result.findings).toHaveLength(0);
  });

  it('does not flag SYSTEM role by default (role in allowRoles)', async () => {
    const mockPrisma: DriftPrismaClient = {
      auditLog: {
        findMany: async () => [
          {
            seq: 50n,
            actorRole: 'SYSTEM',
            actorId: 'system-job',
            model: 'User',
            action: 'DELETE',
            requestId: 'cron-1',
            createdAt: new Date(),
          },
        ],
      },
    };

    const result = await detectDrift({
      prisma: mockPrisma,
      config: baseConfig,
      matrix,
    });

    expect(result.exitCode).toBe(0);
    expect(result.findings).toHaveLength(0);
  });

  it('detects DRIFT002 when actorRole is unrecognized and not in allowRoles', async () => {
    const mockPrisma: DriftPrismaClient = {
      auditLog: {
        findMany: async () => [
          {
            seq: 77n,
            actorRole: 'HACKER',
            actorId: 'bad-actor',
            model: 'User',
            action: 'DELETE',
            requestId: 'attack-1',
            createdAt: new Date(),
          },
        ],
      },
    };

    const result = await detectDrift({
      prisma: mockPrisma,
      config: baseConfig,
      matrix,
    });

    expect(result.findings.some((f) => f.ruleId === 'DRIFT002')).toBe(true);
    const d002 = result.findings.find((f) => f.ruleId === 'DRIFT002')!;
    expect(d002.risk).toBe('medium');
    expect(d002.message).toContain("unrecognized role 'HACKER'");
  });

  it('detects undeclared action on resource (strict vs non-strict)', async () => {
    const mockPrisma: DriftPrismaClient = {
      auditLog: {
        findMany: async () => [
          {
            seq: 88n,
            actorRole: 'ADMIN',
            actorId: 'admin-1',
            model: 'SecretVault',
            action: 'CREATE',
            requestId: 'r1',
            createdAt: new Date(),
          },
        ],
      },
    };

    // Non-strict: emits low risk finding
    const nonStrictResult = await detectDrift({
      prisma: mockPrisma,
      config: baseConfig,
      matrix,
    });
    expect(nonStrictResult.findings).toHaveLength(1);
    expect(nonStrictResult.findings[0]?.ruleId).toBe('DRIFT002');
    expect(nonStrictResult.findings[0]?.risk).toBe('low');
    expect(nonStrictResult.exitCode).toBe(0); // low risk does not exceed default 'high' failOn

    // Strict: emits medium risk finding
    const strictConfig = {
      ...baseConfig,
      drift: { ...baseConfig.drift, strict: true },
    };
    const strictResult = await detectDrift({
      prisma: mockPrisma,
      config: strictConfig,
      matrix,
      failOn: 'medium',
    });
    expect(strictResult.findings).toHaveLength(1);
    expect(strictResult.findings[0]?.ruleId).toBe('DRIFT002');
    expect(strictResult.findings[0]?.risk).toBe('medium');
    expect(strictResult.exitCode).toBe(1);
  });

  it('respects --since filter passing gte Date to query', async () => {
    let capturedWhere: Record<string, unknown> | null = null;
    const mockPrisma: DriftPrismaClient = {
      auditLog: {
        findMany: async (args) => {
          capturedWhere = args.where as Record<string, unknown>;
          return [];
        },
      },
    };

    await detectDrift({
      prisma: mockPrisma,
      config: baseConfig,
      matrix,
      since: '2026-10-01T00:00:00.000Z',
    });

    expect(capturedWhere).toEqual({
      createdAt: { gte: new Date('2026-10-01T00:00:00.000Z') },
    });
  });

  it('suppresses findings matching baseline entries', async () => {
    const mockPrisma: DriftPrismaClient = {
      auditLog: {
        findMany: async () => [
          {
            seq: 101n,
            actorRole: 'TEACHER',
            actorId: 'teacher-1',
            model: 'User',
            action: 'DELETE',
            createdAt: new Date(),
          },
        ],
      },
    };

    const fp = computeDriftFingerprint('DRIFT001', 'TEACHER', 'User', 'delete');
    const baseline = {
      version: 1 as const,
      entries: [{ fingerprint: fp, ruleId: 'DRIFT001', note: 'legacy exemption' }],
    };

    const result = await detectDrift({
      prisma: mockPrisma,
      config: baseConfig,
      matrix,
      baseline,
    });

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.suppressed).toBe(true);
    expect(result.exitCode).toBe(0); // suppressed findings don't trigger failure
  });

  it('formats terminal drift report for clean and violation states', () => {
    const cleanReport = formatDriftReport({
      findings: [],
      totalAuditedRows: 42,
      distinctCombinations: 3,
      exitCode: 0,
    });
    expect(cleanReport).toContain('✔ No RBAC drift detected across 42 audit log entries.');

    const violationReport = formatDriftReport({
      findings: [
        {
          ruleId: 'DRIFT001',
          risk: 'high',
          confidence: 'high',
          message: "Observed role 'TEACHER' deleting 'User'",
          file: 'audit',
          line: 10,
          fingerprint: 'fp1',
        },
      ],
      totalAuditedRows: 15,
      distinctCombinations: 2,
      exitCode: 1,
    });
    expect(violationReport).toContain('✖ RBAC Drift Detected (1 active finding');
    expect(violationReport).toContain('DRIFT001 (HIGH)');
  });

  describe('runDriftCommand (cli/drift-command.ts)', () => {
    it('returns exit code 2 when config file cannot be found or loaded', async () => {
      const outcome = await runDriftCommand({
        config: '/nonexistent/path/trailguard.config.ts',
      });

      expect(outcome.exitCode).toBe(2);
      expect(outcome.message).toContain('Error loading config file');
    });

    it('runs end-to-end drift command with clean fixture and mock prisma', async () => {
      const mockPrisma: DriftPrismaClient = {
        auditLog: {
          findMany: async () => [],
        },
      };

      const outcome = await runDriftCommand({
        config: 'test/fixtures/clean/trailguard.config.ts',
        prisma: mockPrisma,
      });

      expect(outcome.exitCode).toBe(0);
      expect(outcome.message).toContain('No RBAC drift detected');
    });
  });
});
