/**
 * Unit tests for rules registry, individual RBAC rules, findings, and fingerprints.
 *
 * @see context.md §6.10, §6.11
 */

import { describe, it, expect } from 'vitest';
import { Project } from 'ts-morph';
import { loadFixture } from '../helpers/fixture.js';
import { composeMounts } from '../../src/scan/mounts.js';
import { loadPrismaSchema, parsePrismaSchema } from '../../src/scan/prisma-schema.js';
import {
  buildRouteNodes,
  computeRouteFingerprint,
  resolveEffectiveRisk,
} from '../../src/scan/findings.js';
import {
  runRules,
  DEFAULT_RULES,
  rbac001,
  rbac002,
  rbac005,
  rbac007,
} from '../../src/scan/rules/index.js';
import { ConfigSchema } from '../../src/config/schema.js';

describe('Stable fingerprints (no line numbers)', () => {
  it('guarantees fingerprint remains identical when unrelated lines are added above route', () => {
    const codeA = `
      import express from 'express';
      const app = express();
      app.delete('/api/posts/:id', (req, res) => res.json({ ok: true }));
    `;

    const codeB = `
      // Unrelated comments added above
      // Line 2
      // Line 3
      import express from 'express';
      const logger = () => {};
      const unusedVariable = 42;
      /* Multiple
         lines
         of
         comments */
      const app = express();
      app.delete('/api/posts/:id', (req, res) => res.json({ ok: true }));
    `;

    const projectA = new Project({ useInMemoryFileSystem: true });
    projectA.createSourceFile('app.ts', codeA);
    const { routes: routesA } = composeMounts(projectA);
    expect(routesA.length).toBe(1);

    const projectB = new Project({ useInMemoryFileSystem: true });
    projectB.createSourceFile('app.ts', codeB);
    const { routes: routesB } = composeMounts(projectB);
    expect(routesB.length).toBe(1);

    const routeA = routesA[0]!;
    const routeB = routesB[0]!;

    // Line numbers must be different
    expect(routeA.line).not.toBe(routeB.line);

    // Fingerprints must be strictly identical
    const fpA = computeRouteFingerprint('RBAC001', routeA.method, routeA.path);
    const fpB = computeRouteFingerprint('RBAC001', routeB.method, routeB.path);

    expect(fpA).toBe(fpB);
    expect(fpA.length).toBe(64); // 64-char sha256 hex
  });
});

describe('Config risk overrides and disable rule', () => {
  const dummyRoute = {
    method: 'DELETE' as const,
    path: '/items/:id',
    rawPath: '/:id',
    confidence: 'high' as const,
    chain: [],
    file: 'app.ts',
    line: 10,
    ownership: 'none' as const,
  };

  it('honors risk override from config', () => {
    const cfg = ConfigSchema.parse({
      entry: ['app.ts'],
      rules: {
        RBAC001: 'low',
      },
    });

    const findings = rbac001.run({
      routes: [dummyRoute],
      config: cfg,
      prismaSchema: new Map(),
    });

    expect(findings.length).toBe(1);
    expect(findings[0]?.risk).toBe('low');
  });

  it('omits finding when rule is configured off', () => {
    const cfg = ConfigSchema.parse({
      entry: ['app.ts'],
      rules: {
        RBAC001: 'off',
      },
    });

    const findings = rbac001.run({
      routes: [dummyRoute],
      config: cfg,
      prismaSchema: new Map(),
    });

    expect(findings).toEqual([]);
  });

  it('resolves effective risk correctly', () => {
    expect(resolveEffectiveRisk('RBAC001', 'high', {})).toBe('high');
    expect(resolveEffectiveRisk('RBAC001', 'high', { RBAC001: 'medium' })).toBe('medium');
    expect(resolveEffectiveRisk('RBAC001', 'high', { RBAC001: 'off' })).toBe('off');
  });
});

describe('Rule precedence: RBAC001 suppresses RBAC002 on same route', () => {
  it('does not emit RBAC002 when a route triggers RBAC001', () => {
    const mutatingUnauthenticatedRoute = {
      method: 'POST' as const,
      path: '/api/data',
      rawPath: '/data',
      confidence: 'high' as const,
      chain: [], // No auth, no role
      file: 'app.ts',
      line: 5,
      ownership: 'none' as const,
    };

    const cfg = ConfigSchema.parse({ entry: ['app.ts'] });
    const findings = runRules({
      routes: [mutatingUnauthenticatedRoute],
      config: cfg,
      prismaSchema: new Map(),
    });

    const ruleIds = findings.map((f) => f.ruleId);
    expect(ruleIds).toContain('RBAC001');
    expect(ruleIds).not.toContain('RBAC002');
  });
});

describe('Fixtures verification for acceptance criteria', () => {
  it('produces 0 findings on clean fixture', async () => {
    const { project, config } = await loadFixture('clean');
    const { routes: composed } = composeMounts(project);
    const schema = parsePrismaSchema('');
    const routeNodes = buildRouteNodes(composed, config, schema);

    const findings = runRules({
      routes: routeNodes,
      config,
      prismaSchema: schema,
    });

    expect(findings).toEqual([]);
  });

  it('produces RBAC001 on missing-auth fixture', async () => {
    const { project, config } = await loadFixture('missing-auth');
    const { routes: composed } = composeMounts(project);
    const schema = parsePrismaSchema('');
    const routeNodes = buildRouteNodes(composed, config, schema);

    const findings = runRules({
      routes: routeNodes,
      config,
      prismaSchema: schema,
    });

    const ruleIds = findings.map((f) => f.ruleId);
    expect(ruleIds).toEqual(['RBAC001']);
    expect(findings[0]?.route?.method).toBe('DELETE');
    expect(findings[0]?.route?.path).toBe('/api/posts/:id');
  });

  it('produces RBAC002 on auth-no-role fixture', async () => {
    const { project, config } = await loadFixture('auth-no-role');
    const { routes: composed } = composeMounts(project);
    const schema = parsePrismaSchema('');
    const routeNodes = buildRouteNodes(composed, config, schema);

    const findings = runRules({
      routes: routeNodes,
      config,
      prismaSchema: schema,
    });

    const ruleIds = findings.map((f) => f.ruleId);
    expect(ruleIds).toEqual(['RBAC002']);
    expect(findings[0]?.route?.method).toBe('DELETE');
    expect(findings[0]?.route?.path).toBe('/api/posts/:id');
  });

  it('produces RBAC005 and RBAC002 on ownership-missing fixture', async () => {
    const { project, config } = await loadFixture('ownership-missing');
    const schema = loadPrismaSchema(config.prismaSchema, config.ownership.ownerFields);
    const { routes: composed } = composeMounts(project);
    const routeNodes = buildRouteNodes(composed, config, schema);

    const findings = runRules({
      routes: routeNodes,
      config,
      prismaSchema: schema,
    });

    const ruleIds = findings.map((f) => f.ruleId).sort();
    expect(ruleIds).toEqual(['RBAC002', 'RBAC005']);
  });

  it('produces RBAC007 on dynamic-mount fixture', async () => {
    const { project, config } = await loadFixture('dynamic-mount');
    const { routes: composed } = composeMounts(project);
    const schema = parsePrismaSchema('');
    const routeNodes = buildRouteNodes(composed, config, schema);

    const findings = runRules({
      routes: routeNodes,
      config,
      prismaSchema: schema,
    });

    const ruleIds = findings.map((f) => f.ruleId);
    expect(ruleIds).toEqual(['RBAC007']);
    expect(findings[0]?.confidence).toBe('low');
  });

  it('registry registers all default rules with valid IDs and descriptions', () => {
    expect(DEFAULT_RULES).toContain(rbac001);
    expect(DEFAULT_RULES).toContain(rbac002);
    expect(DEFAULT_RULES).toContain(rbac005);
    expect(DEFAULT_RULES).toContain(rbac007);
    expect(DEFAULT_RULES.length).toBe(4);
  });
});

