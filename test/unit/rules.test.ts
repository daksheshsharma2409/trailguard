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
  aud001,
  aud002,
} from '../../src/scan/rules/index.js';
import { findPrismaWrites } from '../../src/scan/prisma-writes.js';
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
    expect(DEFAULT_RULES).toContain(aud001);
    expect(DEFAULT_RULES).toContain(aud002);
    expect(DEFAULT_RULES.length).toBe(6);
  });

  describe('Rule AUD001 (bypass audit client)', () => {
    it('fixture bypass-audit-client produces exactly one AUD001 HIGH with file/line/model.op in message and route info', async () => {
      const { project, config } = await loadFixture('bypass-audit-client');
      const { routes: composed } = composeMounts(project);
      const schema = parsePrismaSchema('');
      const routeNodes = buildRouteNodes(composed, config, schema);
      const prismaWrites = findPrismaWrites(project, config, routeNodes);

      const findings = aud001.run({
        routes: routeNodes,
        config,
        prismaSchema: schema,
        prismaWrites,
        project,
      });

      // Exactly one AUD001
      expect(findings.length).toBe(1);
      const finding = findings[0]!;
      expect(finding.ruleId).toBe('AUD001');
      expect(finding.risk).toBe('high');
      expect(finding.confidence).toBe('high');

      // Message contains file, line, and model.op
      expect(finding.message).toContain('Student.update');
      expect(finding.message).toContain(String(finding.line));
      expect(finding.message).toContain('src/app.ts');

      // Includes route info when inside a handler
      expect(finding.route).toBeDefined();
      expect(finding.route?.method).toBe('PATCH');
      expect(finding.route?.path).toBe('/api/students/:id');

      // Resource is recorded
      expect(finding.resource?.model).toBe('Student');
    });

    it('fingerprint is stable across line shifts', () => {
      const codeA = `
        const prisma: any = {};
        async function updateFn() {
          await prisma.student.update({ where: { id: 1 }, data: { name: 'Bob' } });
        }
      `;

      const codeB = `
        // Added comment lines
        // Another comment
        // Line 3
        // Line 4
        // Line 5
        const unused = 123;
        const prisma: any = {};
        async function updateFn() {
          await prisma.student.update({ where: { id: 1 }, data: { name: 'Bob' } });
        }
      `;

      const cfg = ConfigSchema.parse({
        entry: ['app.ts'],
        audit: { models: ['Student'] },
      });

      const projectA = new Project({ useInMemoryFileSystem: true });
      projectA.createSourceFile('app.ts', codeA);
      const writesA = findPrismaWrites(projectA, cfg);
      const findingsA = aud001.run({
        routes: [],
        config: cfg,
        prismaSchema: parsePrismaSchema(''),
        prismaWrites: writesA,
      });

      const projectB = new Project({ useInMemoryFileSystem: true });
      projectB.createSourceFile('app.ts', codeB);
      const writesB = findPrismaWrites(projectB, cfg);
      const findingsB = aud001.run({
        routes: [],
        config: cfg,
        prismaSchema: parsePrismaSchema(''),
        prismaWrites: writesB,
      });

      expect(findingsA.length).toBe(1);
      expect(findingsB.length).toBe(1);

      // Line numbers MUST differ
      expect(findingsA[0]?.line).not.toBe(findingsB[0]?.line);

      // Fingerprints MUST be strictly identical
      expect(findingsA[0]?.fingerprint).toBe(findingsB[0]?.fingerprint);
      expect(findingsA[0]?.fingerprint.length).toBe(64);
    });
  });

  describe('Rule AUD002 (audit router guarded)', () => {
    it('produces exactly one AUD002 HIGH on audit-router-unguarded fixture', async () => {
      const { project, config } = await loadFixture('audit-router-unguarded');
      const { routes: composed } = composeMounts(project);
      const schema = parsePrismaSchema('');
      const routeNodes = buildRouteNodes(composed, config, schema);

      const findings = aud002.run({
        routes: routeNodes,
        config,
        prismaSchema: schema,
        project,
      });

      expect(findings.length).toBe(1);
      const finding = findings[0]!;
      expect(finding.ruleId).toBe('AUD002');
      expect(finding.risk).toBe('high');
      expect(finding.route?.path).toBe('/audit');
      expect(finding.message).toContain('/audit');
    });

    it('produces 0 findings on audit-router-guarded fixture', async () => {
      const { project, config } = await loadFixture('audit-router-guarded');
      const { routes: composed } = composeMounts(project);
      const schema = parsePrismaSchema('');
      const routeNodes = buildRouteNodes(composed, config, schema);

      const findings = aud002.run({
        routes: routeNodes,
        config,
        prismaSchema: schema,
        project,
      });

      expect(findings).toEqual([]);
    });

    it('counts auditRouter({ guard }) option as guarded when containing auth and role', () => {
      const code = `
        import express from 'express';
        const app = express();
        const authenticate = (req: any, res: any, next: any) => next();
        const requireRole = (role: string) => (req: any, res: any, next: any) => next();
        const auditRouter = (options?: any) => express.Router();

        // Guard provided only via options
        app.use('/audit', auditRouter({
          guard: [authenticate, requireRole('ADMIN')],
        }));
      `;

      const cfg = ConfigSchema.parse({
        entry: ['app.ts'],
        auth: { middleware: ['authenticate'] },
        roles: { middleware: ['requireRole'], known: ['ADMIN'] },
        audit: { routerNames: ['auditRouter'] },
      });

      const project = new Project({ useInMemoryFileSystem: true });
      project.createSourceFile('app.ts', code);

      const findings = aud002.run({
        routes: [],
        config: cfg,
        prismaSchema: parsePrismaSchema(''),
        project,
      });

      expect(findings).toEqual([]);
    });

    it('flags auditRouter({ guard }) when guard only has auth but no role', () => {
      const code = `
        import express from 'express';
        const app = express();
        const authenticate = (req: any, res: any, next: any) => next();
        const auditRouter = (options?: any) => express.Router();

        app.use('/audit', auditRouter({
          guard: authenticate,
        }));
      `;

      const cfg = ConfigSchema.parse({
        entry: ['app.ts'],
        auth: { middleware: ['authenticate'] },
        roles: { middleware: ['requireRole'], known: ['ADMIN'] },
        audit: { routerNames: ['auditRouter'] },
      });

      const project = new Project({ useInMemoryFileSystem: true });
      project.createSourceFile('app.ts', code);

      const findings = aud002.run({
        routes: [],
        config: cfg,
        prismaSchema: parsePrismaSchema(''),
        project,
      });

      expect(findings.length).toBe(1);
      expect(findings[0]?.ruleId).toBe('AUD002');
    });

    it('resolves variable reference holding auditRouter() and detects unguarded mount', () => {
      const code = `
        import express from 'express';
        const app = express();
        const auditRouter = (options?: any) => express.Router();

        const audit = auditRouter();
        app.use('/api/audit', audit);
      `;

      const cfg = ConfigSchema.parse({
        entry: ['app.ts'],
        audit: { routerNames: ['auditRouter'] },
      });

      const project = new Project({ useInMemoryFileSystem: true });
      project.createSourceFile('app.ts', code);

      const findings = aud002.run({
        routes: [],
        config: cfg,
        prismaSchema: parsePrismaSchema(''),
        project,
      });

      expect(findings.length).toBe(1);
      expect(findings[0]?.ruleId).toBe('AUD002');
      expect(findings[0]?.route?.path).toBe('/api/audit');
    });

    it('honors app-level auth and role middleware preceding the mount', () => {
      const code = `
        import express from 'express';
        const app = express();
        const authenticate = (req: any, res: any, next: any) => next();
        const requireRole = (role: string) => (req: any, res: any, next: any) => next();
        const auditRouter = (options?: any) => express.Router();

        app.use(authenticate);
        app.use(requireRole('ADMIN'));
        app.use('/audit', auditRouter());
      `;

      const cfg = ConfigSchema.parse({
        entry: ['app.ts'],
        auth: { middleware: ['authenticate'] },
        roles: { middleware: ['requireRole'], known: ['ADMIN'] },
        audit: { routerNames: ['auditRouter'] },
      });

      const project = new Project({ useInMemoryFileSystem: true });
      project.createSourceFile('app.ts', code);

      const findings = aud002.run({
        routes: [],
        config: cfg,
        prismaSchema: parsePrismaSchema(''),
        project,
      });

      expect(findings).toEqual([]);
    });
  });
});


