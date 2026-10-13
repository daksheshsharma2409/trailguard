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
  rbac003,
  rbac004,
  rbac005,
  rbac006,
  rbac007,
  rbac008,
  aud001,
  aud002,
  aud003,
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
    expect(DEFAULT_RULES).toContain(rbac003);
    expect(DEFAULT_RULES).toContain(rbac004);
    expect(DEFAULT_RULES).toContain(rbac005);
    expect(DEFAULT_RULES).toContain(rbac006);
    expect(DEFAULT_RULES).toContain(rbac007);
    expect(DEFAULT_RULES).toContain(rbac008);
    expect(DEFAULT_RULES).toContain(aud001);
    expect(DEFAULT_RULES).toContain(aud002);
    expect(DEFAULT_RULES).toContain(aud003);
    expect(DEFAULT_RULES.length).toBe(11);
  });

  describe('Rule RBAC003 (unauthenticated read of private resource)', () => {
    const prismaWithPost = parsePrismaSchema(`
      model Post {
        id Int @id
        title String
        authorId Int
      }
      model PublicInfo {
        id Int @id
        content String
      }
    `, ['authorId']);

    it('emits RBAC003 with confidence high when resource is in config.privateResources', () => {
      const cfg = ConfigSchema.parse({
        entry: ['app.ts'],
        privateResources: ['PublicInfo'],
      });
      const route = {
        method: 'GET' as const,
        path: '/api/info',
        rawPath: '/info',
        confidence: 'high' as const,
        chain: [],
        file: 'app.ts',
        line: 10,
        resource: { model: 'PublicInfo', source: 'config' as const },
        ownership: 'none' as const,
      };

      const findings = rbac003.run({
        routes: [route],
        config: cfg,
        prismaSchema: prismaWithPost,
      });

      expect(findings.length).toBe(1);
      expect(findings[0]?.ruleId).toBe('RBAC003');
      expect(findings[0]?.confidence).toBe('high');
      expect(findings[0]?.risk).toBe('medium');
    });

    it('emits RBAC003 with confidence medium when resource has owner fields in schema', () => {
      const cfg = ConfigSchema.parse({ entry: ['app.ts'] });
      const route = {
        method: 'HEAD' as const,
        path: '/api/posts/:id',
        rawPath: '/:id',
        confidence: 'high' as const,
        chain: [],
        file: 'app.ts',
        line: 12,
        resource: { model: 'Post', source: 'heuristic' as const },
        ownership: 'none' as const,
      };

      const findings = rbac003.run({
        routes: [route],
        config: cfg,
        prismaSchema: prismaWithPost,
      });

      expect(findings.length).toBe(1);
      expect(findings[0]?.confidence).toBe('medium');
      expect(findings[0]?.message).toContain("accesses private resource 'Post' without authentication");
    });

    it('does not emit RBAC003 when route has auth middleware', () => {
      const cfg = ConfigSchema.parse({ entry: ['app.ts'] });
      const route = {
        method: 'GET' as const,
        path: '/api/posts/:id',
        rawPath: '/:id',
        confidence: 'high' as const,
        chain: [
          {
            name: 'authenticate',
            text: 'authenticate',
            args: [],
            class: { kind: 'auth' as const },
            file: 'app.ts',
            line: 5,
          },
        ],
        file: 'app.ts',
        line: 15,
        resource: { model: 'Post', source: 'heuristic' as const },
        ownership: 'none' as const,
      };

      const findings = rbac003.run({
        routes: [route],
        config: cfg,
        prismaSchema: prismaWithPost,
      });

      expect(findings).toEqual([]);
    });

    it('does not emit RBAC003 on non-GET/HEAD routes or unmapped public resources', () => {
      const cfg = ConfigSchema.parse({ entry: ['app.ts'] });
      const postRoute = {
        method: 'POST' as const,
        path: '/api/posts',
        rawPath: '/',
        confidence: 'high' as const,
        chain: [],
        file: 'app.ts',
        line: 20,
        resource: { model: 'Post', source: 'heuristic' as const },
        ownership: 'none' as const,
      };
      const publicRoute = {
        method: 'GET' as const,
        path: '/api/info',
        rawPath: '/info',
        confidence: 'high' as const,
        chain: [],
        file: 'app.ts',
        line: 25,
        resource: { model: 'PublicInfo', source: 'heuristic' as const },
        ownership: 'none' as const,
      };

      expect(rbac003.run({ routes: [postRoute, publicRoute], config: cfg, prismaSchema: prismaWithPost })).toEqual([]);
    });
  });

  describe('Rule RBAC004 (unknown role reference)', () => {
    it('emits RBAC004 when role middleware references a role outside roles.known', () => {
      const cfg = ConfigSchema.parse({
        entry: ['app.ts'],
        roles: {
          known: ['ADMIN', 'USER'],
        },
      });

      const route = {
        method: 'DELETE' as const,
        path: '/api/admin',
        rawPath: '/admin',
        confidence: 'high' as const,
        chain: [
          {
            name: 'requireRole',
            text: "requireRole('SUPERADMIN')",
            args: ['SUPERADMIN'],
            class: { kind: 'role' as const, value: 'SUPERADMIN' },
            file: 'app.ts',
            line: 10,
          },
        ],
        file: 'app.ts',
        line: 12,
        ownership: 'none' as const,
      };

      const findings = rbac004.run({
        routes: [route],
        config: cfg,
        prismaSchema: parsePrismaSchema(''),
      });

      expect(findings.length).toBe(1);
      expect(findings[0]?.ruleId).toBe('RBAC004');
      expect(findings[0]?.risk).toBe('medium');
      expect(findings[0]?.confidence).toBe('high');
      expect(findings[0]?.message).toContain("references role 'SUPERADMIN' which is not in configured known roles (ADMIN, USER)");
    });

    it('does not emit RBAC004 if role is known or roles.known is empty', () => {
      const cfg = ConfigSchema.parse({
        entry: ['app.ts'],
        roles: { known: ['ADMIN'] },
      });
      const validRoute = {
        method: 'GET' as const,
        path: '/api/admin',
        rawPath: '/admin',
        confidence: 'high' as const,
        chain: [
          {
            name: 'requireRole',
            text: "requireRole('ADMIN')",
            args: ['ADMIN'],
            class: { kind: 'role' as const, value: 'ADMIN' },
            file: 'app.ts',
            line: 10,
          },
        ],
        file: 'app.ts',
        line: 12,
        ownership: 'none' as const,
      };

      expect(rbac004.run({ routes: [validRoute], config: cfg, prismaSchema: parsePrismaSchema('') })).toEqual([]);

      const emptyKnownCfg = ConfigSchema.parse({ entry: ['app.ts'] });
      expect(rbac004.run({ routes: [validRoute], config: emptyKnownCfg, prismaSchema: parsePrismaSchema('') })).toEqual([]);
    });

    it('deduplicates multiple unknown role references on the same route', () => {
      const cfg = ConfigSchema.parse({
        entry: ['app.ts'],
        roles: { known: ['ADMIN'] },
      });
      const route = {
        method: 'POST' as const,
        path: '/api/settings',
        rawPath: '/settings',
        confidence: 'high' as const,
        chain: [
          {
            name: 'requireRole',
            text: "requireRole('GUEST')",
            args: ['GUEST'],
            class: { kind: 'role' as const, value: 'GUEST' },
            file: 'app.ts',
            line: 5,
          },
          {
            name: 'requireRole',
            text: "requireRole('GUEST')",
            args: ['GUEST'],
            class: { kind: 'role' as const, value: 'GUEST' },
            file: 'app.ts',
            line: 6,
          },
        ],
        file: 'app.ts',
        line: 10,
        ownership: 'none' as const,
      };

      const findings = rbac004.run({ routes: [route], config: cfg, prismaSchema: parsePrismaSchema('') });
      expect(findings.length).toBe(1);
    });
  });

  describe('Rule RBAC006 (unrecognized middleware)', () => {
    it('produces RBAC006 on unknown-mw fixture and ignores neutral middleware', async () => {
      const { project, config } = await loadFixture('unknown-mw');
      const { routes: composed } = composeMounts(project);
      const schema = parsePrismaSchema('');
      const routeNodes = buildRouteNodes(composed, config, schema);

      const findings = rbac006.run({
        routes: routeNodes,
        config,
        prismaSchema: schema,
      });

      expect(findings.length).toBe(1);
      expect(findings[0]?.ruleId).toBe('RBAC006');
      expect(findings[0]?.risk).toBe('low');
      expect(findings[0]?.confidence).toBe('medium');
      expect(findings[0]?.message).toContain('customTelemetry');
      expect(findings[0]?.message).not.toContain('express.json');
    });

    it('does not emit RBAC006 when auth or role middleware is present in chain', () => {
      const cfg = ConfigSchema.parse({ entry: ['app.ts'] });
      const route = {
        method: 'GET' as const,
        path: '/api/data',
        rawPath: '/data',
        confidence: 'high' as const,
        chain: [
          {
            name: 'express.json',
            text: 'express.json()',
            args: [],
            class: { kind: 'neutral' as const },
            file: 'app.ts',
            line: 2,
          },
          {
            name: 'authenticate',
            text: 'authenticate',
            args: [],
            class: { kind: 'auth' as const },
            file: 'app.ts',
            line: 3,
          },
          {
            name: 'customTracker',
            text: 'customTracker',
            args: [],
            class: { kind: 'unknown' as const },
            file: 'app.ts',
            line: 4,
          },
        ],
        file: 'app.ts',
        line: 10,
        ownership: 'none' as const,
      };

      const findings = rbac006.run({ routes: [route], config: cfg, prismaSchema: parsePrismaSchema('') });
      expect(findings).toEqual([]);
    });

    it('does not emit RBAC006 when chain is empty or contains only neutral middleware', () => {
      const cfg = ConfigSchema.parse({ entry: ['app.ts'] });
      const neutralRoute = {
        method: 'GET' as const,
        path: '/public',
        rawPath: '/public',
        confidence: 'high' as const,
        chain: [
          {
            name: 'cors',
            text: 'cors()',
            args: [],
            class: { kind: 'neutral' as const },
            file: 'app.ts',
            line: 2,
          },
        ],
        file: 'app.ts',
        line: 5,
        ownership: 'none' as const,
      };

      expect(rbac006.run({ routes: [neutralRoute], config: cfg, prismaSchema: parsePrismaSchema('') })).toEqual([]);
    });
  });

  describe('Rule RBAC008 (orphan router)', () => {
    it('emits RBAC008 for routes originating from orphan routers', () => {
      const cfg = ConfigSchema.parse({ entry: ['app.ts'] });
      const orphanRoute = {
        method: 'GET' as const,
        path: '/internal/stats',
        rawPath: '/stats',
        confidence: 'high' as const,
        chain: [],
        file: 'src/routes/orphan.ts',
        line: 15,
        orphan: true,
        ownership: 'none' as const,
      };

      const mountedRoute = {
        method: 'GET' as const,
        path: '/api/health',
        rawPath: '/health',
        confidence: 'high' as const,
        chain: [],
        file: 'src/routes/health.ts',
        line: 5,
        orphan: false,
        ownership: 'none' as const,
      };

      const findings = rbac008.run({
        routes: [orphanRoute, mountedRoute],
        config: cfg,
        prismaSchema: parsePrismaSchema(''),
      });

      expect(findings.length).toBe(1);
      expect(findings[0]?.ruleId).toBe('RBAC008');
      expect(findings[0]?.risk).toBe('low');
      expect(findings[0]?.confidence).toBe('high');
      expect(findings[0]?.file).toBe('src/routes/orphan.ts');
      expect(findings[0]?.route?.path).toBe('/internal/stats');
      expect(findings[0]?.message).toContain('orphan router');
    });
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

    it('resolves guard array variable and options variable references in AUD002', () => {
      const code = `
        import express from 'express';
        const app = express();
        const authenticate = (req: any, res: any, next: any) => next();
        const requireRole = (role: string) => (req: any, res: any, next: any) => next();
        const auditRouter = (options?: any) => express.Router();

        // 1. Guard variable
        const myGuards = [authenticate, requireRole('ADMIN')];
        app.use('/audit1', auditRouter({ guard: myGuards }));

        // 2. Options variable
        const myOpts = { guard: [authenticate, requireRole('ADMIN')] };
        app.use('/audit2', auditRouter(myOpts));

        // 3. Prior inline middleware on same use call
        app.use('/audit3', authenticate, requireRole('ADMIN'), auditRouter());

        // 4. Prior middleware matching prefix
        app.use('/admin', authenticate, requireRole('ADMIN'));
        app.use('/admin/audit4', auditRouter());
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

    it('covers AUD001 configuration branches (empty models, risk off, project fallback)', () => {
      const cfgEmpty = ConfigSchema.parse({
        entry: ['app.ts'],
        audit: { models: [] },
      });
      expect(aud001.run({ routes: [], config: cfgEmpty, prismaSchema: parsePrismaSchema('') })).toEqual([]);

      const cfgOff = ConfigSchema.parse({
        entry: ['app.ts'],
        audit: { models: ['Student'] },
        rules: { AUD001: 'off' },
      });
      expect(aud001.run({ routes: [], config: cfgOff, prismaSchema: parsePrismaSchema('') })).toEqual([]);

      // Project fallback when prismaWrites is not supplied
      const cfgActive = ConfigSchema.parse({
        entry: ['app.ts'],
        audit: { models: ['Student'] },
      });
      const project = new Project({ useInMemoryFileSystem: true });
      project.createSourceFile('app.ts', 'prisma.student.delete({ where: { id: 1 } });');
      const findings = aud001.run({
        routes: [],
        config: cfgActive,
        prismaSchema: parsePrismaSchema(''),
        project,
      });
      expect(findings.length).toBe(1);

      // Neither prismaWrites nor project supplied
      expect(
        aud001.run({
          routes: [],
          config: cfgActive,
          prismaSchema: parsePrismaSchema(''),
        }),
      ).toEqual([]);
    });
  });

  describe('Rule AUD003 (raw SQL writes)', () => {
    it('fixture raw-sql produces AUD003 MEDIUM findings with route info and method', async () => {
      const { project, config } = await loadFixture('raw-sql');
      const { routes: composed } = composeMounts(project);
      const schema = parsePrismaSchema('');
      const routeNodes = buildRouteNodes(composed, config, schema);
      const prismaWrites = findPrismaWrites(project, config, routeNodes);

      const findings = aud003.run({
        routes: routeNodes,
        config,
        prismaSchema: schema,
        prismaWrites,
        project,
      });

      expect(findings.length).toBe(2);
      for (const finding of findings) {
        expect(finding.ruleId).toBe('AUD003');
        expect(finding.risk).toBe('medium');
        expect(finding.confidence).toBe('medium');
        expect(finding.message).toContain('Raw SQL write');
        expect(finding.fingerprint).toHaveLength(64);
      }

      const methods = findings.map((f) => f.message);
      expect(methods.some((m) => m.includes('$executeRaw'))).toBe(true);
      expect(methods.some((m) => m.includes('$executeRawUnsafe'))).toBe(true);
    });

    it('produces 0 findings when audit.models is empty', async () => {
      const { project, config } = await loadFixture('raw-sql');
      const emptyModelsConfig = {
        ...config,
        audit: {
          ...config.audit,
          models: [],
        },
      };

      const findings = aud003.run({
        routes: [],
        config: emptyModelsConfig,
        prismaSchema: parsePrismaSchema(''),
        project,
      });

      expect(findings).toEqual([]);
    });

    it('produces 0 findings when AUD003 is turned off', async () => {
      const { project, config } = await loadFixture('raw-sql');
      const disabledRuleConfig = {
        ...config,
        rules: {
          ...config.rules,
          AUD003: 'off' as const,
        },
      };

      const findings = aud003.run({
        routes: [],
        config: disabledRuleConfig,
        prismaSchema: parsePrismaSchema(''),
        project,
      });

      expect(findings).toEqual([]);
    });

    it('guarantees AUD003 fingerprint stability across line shifts', () => {
      const codeA = `
        import express from 'express';
        const prisma: any = {};
        prisma.$executeRaw\`UPDATE Student SET name = 'X'\`;
      `;

      const codeB = `
        // Added comment
        // Line 2
        // Line 3
        import express from 'express';
        const dummy = 123;
        const prisma: any = {};
        prisma.$executeRaw\`UPDATE Student SET name = 'X'\`;
      `;

      const cfg = ConfigSchema.parse({
        entry: ['app.ts'],
        audit: { models: ['Student'] },
      });

      const pA = new Project({ useInMemoryFileSystem: true });
      pA.createSourceFile('app.ts', codeA);
      const findingsA = aud003.run({
        routes: [],
        config: cfg,
        prismaSchema: parsePrismaSchema(''),
        project: pA,
      });

      const pB = new Project({ useInMemoryFileSystem: true });
      pB.createSourceFile('app.ts', codeB);
      const findingsB = aud003.run({
        routes: [],
        config: cfg,
        prismaSchema: parsePrismaSchema(''),
        project: pB,
      });

      expect(findingsA.length).toBe(1);
      expect(findingsB.length).toBe(1);
      expect(findingsA[0]?.fingerprint).toBe(findingsB[0]?.fingerprint);
    });

    it('returns empty array when neither prismaWrites nor project is available', () => {
      const cfg = ConfigSchema.parse({
        entry: ['app.ts'],
        audit: { models: ['Student'] },
      });

      expect(
        aud003.run({
          routes: [],
          config: cfg,
          prismaSchema: parsePrismaSchema(''),
        }),
      ).toEqual([]);
    });
  });
});


