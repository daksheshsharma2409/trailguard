/**
 * Unit tests for Prisma write discovery and raw SQL detection.
 *
 * @see context.md §6.8
 */

import { describe, it, expect } from 'vitest';
import { Project } from 'ts-morph';
import { ConfigSchema } from '../../src/config/schema.js';
import { findPrismaWrites } from '../../src/scan/prisma-writes.js';
import { composeMounts } from '../../src/scan/mounts.js';
import { buildRouteNodes } from '../../src/scan/findings.js';
import { parsePrismaSchema } from '../../src/scan/prisma-schema.js';
import { loadFixture } from '../helpers/fixture.js';

describe('Prisma write discovery', () => {
  const baseConfig = ConfigSchema.parse({
    entry: ['app.ts'],
    audit: {
      models: ['Student'],
      clientNames: ['auditClient', 'audited', 'db'],
    },
  });

  it('detects prisma.student.update() as raw write', () => {
    const code = `
      import express from 'express';
      const app = express();
      const prisma: any = {};
      app.post('/students', async (req, res) => {
        await prisma.student.update({ where: { id: 1 }, data: { name: 'Alice' } });
        res.json({ ok: true });
      });
    `;

    const project = new Project({ useInMemoryFileSystem: true });
    project.createSourceFile('app.ts', code);

    const { routes: composed } = composeMounts(project);
    const schema = parsePrismaSchema('');
    const routeNodes = buildRouteNodes(composed, baseConfig, schema);

    const result = findPrismaWrites(project, baseConfig, routeNodes);

    expect(result.modelWrites.length).toBe(1);
    const write = result.modelWrites[0]!;
    expect(write.model).toBe('Student');
    expect(write.op).toBe('update');
    expect(write.receiver).toBe('prisma');
    expect(write.routeNode?.path).toBe('/students');
    expect(write.routeNode?.method).toBe('POST');
  });

  it('does not flag auditClient.student.update()', () => {
    const code = `
      import express from 'express';
      const app = express();
      const auditClient: any = {};
      app.post('/students', async (req, res) => {
        await auditClient.student.update({ where: { id: 1 }, data: { name: 'Alice' } });
        res.json({ ok: true });
      });
    `;

    const project = new Project({ useInMemoryFileSystem: true });
    project.createSourceFile('app.ts', code);

    const result = findPrismaWrites(project, baseConfig);

    expect(result.modelWrites.length).toBe(0);
    expect(result.writes.length).toBe(0);
  });

  it('detects tx.student.delete() inside $transaction(async tx => …)', () => {
    const code = `
      import express from 'express';
      const app = express();
      const prisma: any = {};
      app.delete('/students/:id', async (req, res) => {
        await prisma.$transaction(async (tx: any) => {
          await tx.student.delete({ where: { id: req.params.id } });
        });
        res.json({ ok: true });
      });
    `;

    const project = new Project({ useInMemoryFileSystem: true });
    project.createSourceFile('app.ts', code);

    const { routes: composed } = composeMounts(project);
    const schema = parsePrismaSchema('');
    const routeNodes = buildRouteNodes(composed, baseConfig, schema);

    const result = findPrismaWrites(project, baseConfig, routeNodes);

    expect(result.modelWrites.length).toBe(1);
    const write = result.modelWrites[0]!;
    expect(write.model).toBe('Student');
    expect(write.op).toBe('delete');
    expect(write.receiver).toBe('tx');
    expect(write.routeNode?.path).toBe('/students/:id');
  });

  it('ignores non-audited models', () => {
    const code = `
      import express from 'express';
      const app = express();
      const prisma: any = {};
      app.post('/courses', async (req, res) => {
        await prisma.course.update({ where: { id: 1 }, data: { title: 'Math' } });
        await prisma.teacher.create({ data: { name: 'Bob' } });
        res.json({ ok: true });
      });
    `;

    const project = new Project({ useInMemoryFileSystem: true });
    project.createSourceFile('app.ts', code);

    // Only 'Student' is configured in baseConfig.audit.models
    const result = findPrismaWrites(project, baseConfig);

    expect(result.modelWrites.length).toBe(0);
    expect(result.writes.length).toBe(0);
  });

  it('detects all standard Prisma write ops: create, createMany, update, updateMany, upsert, delete, deleteMany', () => {
    const code = `
      const prisma: any = {};
      async function doWrites() {
        await prisma.student.create({ data: {} });
        await prisma.student.createMany({ data: [] });
        await prisma.student.update({ where: {}, data: {} });
        await prisma.student.updateMany({ where: {}, data: {} });
        await prisma.student.upsert({ where: {}, create: {}, update: {} });
        await prisma.student.delete({ where: {} });
        await prisma.student.deleteMany({ where: {} });
      }
    `;

    const project = new Project({ useInMemoryFileSystem: true });
    project.createSourceFile('app.ts', code);

    const result = findPrismaWrites(project, baseConfig);

    expect(result.modelWrites.length).toBe(7);
    const ops = result.modelWrites.map((w) => w.op);
    expect(ops).toEqual([
      'create',
      'createMany',
      'update',
      'updateMany',
      'upsert',
      'delete',
      'deleteMany',
    ]);
    expect(result.modelWrites.every((w) => w.enclosingFunction === 'doWrites')).toBe(true);
  });

  it('ignores Prisma read operations', () => {
    const code = `
      const prisma: any = {};
      async function doReads() {
        await prisma.student.findUnique({ where: { id: 1 } });
        await prisma.student.findMany();
        await prisma.student.findFirst();
        await prisma.student.count();
        await prisma.student.aggregate({});
        await prisma.student.groupBy({});
      }
    `;

    const project = new Project({ useInMemoryFileSystem: true });
    project.createSourceFile('app.ts', code);

    const result = findPrismaWrites(project, baseConfig);

    expect(result.modelWrites.length).toBe(0);
  });
});

describe('Raw SQL write detection', () => {
  const config = ConfigSchema.parse({
    entry: ['app.ts'],
    audit: {
      models: ['Student'],
    },
  });

  it('detects UPDATE and DELETE in tagged templates ($executeRaw and $queryRaw)', () => {
    const code = `
      const prisma: any = {};
      async function rawOps() {
        await prisma.$executeRaw\`UPDATE Student SET name = 'Alice' WHERE id = 1\`;
        await prisma.$queryRaw\`DELETE FROM Student WHERE id = 2\`;
        await prisma.$queryRaw\`SELECT * FROM Student\`; // read-only, should be ignored
      }
    `;

    const project = new Project({ useInMemoryFileSystem: true });
    project.createSourceFile('app.ts', code);

    const result = findPrismaWrites(project, config);

    expect(result.rawSqlWrites.length).toBe(2);
    expect(result.rawSqlWrites[0]?.method).toBe('$executeRaw');
    expect(result.rawSqlWrites[0]?.sql).toContain('UPDATE');
    expect(result.rawSqlWrites[1]?.method).toBe('$queryRaw');
    expect(result.rawSqlWrites[1]?.sql).toContain('DELETE');
  });

  it('detects UPDATE and DELETE in string arguments ($executeRawUnsafe and $queryRawUnsafe)', () => {
    const code = `
      const prisma: any = {};
      async function unsafeOps() {
        await prisma.$executeRawUnsafe("UPDATE Student SET status = 'ACTIVE'");
        await prisma.$queryRawUnsafe('DELETE FROM Student WHERE graduated = true');
        await prisma.$queryRawUnsafe('SELECT count(*) FROM Student'); // read-only, should be ignored
      }
    `;

    const project = new Project({ useInMemoryFileSystem: true });
    project.createSourceFile('app.ts', code);

    const result = findPrismaWrites(project, config);

    expect(result.rawSqlWrites.length).toBe(2);
    expect(result.rawSqlWrites[0]?.method).toBe('$executeRawUnsafe');
    expect(result.rawSqlWrites[0]?.sql).toContain('UPDATE');
    expect(result.rawSqlWrites[1]?.method).toBe('$queryRawUnsafe');
    expect(result.rawSqlWrites[1]?.sql).toContain('DELETE');
  });

  it('detects mutating keywords via variable declarations passed to raw methods', () => {
    const code = `
      const prisma: any = {};
      async function varOp() {
        const query = 'TRUNCATE TABLE logs';
        await prisma.$executeRawUnsafe(query);
      }
    `;

    const project = new Project({ useInMemoryFileSystem: true });
    project.createSourceFile('app.ts', code);

    const result = findPrismaWrites(project, config);

    expect(result.rawSqlWrites.length).toBe(1);
    expect(result.rawSqlWrites[0]?.sql).toContain('TRUNCATE TABLE logs');
  });
});

describe('Fixtures integration for T4.1', () => {
  it('correctly scans bypass-audit-client fixture', async () => {
    const { project, config } = await loadFixture('bypass-audit-client');
    const { routes: composed } = composeMounts(project);
    const schema = parsePrismaSchema('');
    const routeNodes = buildRouteNodes(composed, config, schema);

    const result = findPrismaWrites(project, config, routeNodes);

    // Exactly 1 direct raw model write on Student: prisma.student.update in PATCH /api/students/:id
    expect(result.modelWrites.length).toBe(1);
    const write = result.modelWrites[0]!;
    expect(write.model).toBe('Student');
    expect(write.op).toBe('update');
    expect(write.receiver).toBe('prisma');
    expect(write.routeNode?.method).toBe('PATCH');
    expect(write.routeNode?.path).toBe('/api/students/:id');
  });

  it('correctly scans raw-sql fixture', async () => {
    const { project, config } = await loadFixture('raw-sql');
    const { routes: composed } = composeMounts(project);
    const schema = parsePrismaSchema('');
    const routeNodes = buildRouteNodes(composed, config, schema);

    const result = findPrismaWrites(project, config, routeNodes);

    // 2 raw SQL writes (UPDATE in /api/raw-update, DELETE in /api/raw-delete)
    expect(result.rawSqlWrites.length).toBe(2);
    const methods = result.rawSqlWrites.map((w) => w.method);
    expect(methods).toContain('$executeRaw');
    expect(methods).toContain('$executeRawUnsafe');
  });

  it('handles target variations (SourceFile and SourceFile[]) and various enclosing function kinds', () => {
    const code = `
      class Controller {
        classMethod() {
          prisma.student.create({ data: {} });
        }
      }
      const namedExpr = function myNamedFn() {
        prisma.student.delete({ where: { id: 1 } });
      };
      const obj = {
        propFn: function() {
          prisma.student.update({ where: { id: 1 }, data: {} });
        },
        propArrow: () => {
          prisma.student.upsert({ where: { id: 1 }, create: {}, update: {} });
        },
      };
      // Dotted audited client receiver
      req.app.locals.auditClient.student.update({ where: { id: 1 }, data: {} });
    `;

    const project = new Project({ useInMemoryFileSystem: true });
    const sf = project.createSourceFile('handlers.ts', code);

    const dummyRoute = {
      method: 'POST' as const,
      path: '/test',
      rawPath: '/test',
      confidence: 'high' as const,
      chain: [],
      file: sf.getFilePath(),
      line: 1,
      handler: {
        name: 'Controller.classMethod',
        file: sf.getFilePath(),
        line: 3,
      },
      ownership: 'none' as const,
    };

    const localConfig = ConfigSchema.parse({
      entry: ['app.ts'],
      audit: {
        models: ['Student'],
        clientNames: ['auditClient'],
      },
    });

    // Test with single SourceFile and RouteNode matching
    const resSingle = findPrismaWrites(sf, localConfig, [dummyRoute]);
    expect(resSingle.modelWrites.length).toBe(4);
    const classWrite = resSingle.modelWrites.find((w) => w.op === 'create');
    expect(classWrite?.enclosingFunction).toBe('classMethod');
    expect(classWrite?.routeNode?.path).toBe('/test');

    const fnWrite = resSingle.modelWrites.find((w) => w.op === 'delete');
    expect(fnWrite?.enclosingFunction).toBe('myNamedFn');

    const propFnWrite = resSingle.modelWrites.find((w) => w.op === 'update');
    expect(propFnWrite?.enclosingFunction).toBe('propFn');

    const propArrowWrite = resSingle.modelWrites.find((w) => w.op === 'upsert');
    expect(propArrowWrite?.enclosingFunction).toBe('propArrow');

    // Test with SourceFile[]
    const resArray = findPrismaWrites([sf], localConfig);
    expect(resArray.modelWrites.length).toBe(4);
  });
});
