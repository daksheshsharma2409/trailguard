/**
 * Unit tests for RBAC access matrix derivation.
 *
 * Tests verb->action mapping, anonymous access, any-authenticated,
 * role union, ownership flag ('own'), and uncertainty propagation.
 *
 * @see context.md §6.9
 */

import { describe, it, expect } from 'vitest';
import {
  deriveMatrix,
  methodToActions,
  MATRIX_DISCLAIMER,
  MATRIX_ACTIONS,
} from '../../src/scan/matrix.js';
import type { RouteNode } from '../../src/core/types.js';
import { loadFixture } from '../helpers/fixture.js';
import { composeMounts } from '../../src/scan/mounts.js';
import { loadPrismaSchema, parsePrismaSchema } from '../../src/scan/prisma-schema.js';
import { buildRouteNodes } from '../../src/scan/findings.js';

describe('methodToActions mapping', () => {
  it('maps GET and HEAD to read', () => {
    expect(methodToActions('GET')).toEqual(['read']);
    expect(methodToActions('get')).toEqual(['read']);
    expect(methodToActions('HEAD')).toEqual(['read']);
    expect(methodToActions('head')).toEqual(['read']);
  });

  it('maps POST to create', () => {
    expect(methodToActions('POST')).toEqual(['create']);
    expect(methodToActions('post')).toEqual(['create']);
  });

  it('maps PUT and PATCH to update', () => {
    expect(methodToActions('PUT')).toEqual(['update']);
    expect(methodToActions('put')).toEqual(['update']);
    expect(methodToActions('PATCH')).toEqual(['update']);
    expect(methodToActions('patch')).toEqual(['update']);
  });

  it('maps DELETE to delete', () => {
    expect(methodToActions('DELETE')).toEqual(['delete']);
    expect(methodToActions('delete')).toEqual(['delete']);
  });

  it('maps all to create, read, update, delete', () => {
    expect(methodToActions('all')).toEqual(['create', 'read', 'update', 'delete']);
    expect(methodToActions('ALL')).toEqual(['create', 'read', 'update', 'delete']);
  });

  it('ignores OPTIONS and unrecognised verbs', () => {
    expect(methodToActions('OPTIONS')).toEqual([]);
    expect(methodToActions('options')).toEqual([]);
    expect(methodToActions('TRACE')).toEqual([]);
  });

  it('defines the required matrix disclaimer', () => {
    expect(MATRIX_DISCLAIMER).toBe(
      'This matrix is derived statically from middleware declarations. It does not execute your handlers.',
    );
    expect(MATRIX_ACTIONS).toEqual(['create', 'read', 'update', 'delete']);
  });
});

describe('deriveMatrix access policies and cell union', () => {
  function makeRoute(overrides: Partial<RouteNode>): RouteNode {
    return {
      method: 'post',
      path: '/api/posts',
      rawPath: '/posts',
      confidence: 'high',
      chain: [],
      file: 'src/routes.ts',
      line: 10,
      resource: {
        model: 'Post',
        source: 'heuristic',
      },
      ownership: 'none',
      ...overrides,
    };
  }

  it('marks anonymous: true when contributing route has no auth middleware', () => {
    const unauthRoute = makeRoute({
      method: 'get',
      chain: [], // no auth
    });

    const matrix = deriveMatrix([unauthRoute], ['Post']);
    const readCell = matrix.find((c) => c.resource === 'Post' && c.action === 'read');

    expect(readCell).toBeDefined();
    expect(readCell?.anonymous).toBe(true);
    expect(readCell?.anyAuthenticated).toBe(false);
  });

  it('marks anonymous: false and anyAuthenticated: true when route has auth but no role', () => {
    const authRoute = makeRoute({
      method: 'post',
      chain: [
        {
          text: 'authenticate',
          name: 'authenticate',
          args: [],
          class: { kind: 'auth' },
          file: 'src/auth.ts',
          line: 1,
        },
      ],
    });

    const matrix = deriveMatrix([authRoute], ['Post']);
    const createCell = matrix.find((c) => c.resource === 'Post' && c.action === 'create');

    expect(createCell).toBeDefined();
    expect(createCell?.anonymous).toBe(false);
    expect(createCell?.anyAuthenticated).toBe(true);
    expect(createCell?.roles).toEqual([]);
  });

  it('unions roles across contributing routes in alphabetical order', () => {
    const route1 = makeRoute({
      method: 'put',
      chain: [
        {
          text: 'authenticate',
          name: 'authenticate',
          args: [],
          class: { kind: 'auth' },
          file: 'src/auth.ts',
          line: 1,
        },
        {
          text: 'requireRole("USER")',
          name: 'requireRole',
          args: ['USER'],
          class: { kind: 'role', value: 'USER' },
          file: 'src/auth.ts',
          line: 2,
        },
      ],
    });

    const route2 = makeRoute({
      method: 'patch',
      chain: [
        {
          text: 'authenticate',
          name: 'authenticate',
          args: [],
          class: { kind: 'auth' },
          file: 'src/auth.ts',
          line: 1,
        },
        {
          text: 'requireRole("ADMIN")',
          name: 'requireRole',
          args: ['ADMIN'],
          class: { kind: 'role', value: 'ADMIN' },
          file: 'src/auth.ts',
          line: 2,
        },
      ],
    });

    const matrix = deriveMatrix([route1, route2], ['Post']);
    const updateCell = matrix.find((c) => c.resource === 'Post' && c.action === 'update');

    expect(updateCell).toBeDefined();
    expect(updateCell?.anonymous).toBe(false);
    expect(updateCell?.anyAuthenticated).toBe(false);
    expect(updateCell?.roles).toEqual(['ADMIN', 'USER']);
  });

  it('flags own: true when at least one contributing route has probable ownership', () => {
    const routeWithOwnership = makeRoute({
      method: 'delete',
      ownership: 'probable',
      chain: [
        {
          text: 'authenticate',
          name: 'authenticate',
          args: [],
          class: { kind: 'auth' },
          file: 'src/auth.ts',
          line: 1,
        },
      ],
    });

    const matrix = deriveMatrix([routeWithOwnership], ['Post']);
    const deleteCell = matrix.find((c) => c.resource === 'Post' && c.action === 'delete');

    expect(deleteCell).toBeDefined();
    expect(deleteCell?.own).toBe(true);
  });

  it('flags uncertain: true when confidence is low or middleware is unknown', () => {
    const lowConfRoute = makeRoute({
      method: 'delete',
      confidence: 'low',
      chain: [],
    });

    const matrix1 = deriveMatrix([lowConfRoute], ['Post']);
    const cell1 = matrix1.find((c) => c.resource === 'Post' && c.action === 'delete');
    expect(cell1?.uncertain).toBe(true);

    const unknownMwRoute = makeRoute({
      method: 'get',
      confidence: 'high',
      chain: [
        {
          text: 'customMw()',
          name: 'customMw',
          args: [],
          class: { kind: 'unknown' },
          file: 'src/mw.ts',
          line: 5,
        },
      ],
    });

    const matrix2 = deriveMatrix([unknownMwRoute], ['Post']);
    const cell2 = matrix2.find((c) => c.resource === 'Post' && c.action === 'read');
    expect(cell2?.uncertain).toBe(true);
  });

  it('flags uncertain: true when ownership is unknown or role value is unknown', () => {
    const unknownOwnerRoute = makeRoute({
      method: 'post',
      ownership: 'unknown',
    });

    const matrix1 = deriveMatrix([unknownOwnerRoute], ['Post']);
    const cell1 = matrix1.find((c) => c.resource === 'Post' && c.action === 'create');
    expect(cell1?.uncertain).toBe(true);

    const unknownRoleRoute = makeRoute({
      method: 'get',
      chain: [
        {
          text: 'requireRole(dynamicRole)',
          name: 'requireRole',
          args: [],
          class: { kind: 'role', value: 'unknown' },
          file: 'src/auth.ts',
          line: 3,
        },
      ],
    });

    const matrix2 = deriveMatrix([unknownRoleRoute], ['Post']);
    const cell2 = matrix2.find((c) => c.resource === 'Post' && c.action === 'read');
    expect(cell2?.uncertain).toBe(true);
    expect(cell2?.roles).toEqual([]); // 'unknown' excluded from roles list
  });

  it('produces empty cells for models without contributing routes', () => {
    const matrix = deriveMatrix([], ['Student']);
    expect(matrix.length).toBe(4);

    for (const cell of matrix) {
      expect(cell.resource).toBe('Student');
      expect(cell.anonymous).toBe(false);
      expect(cell.anyAuthenticated).toBe(false);
      expect(cell.roles).toEqual([]);
      expect(cell.own).toBe(false);
      expect(cell.uncertain).toBe(false);
    }
  });

  it('app.all populates all 4 CRUD actions', () => {
    const allRoute = makeRoute({
      method: 'all',
      chain: [
        {
          text: 'authenticate',
          name: 'authenticate',
          args: [],
          class: { kind: 'auth' },
          file: 'src/auth.ts',
          line: 1,
        },
        {
          text: 'requireRole("ADMIN")',
          name: 'requireRole',
          args: ['ADMIN'],
          class: { kind: 'role', value: 'ADMIN' },
          file: 'src/auth.ts',
          line: 2,
        },
      ],
    });

    const matrix = deriveMatrix([allRoute], ['Post']);
    expect(matrix.length).toBe(4);

    for (const action of ['create', 'read', 'update', 'delete'] as const) {
      const cell = matrix.find((c) => c.action === action);
      expect(cell?.roles).toEqual(['ADMIN']);
      expect(cell?.anonymous).toBe(false);
      expect(cell?.anyAuthenticated).toBe(false);
    }
  });
});

describe('deriveMatrix on realistic fixtures', () => {
  it('correctly flags own: true on ownership-ok fixture', async () => {
    const { project, config } = await loadFixture('ownership-ok');
    const { routes: composed } = composeMounts(project);
    const schema = loadPrismaSchema(config.prismaSchema, config.ownership.ownerFields);
    const routeNodes = buildRouteNodes(composed, config, schema);

    const matrix = deriveMatrix(routeNodes, ['Post']);
    const deleteCell = matrix.find((c) => c.resource === 'Post' && c.action === 'delete');

    expect(deleteCell).toBeDefined();
    expect(deleteCell?.own).toBe(true);
    expect(deleteCell?.anonymous).toBe(false);
  });

  it('correctly flags own: false on ownership-missing fixture', async () => {
    const { project, config } = await loadFixture('ownership-missing');
    const { routes: composed } = composeMounts(project);
    const schema = loadPrismaSchema(config.prismaSchema, config.ownership.ownerFields);
    const routeNodes = buildRouteNodes(composed, config, schema);

    const matrix = deriveMatrix(routeNodes, ['Post']);
    const deleteCell = matrix.find((c) => c.resource === 'Post' && c.action === 'delete');

    expect(deleteCell).toBeDefined();
    expect(deleteCell?.own).toBe(false);
  });

  it('correctly propagates uncertain: true on dynamic-mount fixture', async () => {
    const { project, config } = await loadFixture('dynamic-mount');
    const { routes: composed } = composeMounts(project);
    const schema = parsePrismaSchema('');
    const configWithResource = {
      ...config,
      resources: { '/api/:dynamic': 'Post' },
    };
    const routeNodes = buildRouteNodes(composed, configWithResource, schema);

    expect(routeNodes[0]?.confidence).toBe('low');
    expect(routeNodes[0]?.resource?.model).toBe('Post');

    // Dynamic mount on /api/:dynamic/:id maps to Post
    const matrix = deriveMatrix(routeNodes, ['Post']);
    const getCell = matrix.find((c) => c.resource === 'Post' && c.action === 'read');

    expect(getCell).toBeDefined();
    expect(getCell?.uncertain).toBe(true);
  });
});
