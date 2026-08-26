/**
 * Unit tests for Express mount composition and effective middleware chain.
 *
 * @see context.md §6.3
 */

import { describe, it, expect, vi } from 'vitest';
import { Project } from 'ts-morph';
import { loadFixture } from '../helpers/fixture.js';
import {
  normalizePath,
  matchesPrefix,
  composeMounts,
} from '../../src/scan/mounts.js';

describe('normalizePath', () => {
  it('handles empty input and single root slash', () => {
    expect(normalizePath()).toBe('/');
    expect(normalizePath('')).toBe('/');
    expect(normalizePath('/')).toBe('/');
    expect(normalizePath('/', '/')).toBe('/');
  });

  it('joins segments, removes redundant slashes, and strips trailing slash', () => {
    expect(normalizePath('/api/v1', '/posts', '/:id')).toBe('/api/v1/posts/:id');
    expect(normalizePath('/api/v1/', '/posts/', '/')).toBe('/api/v1/posts');
    expect(normalizePath('api', 'posts', ':id')).toBe('/api/posts/:id');
    expect(normalizePath('/api///v1//', '//posts/')).toBe('/api/v1/posts');
  });

  it('preserves route params and dynamic segments', () => {
    expect(normalizePath('/api', ':dynamic', 'posts', ':id')).toBe('/api/:dynamic/posts/:id');
    expect(normalizePath('/users/:userId/orders/:orderId')).toBe('/users/:userId/orders/:orderId');
  });
});

describe('matchesPrefix', () => {
  it('matches any route when usePath is undefined, empty, or root', () => {
    expect(matchesPrefix('/api/v1/posts', undefined)).toBe(true);
    expect(matchesPrefix('/api/v1/posts', '')).toBe(true);
    expect(matchesPrefix('/api/v1/posts', '/')).toBe(true);
  });

  it('matches exact and slash-bounded sub-paths', () => {
    expect(matchesPrefix('/api/v1/posts', '/api')).toBe(true);
    expect(matchesPrefix('/api/v1/posts', '/api/v1')).toBe(true);
    expect(matchesPrefix('/api', '/api')).toBe(true);
    expect(matchesPrefix('/api/', '/api')).toBe(true);
  });

  it('rejects paths that do not match on slash boundaries', () => {
    expect(matchesPrefix('/api-docs', '/api')).toBe(false);
    expect(matchesPrefix('/apiv1', '/api')).toBe(false);
    expect(matchesPrefix('/users/123', '/api')).toBe(false);
  });
});

describe('Mount composition with nested-routers fixture', () => {
  it('composes 3-level deep router (/api/v1 + /posts + /:id) and applies app-level middleware before mount', async () => {
    const { project } = await loadFixture('nested-routers');
    const { routes, warnings } = composeMounts(project);

    expect(warnings).toEqual([]);

    const getRoute = routes.find((r) => r.method === 'GET');
    expect(getRoute).toBeDefined();
    expect(getRoute?.path).toBe('/api/v1/posts/:id');
    expect(getRoute?.confidence).toBe('high');
    expect(getRoute?.orphan).toBe(false);

    // App-level use(authenticate) registered BEFORE app.use('/api/v1', ...) protects children
    const mwTexts = getRoute?.middlewareArgs.map((m) => m.getText()) ?? [];
    expect(mwTexts).toContain('authenticate');

    // App-level use(afterAppMw) registered AFTER app.use('/api/v1', ...) does NOT protect children
    expect(mwTexts).not.toContain('afterAppMw');

    const postRoute = routes.find((r) => r.method === 'POST');
    expect(postRoute).toBeDefined();
    expect(postRoute?.path).toBe('/api/v1/posts');
    const postMwTexts = postRoute?.middlewareArgs.map((m) => m.getText()) ?? [];
    expect(postMwTexts).toContain('authenticate');
    expect(postMwTexts).not.toContain('afterAppMw');
  });
});

describe('Mount composition with router-use-order fixture', () => {
  it('verifies router.use(authenticate) declared AFTER a route does not protect it', async () => {
    const { project } = await loadFixture('router-use-order');
    const { routes } = composeMounts(project);

    const getRoute = routes.find((r) => r.method === 'GET');
    const deleteRoute = routes.find((r) => r.method === 'DELETE');

    expect(getRoute).toBeDefined();
    expect(deleteRoute).toBeDefined();

    expect(getRoute?.path).toBe('/items/:id');
    expect(deleteRoute?.path).toBe('/items/:id');

    // GET route declared BEFORE router.use(authenticate) -> authenticate is NOT in chain
    const getMwTexts = getRoute?.middlewareArgs.map((m) => m.getText()) ?? [];
    expect(getMwTexts).not.toContain('authenticate');
    expect(getMwTexts.length).toBe(0);

    // DELETE route declared AFTER router.use(authenticate) -> authenticate IS in chain
    const deleteMwTexts = deleteRoute?.middlewareArgs.map((m) => m.getText()) ?? [];
    expect(deleteMwTexts).toContain('authenticate');
  });
});

describe('Mount composition with dynamic-mount fixture', () => {
  it('marks dynamic mounts as :dynamic and confidence low', async () => {
    const { project } = await loadFixture('dynamic-mount');
    const { routes } = composeMounts(project);

    const getRoute = routes.find((r) => r.method === 'GET');
    expect(getRoute).toBeDefined();
    expect(getRoute?.path).toBe('/api/:dynamic/:id');
    expect(getRoute?.confidence).toBe('low');
  });
});

describe('Cycle detection in router mounts', () => {
  it('detects router cycle, terminates cleanly without loop, and warns', () => {
    const project = new Project({ useInMemoryFileSystem: true });

    project.createSourceFile(
      'app.ts',
      `
      import express, { Router } from 'express';
      const app = express();
      const routerA = Router();
      const routerB = Router();

      routerA.use('/b', routerB);
      routerB.use('/a', routerA);
      routerB.get('/endpoint', (req, res) => res.send('ok'));

      app.use('/api', routerA);
      `,
    );

    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

    const { routes, warnings } = composeMounts(project);

    expect(warnings.length).toBeGreaterThan(0);
    expect(warnings.some((w) => w.toLowerCase().includes('cycle'))).toBe(true);

    // Should still return composed routes reached before the cycle
    expect(routes.length).toBeGreaterThan(0);

    warnSpy.mockRestore();
  });
});
