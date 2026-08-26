import { describe, it, expect } from 'vitest';
import { Project } from 'ts-morph';
import { extractRoutes, extractRoutesFromProject } from '../../src/scan/routes.js';
import { loadFixture } from '../helpers/fixture.js';

describe('T2.2 — Route extraction', () => {
  describe('All call shapes from context.md §6.2', () => {
    it('extracts every recognized call shape with correct method, rawPath, middlewareArgs, handlerArg, and order', () => {
      const project = new Project({ compilerOptions: { allowJs: true } });
      const sf = project.createSourceFile(
        'shapes.ts',
        `
        import express from 'express';
        const app = express();
        const router = express.Router();

        // 1. app.get('/x', a, b, handler)
        app.get('/x', a, b, handler);

        // 2. router.post('/', createPost)
        router.post('/', createPost);

        // 3. router.route('/:id').get(h).patch(authenticate, h)
        router.route('/:id').get(h).patch(authenticate, h);

        // 4. app.use('/api/posts', postRouter)
        app.use('/api/posts', postRouter);

        // 5. app.use(authenticate)
        app.use(authenticate);

        // 6. router.use(authenticate)
        router.use(authenticate);

        // 7. app.use('/api', authenticate, router)
        app.use('/api', authenticate, router);

        // 8. app.use(express.json())
        app.use(express.json());

        // 9. Array of middleware: flattened
        app.get('/arr', [mw1, mw2], mw3, hArr);

        // 10. app.all verb
        app.all('/all', hAll);

        // 11. Template literal paths
        app.get(\`/users/\${id}\`, hDyn);
        app.get(\`/constant\`, hConst);

        // 12. RegExp path
        app.get(/test-regex/, hRegex);
      `,
      );

      const result = extractRoutes(sf);
      const { routes, uses } = result;

      // ── Verify Route 1: app.get('/x', a, b, handler) ──
      const r1 = routes.find((r) => r.method === 'GET' && r.rawPath === '/x');
      expect(r1).toBeDefined();
      expect(r1!.middlewareArgs.map((a) => a.getText())).toEqual(['a', 'b']);
      expect(r1!.handlerArg?.getText()).toBe('handler');
      expect(r1!.order).toBe(1);
      expect(r1!.confidence).toBe('high');

      // ── Verify Route 2: router.post('/', createPost) ──
      const r2 = routes.find((r) => r.method === 'POST' && r.rawPath === '/');
      expect(r2).toBeDefined();
      expect(r2!.middlewareArgs.map((a) => a.getText())).toEqual([]);
      expect(r2!.handlerArg?.getText()).toBe('createPost');
      expect(r2!.order).toBe(2);

      // ── Verify Route 3: router.route('/:id').get(h).patch(authenticate, h) ──
      const r3Get = routes.find((r) => r.method === 'GET' && r.rawPath === '/:id');
      const r3Patch = routes.find((r) => r.method === 'PATCH' && r.rawPath === '/:id');
      expect(r3Get).toBeDefined();
      expect(r3Get!.middlewareArgs.map((a) => a.getText())).toEqual([]);
      expect(r3Get!.handlerArg?.getText()).toBe('h');
      expect(r3Get!.order).toBe(3);

      expect(r3Patch).toBeDefined();
      expect(r3Patch!.middlewareArgs.map((a) => a.getText())).toEqual(['authenticate']);
      expect(r3Patch!.handlerArg?.getText()).toBe('h');
      expect(r3Patch!.order).toBe(4);

      // ── Verify Use 4: app.use('/api/posts', postRouter) ──
      const u4 = uses.find((u) => u.rawPath === '/api/posts');
      expect(u4).toBeDefined();
      expect(u4!.args.map((a) => a.getText())).toEqual(['postRouter']);
      expect(u4!.order).toBe(5);

      // ── Verify Use 5: app.use(authenticate) ──
      const u5 = uses.find((u) => u.routerVarName === 'app' && u.rawPath === undefined && u.order === 6);
      expect(u5).toBeDefined();
      expect(u5!.args.map((a) => a.getText())).toEqual(['authenticate']);

      // ── Verify Use 6: router.use(authenticate) ──
      const u6 = uses.find((u) => u.routerVarName === 'router' && u.rawPath === undefined);
      expect(u6).toBeDefined();
      expect(u6!.args.map((a) => a.getText())).toEqual(['authenticate']);
      expect(u6!.order).toBe(7);

      // ── Verify Use 7: app.use('/api', authenticate, router) ──
      const u7 = uses.find((u) => u.rawPath === '/api');
      expect(u7).toBeDefined();
      expect(u7!.args.map((a) => a.getText())).toEqual(['authenticate', 'router']);
      expect(u7!.order).toBe(8);

      // ── Verify Use 8: app.use(express.json()) ──
      const u8 = uses.find((u) => u.order === 9);
      expect(u8).toBeDefined();
      expect(u8!.rawPath).toBeUndefined();
      expect(u8!.args.map((a) => a.getText())).toEqual(['express.json()']);

      // ── Verify Route 9: app.get('/arr', [mw1, mw2], mw3, hArr) ──
      const rArr = routes.find((r) => r.rawPath === '/arr');
      expect(rArr).toBeDefined();
      expect(rArr!.middlewareArgs.map((a) => a.getText())).toEqual(['mw1', 'mw2', 'mw3']);
      expect(rArr!.handlerArg?.getText()).toBe('hArr');
      expect(rArr!.order).toBe(10);

      // ── Verify Route 10: app.all('/all', hAll) ──
      const rAll = routes.find((r) => r.rawPath === '/all');
      expect(rAll).toBeDefined();
      expect(rAll!.method).toBe('ALL');
      expect(rAll!.handlerArg?.getText()).toBe('hAll');
      expect(rAll!.order).toBe(11);

      // ── Verify Route 11: template literal paths ──
      const rDyn = routes.find((r) => r.rawPath === '/users/:dynamic');
      expect(rDyn).toBeDefined();
      expect(rDyn!.confidence).toBe('low');
      expect(rDyn!.order).toBe(12);

      const rConst = routes.find((r) => r.rawPath === '/constant');
      expect(rConst).toBeDefined();
      expect(rConst!.confidence).toBe('high');
      expect(rConst!.order).toBe(13);

      // ── Verify Route 12: RegExp path ──
      const rRegex = routes.find((r) => r.rawPath === '<regex>');
      expect(rRegex).toBeDefined();
      expect(rRegex!.confidence).toBe('low');
      expect(rRegex!.order).toBe(14);
    });

    it('tracks app and router by symbol across declarations and usages', () => {
      const project = new Project({ compilerOptions: { allowJs: true } });
      const sf = project.createSourceFile(
        'symbols.ts',
        `
        import express from 'express';
        const myApp = express();
        const myRouter = express.Router();

        myApp.get('/test-app', h1);
        myRouter.post('/test-router', h2);
      `,
      );

      const { routes } = extractRoutes(sf);
      const appRoute = routes.find((r) => r.rawPath === '/test-app')!;
      const routerRoute = routes.find((r) => r.rawPath === '/test-router')!;

      expect(appRoute.routerSymbol).toBeDefined();
      expect(routerRoute.routerSymbol).toBeDefined();
      expect(appRoute.routerSymbol).not.toBe(routerRoute.routerSymbol);

      const appDecl = sf.getVariableDeclarationOrThrow('myApp');
      const routerDecl = sf.getVariableDeclarationOrThrow('myRouter');

      expect(appRoute.routerSymbol).toBe(appDecl.getSymbol());
      expect(routerRoute.routerSymbol).toBe(routerDecl.getSymbol());
    });
  });

  describe('Fixtures route extraction', () => {
    it('extracts routes from clean fixture', async () => {
      const { project } = await loadFixture('clean');
      const { routes, uses } = extractRoutesFromProject(project);

      // Verify routes extracted from clean/src/routes.ts
      expect(routes.length).toBe(2);

      const getHealth = routes.find((r) => r.method === 'GET' && r.rawPath === '/health');
      expect(getHealth).toBeDefined();
      expect(getHealth!.middlewareArgs).toHaveLength(0);
      expect(getHealth!.handlerArg).toBeDefined();
      expect(getHealth!.order).toBe(1);

      const postItems = routes.find((r) => r.method === 'POST' && r.rawPath === '/items');
      expect(postItems).toBeDefined();
      expect(postItems!.middlewareArgs.map((a) => a.getText())).toEqual([
        'authenticate',
        "requireRole('ADMIN')",
      ]);
      expect(postItems!.handlerArg).toBeDefined();
      expect(postItems!.order).toBe(2);

      // Verify uses extracted from clean/src/app.ts
      expect(uses.length).toBe(2);

      const jsonUse = uses.find((u) => u.rawPath === undefined);
      expect(jsonUse).toBeDefined();
      expect(jsonUse!.args.map((a) => a.getText())).toEqual(['express.json()']);
      expect(jsonUse!.order).toBe(1);

      const apiUse = uses.find((u) => u.rawPath === '/api');
      expect(apiUse).toBeDefined();
      expect(apiUse!.args.map((a) => a.getText())).toEqual(['router']);
      expect(apiUse!.order).toBe(2);
    });

    it('extracts chained routes from route-chain fixture', async () => {
      const { project } = await loadFixture('route-chain');
      const { routes, uses } = extractRoutesFromProject(project);

      // routes.ts has router.route('/:id').get(getItem).patch(authenticate, updateItem)
      expect(routes.length).toBe(2);

      const getRoute = routes.find((r) => r.method === 'GET');
      expect(getRoute).toBeDefined();
      expect(getRoute!.rawPath).toBe('/:id');
      expect(getRoute!.middlewareArgs).toHaveLength(0);
      expect(getRoute!.handlerArg?.getText()).toBe('getItem');
      expect(getRoute!.order).toBe(1);

      const patchRoute = routes.find((r) => r.method === 'PATCH');
      expect(patchRoute).toBeDefined();
      expect(patchRoute!.rawPath).toBe('/:id');
      expect(patchRoute!.middlewareArgs.map((a) => a.getText())).toEqual(['authenticate']);
      expect(patchRoute!.handlerArg?.getText()).toBe('updateItem');
      expect(patchRoute!.order).toBe(2);

      // app.ts has 2 use calls
      expect(uses.length).toBe(2);
      expect(uses[0]?.order).toBe(1);
      expect(uses[1]?.order).toBe(2);
    });
  });
});
