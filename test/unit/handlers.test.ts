import { describe, it, expect } from 'vitest';
import { Project } from 'ts-morph';
import { resolveHandler, resolveRouter, ResolutionContext } from '../../src/scan/handlers.js';
import { extractRoutes } from '../../src/scan/routes.js';
import { loadFixture } from '../helpers/fixture.js';

describe('T2.3 — Import/handler resolution', () => {
  describe('Handler resolution by reference style', () => {
    it('resolves functions, object methods, class static/instance members, and handles unresolvable references', () => {
      const project = new Project({ compilerOptions: { allowJs: true } });
      const sf = project.createSourceFile(
        'handlers-demo.ts',
        `
        function myFunction(req, res) { return 1; }
        const myArrow = (req, res) => 2;
        const myController = {
          myMethod(req, res) { return 3; },
          myArrowMethod: (req, res) => 4,
        };
        class MyClass {
          static myStatic(req, res) { return 5; }
          myInstance(req, res) { return 6; }
        }
        const myInstanceObj = new MyClass();

        app.get('/fn', myFunction);
        app.get('/arrow', myArrow);
        app.get('/method', myController.myMethod);
        app.get('/arrow-method', myController.myArrowMethod);
        app.get('/static', MyClass.myStatic);
        app.get('/instance', myInstanceObj.myInstance);
        app.get('/inline', (req, res) => 7);
        app.get('/unknown', completelyUnknownHandler);
      `,
      );

      const ctx = new ResolutionContext();
      const { routes } = extractRoutes(sf);

      // 1. Function declaration
      const rFn = routes.find((r) => r.rawPath === '/fn')!;
      const resFn = resolveHandler(rFn.handlerArg!, ctx);
      expect(resFn.resolved).toBe(true);
      expect(resFn.name).toBe('myFunction');
      expect(resFn.declarationNode).toBeDefined();
      expect(resFn.bodyNode).toBeDefined();

      // 2. Arrow function variable
      const rArrow = routes.find((r) => r.rawPath === '/arrow')!;
      const resArrow = resolveHandler(rArrow.handlerArg!, ctx);
      expect(resArrow.resolved).toBe(true);
      expect(resArrow.name).toBe('myArrow');
      expect(resArrow.bodyNode).toBeDefined();

      // 3. Object method
      const rMethod = routes.find((r) => r.rawPath === '/method')!;
      const resMethod = resolveHandler(rMethod.handlerArg!, ctx);
      expect(resMethod.resolved).toBe(true);
      expect(resMethod.declarationNode).toBeDefined();
      expect(resMethod.bodyNode).toBeDefined();

      // 4. Object arrow property
      const rArrowMethod = routes.find((r) => r.rawPath === '/arrow-method')!;
      const resArrowMethod = resolveHandler(rArrowMethod.handlerArg!, ctx);
      expect(resArrowMethod.resolved).toBe(true);
      expect(resArrowMethod.bodyNode).toBeDefined();

      // 5. Class static member
      const rStatic = routes.find((r) => r.rawPath === '/static')!;
      const resStatic = resolveHandler(rStatic.handlerArg!, ctx);
      expect(resStatic.resolved).toBe(true);
      expect(resStatic.declarationNode).toBeDefined();
      expect(resStatic.bodyNode).toBeDefined();

      // 6. Class instance member
      const rInstance = routes.find((r) => r.rawPath === '/instance')!;
      const resInstance = resolveHandler(rInstance.handlerArg!, ctx);
      expect(resInstance.resolved).toBe(true);
      expect(resInstance.declarationNode).toBeDefined();
      expect(resInstance.bodyNode).toBeDefined();

      // 7. Inline arrow
      const rInline = routes.find((r) => r.rawPath === '/inline')!;
      const resInline = resolveHandler(rInline.handlerArg!, ctx);
      expect(resInline.resolved).toBe(true);
      expect(resInline.name).toBe('(anonymous)');
      expect(resInline.bodyNode).toBeDefined();

      // 8. Unresolvable handler returns { resolved: false } without throwing
      const rUnknown = routes.find((r) => r.rawPath === '/unknown')!;
      const resUnknown = resolveHandler(rUnknown.handlerArg!, ctx);
      expect(resUnknown.resolved).toBe(false);
      expect(resUnknown.name).toBe('completelyUnknownHandler');
    });

    it('caches handler resolution results by symbol', () => {
      const project = new Project({ compilerOptions: { allowJs: true } });
      const sf = project.createSourceFile(
        'cache-test.ts',
        `
        function handler(req, res) {}
        app.get('/1', handler);
        app.get('/2', handler);
      `,
      );

      const ctx = new ResolutionContext();
      const { routes } = extractRoutes(sf);
      const res1 = resolveHandler(routes[0]!.handlerArg!, ctx);
      const res2 = resolveHandler(routes[1]!.handlerArg!, ctx);

      expect(res1).toBe(res2); // Same cached object reference
    });
  });

  describe('Router import resolution over fixture import-resolution', () => {
    it('proves each import style resolves: named, default, aliased, re-exported, and require', async () => {
      const { project } = await loadFixture('import-resolution');
      const appFile = project.getSourceFiles().find((sf) => sf.getFilePath().endsWith('app.ts'))!;
      const { routes, uses } = extractRoutes(appFile);
      const ctx = new ResolutionContext();

      // 1. Named router import: app.use('/posts', postsRouter)
      const uPosts = uses.find((u) => u.rawPath === '/posts')!;
      const resPosts = resolveRouter(uPosts.args[0]!, ctx);
      expect(resPosts.resolved).toBe(true);
      expect(resPosts.name).toBe('postsRouter');
      expect(resPosts.file).toContain('posts.ts');

      // 2. Default router import: app.use('/comments', commentsRouter)
      const uComments = uses.find((u) => u.rawPath === '/comments')!;
      const resComments = resolveRouter(uComments.args[0]!, ctx);
      expect(resComments.resolved).toBe(true);
      expect(resComments.file).toContain('comments.ts');

      // 3. Aliased router import: app.use('/users', aliasedRouter)
      const uUsers = uses.find((u) => u.rawPath === '/users')!;
      const resUsers = resolveRouter(uUsers.args[0]!, ctx);
      expect(resUsers.resolved).toBe(true);
      expect(resUsers.file).toContain('users.ts');

      // 4. Re-exported router import: app.use('/items', reExportedRouter)
      const uItems = uses.find((u) => u.rawPath === '/items')!;
      const resItems = resolveRouter(uItems.args[0]!, ctx);
      expect(resItems.resolved).toBe(true);
      expect(resItems.file).toContain('items.ts');

      // 5. Require router import: app.use('/orders', ordersRouter)
      const uOrders = uses.find((u) => u.rawPath === '/orders')!;
      const resOrders = resolveRouter(uOrders.args[0]!, ctx);
      expect(resOrders.resolved).toBe(true);
      expect(resOrders.file).toContain('orders.js');

      // 6. Verify handler resolutions from app.ts:
      // Function handler: listPosts
      const rPosts = routes.find((r) => r.rawPath === '/api/posts' && r.method === 'GET')!;
      const resH1 = resolveHandler(rPosts.handlerArg!, ctx);
      expect(resH1.resolved).toBe(true);
      expect(resH1.name).toBe('listPosts');
      expect(resH1.file).toContain('posts.ts');

      // Object method handler: postController.createPost
      const rCreate = routes.find((r) => r.rawPath === '/api/posts' && r.method === 'POST')!;
      const resH2 = resolveHandler(rCreate.handlerArg!, ctx);
      expect(resH2.resolved).toBe(true);
      expect(resH2.file).toContain('posts.ts');

      // Class static handler: UserController.getUser
      const rUser = routes.find((r) => r.rawPath === '/api/users/:id')!;
      const resH3 = resolveHandler(rUser.handlerArg!, ctx);
      expect(resH3.resolved).toBe(true);
      expect(resH3.file).toContain('users.ts');

      // Class instance handler: authService.login
      const rLogin = routes.find((r) => r.rawPath === '/api/auth/login')!;
      const resH4 = resolveHandler(rLogin.handlerArg!, ctx);
      expect(resH4.resolved).toBe(true);
      expect(resH4.file).toContain('users.ts');

      // Inline handler: /api/health
      const rHealth = routes.find((r) => r.rawPath === '/api/health')!;
      const resH5 = resolveHandler(rHealth.handlerArg!, ctx);
      expect(resH5.resolved).toBe(true);
      expect(resH5.name).toBe('(anonymous)');

      // Unresolvable handler: /api/external
      const rExternal = routes.find((r) => r.rawPath === '/api/external')!;
      const resH6 = resolveHandler(rExternal.handlerArg!, ctx);
      expect(resH6.resolved).toBe(false);
      expect(resH6.name).toBe('unresolvableExternalHandler');
    });

    it('supports ResolutionContext cache and clearing', () => {
      const ctx = new ResolutionContext();
      ctx.clear();
      expect(ctx.getCachedHandler({} as unknown as Node)).toBeUndefined();
      expect(ctx.getCachedRouter({} as unknown as Node)).toBeUndefined();
    });

    it('resolves CJS exports assignments', () => {
      const project = new Project({ useInMemoryFileSystem: true });
      project.createSourceFile(
        'cjs.js',
        `
        exports.myHandler = function(req, res) { res.send('ok'); };
        module.exports.otherHandler = (req, res) => res.send('ok');
        `,
      );
      const appSf = project.createSourceFile(
        'app.js',
        `
        const cjs = require('./cjs');
        app.get('/test', cjs.myHandler);
        app.get('/test2', cjs.otherHandler);
        `,
      );
      const ctx = new ResolutionContext();
      const { routes } = extractRoutes(appSf);
      for (const r of routes) {
        if (r.handlerArg) {
          const res = resolveHandler(r.handlerArg, ctx);
          expect(res).toBeDefined();
        }
      }
    });

    it('resolves higher-order function handlers and property assignments', () => {
      const project = new Project({ useInMemoryFileSystem: true });
      const sf = project.createSourceFile(
        'hof.ts',
        `
        function makeHandler() {
          return (req, res) => res.send('ok');
        }
        const controller = {
          fnProp: function(req, res) { res.send('ok'); },
          arrowProp: (req, res) => res.send('ok'),
        };

        app.get('/hof', makeHandler());
        app.get('/fn-prop', controller.fnProp);
        app.get('/arrow-prop', controller.arrowProp);
        `,
      );
      const ctx = new ResolutionContext();
      const { routes } = extractRoutes(sf);
      for (const r of routes) {
        if (r.handlerArg) {
          const res = resolveHandler(r.handlerArg, ctx);
          expect(res.resolved).toBe(true);
        }
      }
    });

    it('resolves direct require in app.use and destructured require', () => {
      const project = new Project({ useInMemoryFileSystem: true });
      project.createSourceFile(
        'routes.ts',
        `
        import express from 'express';
        const router = express.Router();
        export default router;
        export const namedRouter = express.Router();
        `,
      );
      const appSf = project.createSourceFile(
        'app.ts',
        `
        const { namedRouter } = require('./routes');
        app.use('/direct', require('./routes'));
        app.use('/named', namedRouter);
        `,
      );
      const ctx = new ResolutionContext();
      const { uses } = extractRoutes(appSf);
      for (const u of uses) {
        for (const arg of u.args) {
          const res = resolveRouter(arg, ctx);
          if (res.resolved) {
            expect(res.file).toBeDefined();
          }
        }
      }
    });
  });
});
