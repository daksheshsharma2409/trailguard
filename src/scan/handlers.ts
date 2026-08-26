/**
 * Router and handler reference resolution for Express static analysis.
 *
 * Resolves imported routers (named, default, aliased, re-exported, require)
 * and handler references (functions, controller methods, class static/instance members)
 * to their declarations, caching results by ts-morph Symbol.
 *
 * @see context.md §6.2, §6.3, §6.7
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import {
  Node,
  SyntaxKind,
  type SourceFile,
  type Symbol as TsMorphSymbol,
} from 'ts-morph';

export interface ResolvedHandler {
  resolved: boolean;
  name: string;
  file?: string | undefined;
  line?: number | undefined;
  declarationNode?: Node | undefined;
  bodyNode?: Node | undefined;
}

export interface ResolvedRouter {
  resolved: boolean;
  name: string;
  file?: string | undefined;
  line?: number | undefined;
  symbol?: TsMorphSymbol | undefined;
  declarationNode?: Node | undefined;
}

/**
 * Unwrap type assertions (`as Type`), parenthesized expressions, etc.
 */
export function unwrapExpression(node: Node): Node {
  let curr = node;
  while (
    Node.isAsExpression(curr) ||
    Node.isTypeAssertion(curr) ||
    Node.isParenthesizedExpression(curr) ||
    Node.isNonNullExpression(curr)
  ) {
    curr = curr.getExpression();
  }
  return curr;
}

/**
 * Follow symbol aliases to the root canonical symbol.
 */
export function getRootSymbol(symbol: TsMorphSymbol): TsMorphSymbol {
  let current = symbol;
  while (current.getAliasedSymbol()) {
    const next = current.getAliasedSymbol();
    if (!next || next === current) break;
    current = next;
  }
  return current;
}

/**
 * Resolve a relative module specifier to a SourceFile within the ts-morph Project.
 * If the file exists on disk but is not yet loaded into the Project, loads it on demand.
 */
export function resolveModuleSourceFile(
  currentFile: SourceFile,
  specifier: string,
): SourceFile | undefined {
  const project = currentFile.getProject();
  const dir = currentFile.getDirectoryPath();

  // Strip extension if present to try standard TS/JS extensions
  const clean = specifier.replace(/\.[jt]sx?$/, '');
  const candidates = [
    specifier,
    `${clean}.ts`,
    `${clean}.js`,
    `${clean}.mjs`,
    `${clean}/index.ts`,
    `${clean}/index.js`,
  ];

  for (const candidate of candidates) {
    const absPath = path.resolve(dir, candidate);
    let sf = project.getSourceFile(absPath);
    if (!sf && fs.existsSync(absPath)) {
      try {
        sf = project.addSourceFileAtPath(absPath);
      } catch {
        // Ignored if unparseable
      }
    }
    if (sf) return sf;
  }

  return undefined;
}

/**
 * Find export declarations in CommonJS module files (`module.exports = ...`).
 */
function findCjsExport(targetSf: SourceFile, bindingName: string): Node {
  for (const b of targetSf.getDescendantsOfKind(SyntaxKind.BinaryExpression)) {
    const leftText = b.getLeft().getText();
    if (leftText === 'module.exports') {
      const right = b.getRight();
      if (Node.isIdentifier(right)) {
        const vd = targetSf.getVariableDeclaration(right.getText());
        if (vd) return vd;
      }
      return b;
    }
    if (leftText === `exports.${bindingName}` || leftText === `module.exports.${bindingName}`) {
      return b.getRight();
    }
  }
  const vd = targetSf.getVariableDeclaration(bindingName);
  if (vd) return vd;
  return targetSf;
}

/**
 * Context holding symbol resolution caches.
 */
export class ResolutionContext {
  private handlerCache = new Map<TsMorphSymbol, ResolvedHandler>();
  private routerCache = new Map<TsMorphSymbol, ResolvedRouter>();

  public getCachedHandler(symbol: TsMorphSymbol): ResolvedHandler | undefined {
    return this.handlerCache.get(symbol);
  }

  public setCachedHandler(symbol: TsMorphSymbol, resolved: ResolvedHandler): void {
    this.handlerCache.set(symbol, resolved);
  }

  public getCachedRouter(symbol: TsMorphSymbol): ResolvedRouter | undefined {
    return this.routerCache.get(symbol);
  }

  public setCachedRouter(symbol: TsMorphSymbol, resolved: ResolvedRouter): void {
    this.routerCache.set(symbol, resolved);
  }

  public clear(): void {
    this.handlerCache.clear();
    this.routerCache.clear();
  }
}

const defaultContext = new ResolutionContext();

/**
 * Resolve a handler argument node to its declaration and body.
 *
 * Handles:
 * - Direct inline function / arrow function
 * - Identifier referencing local or imported function
 * - Property access `controller.method` (object method or class static/instance member)
 * - Factory / higher-order call expression
 *
 * Never throws; returns `{ resolved: false, name }` when unresolvable.
 */
export function resolveHandler(
  node: Node,
  ctx: ResolutionContext = defaultContext,
): ResolvedHandler {
  try {
    const targetNode = unwrapExpression(node);
    const textName = targetNode.getText();

    // 1. Inline ArrowFunction or FunctionExpression
    if (Node.isArrowFunction(targetNode) || Node.isFunctionExpression(targetNode)) {
      return {
        resolved: true,
        name: '(anonymous)',
        file: targetNode.getSourceFile().getFilePath(),
        line: targetNode.getStartLineNumber(),
        declarationNode: targetNode,
        bodyNode: targetNode.getBody(),
      };
    }

    // 2. Symbol resolution (identifier, property access, etc.)
    const initialSym = targetNode.getSymbol();
    if (initialSym) {
      const cached = ctx.getCachedHandler(initialSym);
      if (cached) return cached;

      const rootSym = getRootSymbol(initialSym);
      const cachedRoot = ctx.getCachedHandler(rootSym);
      if (cachedRoot) return cachedRoot;

      const decls = rootSym.getDeclarations();
      if (decls.length > 0) {
        const decl = decls[0];
        if (!decl || decl.getSourceFile().isDeclarationFile()) {
          return { resolved: false, name: textName };
        }

        // 2a. FunctionDeclaration
        if (Node.isFunctionDeclaration(decl)) {
          const body = decl.getBody();
          if (!body) {
            return { resolved: false, name: textName };
          }
          const res: ResolvedHandler = {
            resolved: true,
            name: decl.getName() ?? textName,
            file: decl.getSourceFile().getFilePath(),
            line: decl.getStartLineNumber(),
            declarationNode: decl,
            bodyNode: body,
          };
          ctx.setCachedHandler(initialSym, res);
          ctx.setCachedHandler(rootSym, res);
          return res;
        }

        // 2b. MethodDeclaration (in class or object literal)
        if (Node.isMethodDeclaration(decl)) {
          const body = decl.getBody();
          if (!body) {
            return { resolved: false, name: textName };
          }
          const res: ResolvedHandler = {
            resolved: true,
            name: textName,
            file: decl.getSourceFile().getFilePath(),
            line: decl.getStartLineNumber(),
            declarationNode: decl,
            bodyNode: body,
          };
          ctx.setCachedHandler(initialSym, res);
          ctx.setCachedHandler(rootSym, res);
          return res;
        }

        // 2c. VariableDeclaration with function initializer
        if (Node.isVariableDeclaration(decl)) {
          const rawInit = decl.getInitializer();
          if (!rawInit) {
            return { resolved: false, name: textName };
          }

          const init = unwrapExpression(rawInit);
          if (Node.isArrowFunction(init) || Node.isFunctionExpression(init)) {
            const res: ResolvedHandler = {
              resolved: true,
              name: decl.getName(),
              file: decl.getSourceFile().getFilePath(),
              line: decl.getStartLineNumber(),
              declarationNode: decl,
              bodyNode: init.getBody(),
            };
            ctx.setCachedHandler(initialSym, res);
            ctx.setCachedHandler(rootSym, res);
            return res;
          }

          // If initialized with another expression / identifier / call, recurse
          return resolveHandler(init, ctx);
        }

        // 2d. PropertyAssignment: `controller = { method: fn }`
        if (Node.isPropertyAssignment(decl)) {
          const rawInit = decl.getInitializer();
          if (rawInit) {
            const init = unwrapExpression(rawInit);
            if (Node.isArrowFunction(init) || Node.isFunctionExpression(init)) {
              const res: ResolvedHandler = {
                resolved: true,
                name: textName,
                file: decl.getSourceFile().getFilePath(),
                line: decl.getStartLineNumber(),
                declarationNode: decl,
                bodyNode: init.getBody(),
              };
              ctx.setCachedHandler(initialSym, res);
              return res;
            }
            // If initialized with another identifier, recurse
            return resolveHandler(init, ctx);
          }
        }
      }
    }

    // 3. Higher-order function / call expression: `createHandler('admin')`
    if (Node.isCallExpression(targetNode)) {
      const callee = targetNode.getExpression();
      const calleeRes = resolveHandler(callee, ctx);
      return {
        resolved: calleeRes.resolved,
        name: textName,
        file: calleeRes.file,
        line: calleeRes.line,
        declarationNode: calleeRes.declarationNode,
        bodyNode: calleeRes.bodyNode,
      };
    }

    // Unresolvable handler
    return {
      resolved: false,
      name: textName,
    };
  } catch {
    // Failsafe: never throw on unresolvable handlers
    return {
      resolved: false,
      name: node.getText(),
    };
  }
}

/**
 * Check if a declaration represents an Express router or app.
 */
export function isRouterDeclaration(decl: Node): boolean {
  if (Node.isVariableDeclaration(decl)) {
    const rawInit = decl.getInitializer();
    if (rawInit) {
      const init = unwrapExpression(rawInit);
      if (Node.isArrowFunction(init) || Node.isFunctionExpression(init)) {
        return false;
      }
      if (Node.isCallExpression(init)) {
        const text = init.getExpression().getText();
        if (
          text === 'Router' ||
          text.endsWith('.Router') ||
          text === 'express' ||
          text.endsWith('.express')
        ) {
          return true;
        }
      }
    }
    const typeText = decl.getType().getText();
    if (
      typeText.includes('Router') ||
      typeText.includes('Express') ||
      typeText.includes('Application') ||
      typeText.includes('IRouter')
    ) {
      return true;
    }
    const name = decl.getName();
    if (name === 'router' || name.endsWith('Router') || name === 'app' || name.endsWith('App')) {
      return true;
    }
  }
  return false;
}

/**
 * Resolve a router node or variable to its declaration.
 *
 * Handles:
 * - Named imports (`import { router } from './routes'`)
 * - Default imports (`import router from './routes'`)
 * - Aliased imports (`import { router as r } from './routes'`)
 * - Re-exports (`export { router } from './routes'`)
 * - CommonJS `require('./routes')` and `{ router } = require('./routes')`
 *
 * Never throws; returns `{ resolved: false, name }` when unresolvable.
 */
export function resolveRouter(
  node: Node,
  ctx: ResolutionContext = defaultContext,
): ResolvedRouter {
  try {
    const targetNode = unwrapExpression(node);
    const textName = targetNode.getText();

    // 1. Check if node is an identifier with a symbol
    const initialSym = targetNode.getSymbol();
    if (initialSym) {
      const cached = ctx.getCachedRouter(initialSym);
      if (cached) return cached;

      const rootSym = getRootSymbol(initialSym);
      const cachedRoot = ctx.getCachedRouter(rootSym);
      if (cachedRoot) return cachedRoot;

      const decls = rootSym.getDeclarations();
      for (const decl of decls) {
        // Variable declaration holding a router
        if (Node.isVariableDeclaration(decl)) {
          const rawInit = decl.getInitializer();
          const init = rawInit ? unwrapExpression(rawInit) : undefined;

          // Check if initialized with require(...)
          if (init && Node.isCallExpression(init)) {
            const expr = init.getExpression();
            if (expr.getText() === 'require') {
              const arg = init.getArguments()[0];
              if (arg && Node.isStringLiteral(arg)) {
                const targetSf = resolveModuleSourceFile(
                  decl.getSourceFile(),
                  arg.getLiteralValue(),
                );
                if (targetSf) {
                  // If destructuring `const { namedRouter } = require(...)`
                  const bindingName = decl.getName();
                  const exported =
                    targetSf.getExportedDeclarations().get(bindingName)?.[0] ??
                    targetSf.getExportedDeclarations().get('default')?.[0] ??
                    findCjsExport(targetSf, bindingName);

                  const res: ResolvedRouter = {
                    resolved: true,
                    name: bindingName,
                    file: targetSf.getFilePath(),
                    line: exported.getStartLineNumber(),
                    symbol: exported.getSymbol(),
                    declarationNode: exported,
                  };
                  ctx.setCachedRouter(initialSym, res);
                  return res;
                }
              }
            }
          }

          // Check if variable declaration actually holds a router
          if (!isRouterDeclaration(decl)) {
            continue;
          }

          const res: ResolvedRouter = {
            resolved: true,
            name: decl.getName(),
            file: decl.getSourceFile().getFilePath(),
            line: decl.getStartLineNumber(),
            symbol: rootSym,
            declarationNode: decl,
          };
          ctx.setCachedRouter(initialSym, res);
          ctx.setCachedRouter(rootSym, res);
          return res;
        }

        // Export assignment: `export default router;`
        if (Node.isExportAssignment(decl)) {
          const expExpr = decl.getExpression();
          if (expExpr !== targetNode) {
            return resolveRouter(expExpr, ctx);
          }
        }
      }
    }

    // 2. Direct require call: `app.use('/orders', require('./orders'))`
    if (Node.isCallExpression(targetNode)) {
      const expr = targetNode.getExpression();
      if (expr.getText() === 'require') {
        const arg = targetNode.getArguments()[0];
        if (arg && Node.isStringLiteral(arg)) {
          const targetSf = resolveModuleSourceFile(targetNode.getSourceFile(), arg.getLiteralValue());
          if (targetSf) {
            const defaultExport =
              targetSf.getExportedDeclarations().get('default')?.[0] ??
              findCjsExport(targetSf, 'default');
            return {
              resolved: true,
              name: defaultExport.getSymbol()?.getName() ?? textName,
              file: targetSf.getFilePath(),
              line: defaultExport.getStartLineNumber(),
              symbol: defaultExport.getSymbol(),
              declarationNode: defaultExport,
            };
          }
        }
      }
    }

    return {
      resolved: false,
      name: textName,
    };
  } catch {
    return {
      resolved: false,
      name: node.getText(),
    };
  }
}
