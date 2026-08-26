/**
 * Route and middleware extraction from Express source files via ts-morph AST.
 *
 * @see context.md §6.2
 */

import {
  Node,
  SyntaxKind,
  type SourceFile,
  type CallExpression,
  type Symbol as TsMorphSymbol,
  type Project,
} from 'ts-morph';
import type { HttpMethod } from '../core/types.js';

export const HTTP_METHODS = [
  'get',
  'post',
  'put',
  'patch',
  'delete',
  'head',
  'options',
  'all',
] as const;

export type HttpMethodLower = (typeof HTTP_METHODS)[number];

export interface ExtractedPath {
  rawPath: string;
  isDynamic: boolean;
  confidence: 'high' | 'medium' | 'low';
}

export interface ExtractedRoute {
  method: HttpMethod;
  rawPath: string;
  confidence: 'high' | 'medium' | 'low';
  file: string;
  line: number;
  routerSymbol?: TsMorphSymbol | undefined;
  routerVarName: string;
  middlewareArgs: Node[];
  handlerArg?: Node | undefined;
  order: number;
  callNode: CallExpression;
}

export interface ExtractedUse {
  routerSymbol?: TsMorphSymbol | undefined;
  routerVarName: string;
  rawPath?: string | undefined;
  isDynamicPath: boolean;
  confidence: 'high' | 'medium' | 'low';
  args: Node[];
  file: string;
  line: number;
  order: number;
  callNode: CallExpression;
}

export interface FileRoutesResult {
  file: string;
  routes: ExtractedRoute[];
  uses: ExtractedUse[];
}

/**
 * Check if an AST argument represents a route/mount path.
 */
export function isPathArg(node: Node): boolean {
  if (
    Node.isStringLiteral(node) ||
    Node.isNoSubstitutionTemplateLiteral(node) ||
    Node.isTemplateExpression(node) ||
    Node.isRegularExpressionLiteral(node)
  ) {
    return true;
  }
  if (Node.isArrayLiteralExpression(node)) {
    const elems = node.getElements();
    if (elems.length > 0) {
      const first = elems[0];
      if (first !== undefined && isPathArg(first)) {
        return true;
      }
    }
  }
  return false;
}

/**
 * Extract path string, dynamism, and confidence from an AST node.
 */
export function extractPathFromNode(node: Node): ExtractedPath {
  if (Node.isStringLiteral(node)) {
    return {
      rawPath: node.getLiteralValue(),
      isDynamic: false,
      confidence: 'high',
    };
  }

  if (Node.isNoSubstitutionTemplateLiteral(node)) {
    return {
      rawPath: node.getLiteralText(),
      isDynamic: false,
      confidence: 'high',
    };
  }

  if (Node.isTemplateExpression(node)) {
    let p = node.getHead().getLiteralText();
    for (const span of node.getTemplateSpans()) {
      p += ':dynamic' + span.getLiteral().getLiteralText();
    }
    return {
      rawPath: p,
      isDynamic: true,
      confidence: 'low',
    };
  }

  if (Node.isRegularExpressionLiteral(node) || Node.isArrayLiteralExpression(node)) {
    return {
      rawPath: '<regex>',
      isDynamic: true,
      confidence: 'low',
    };
  }

  return {
    rawPath: ':dynamic',
    isDynamic: true,
    confidence: 'low',
  };
}

/**
 * Recursively flatten nested array arguments.
 */
export function flattenArgs(args: Node[]): Node[] {
  const result: Node[] = [];
  for (const arg of args) {
    if (Node.isArrayLiteralExpression(arg)) {
      result.push(...flattenArgs(arg.getElements()));
    } else {
      result.push(arg);
    }
  }
  return result;
}

interface TrackedReceiver {
  symbol?: TsMorphSymbol | undefined;
  name: string;
  isApp: boolean;
}

/**
 * Find variables holding an Express app or router within a source file.
 */
function findTrackedReceivers(sourceFile: SourceFile): {
  symbols: Map<TsMorphSymbol, TrackedReceiver>;
  names: Map<string, TrackedReceiver>;
} {
  const symbols = new Map<TsMorphSymbol, TrackedReceiver>();
  const names = new Map<string, TrackedReceiver>();

  // 1. Variable declarations
  for (const vd of sourceFile.getVariableDeclarations()) {
    const name = vd.getName();
    const init = vd.getInitializer();
    let isApp = false;
    let isRouter = false;

    if (init && Node.isCallExpression(init)) {
      const expr = init.getExpression();
      const text = expr.getText();
      if (text === 'express' || text.endsWith('.express') || text === 'express()') {
        isApp = true;
      } else if (text === 'Router' || text.endsWith('.Router')) {
        isRouter = true;
      }
    }

    const typeText = vd.getType().getText();
    if (typeText.includes('Express') || typeText.includes('Application')) {
      isApp = true;
    } else if (typeText.includes('Router') || typeText.includes('IRouter')) {
      isRouter = true;
    }

    if (!isApp && !isRouter) {
      if (name === 'app' || name.endsWith('App')) {
        isApp = true;
      } else if (name === 'router' || name.endsWith('Router')) {
        isRouter = true;
      }
    }

    if (isApp || isRouter) {
      const sym = vd.getSymbol();
      const receiver: TrackedReceiver = { symbol: sym, name, isApp };
      if (sym) {
        symbols.set(sym, receiver);
      }
      names.set(name, receiver);
    }
  }

  // 2. Parameters in functions (e.g. registerRoutes(router: Router))
  for (const fn of sourceFile.getFunctions()) {
    for (const param of fn.getParameters()) {
      const name = param.getName();
      const typeText = param.getType().getText();
      if (
        name === 'app' ||
        name === 'router' ||
        typeText.includes('Router') ||
        typeText.includes('Express')
      ) {
        const sym = param.getSymbol();
        const isApp = name === 'app' || typeText.includes('Express');
        const receiver: TrackedReceiver = { symbol: sym, name, isApp };
        if (sym) {
          symbols.set(sym, receiver);
        }
        names.set(name, receiver);
      }
    }
  }

  return { symbols, names };
}

interface RouteBaseInfo {
  routerSymbol?: TsMorphSymbol | undefined;
  routerName: string;
  pathNode: Node;
}

/**
 * Traverse chained calls backwards to find the base router and path of `.route(path)`.
 */
function resolveRouteBase(
  node: Node,
  tracked: {
    symbols: Map<TsMorphSymbol, TrackedReceiver>;
    names: Map<string, TrackedReceiver>;
  },
): RouteBaseInfo | null {
  if (!Node.isCallExpression(node)) return null;
  const expr = node.getExpression();
  if (!Node.isPropertyAccessExpression(expr)) return null;

  const methodName = expr.getName();
  const receiverExpr = expr.getExpression();

  if (methodName === 'route') {
    const sym = receiverExpr.getSymbol();
    const name = receiverExpr.getText();
    const rec = (sym ? tracked.symbols.get(sym) : undefined) ?? tracked.names.get(name);
    const args = node.getArguments();
    const pathArg = args[0];
    if (pathArg) {
      return {
        routerSymbol: rec?.symbol ?? sym,
        routerName: rec?.name ?? name,
        pathNode: pathArg,
      };
    }
    return null;
  }

  if (HTTP_METHODS.includes(methodName.toLowerCase() as HttpMethodLower)) {
    return resolveRouteBase(receiverExpr, tracked);
  }

  return null;
}

interface RawExtractedItem {
  pos: number;
  route?: ExtractedRoute | undefined;
  use?: ExtractedUse | undefined;
}

/**
 * Extract all route and middleware (`use`) registrations from a single source file.
 */
export function extractRoutes(sourceFile: SourceFile): FileRoutesResult {
  const filePath = sourceFile.getFilePath();
  const tracked = findTrackedReceivers(sourceFile);
  const items: RawExtractedItem[] = [];

  for (const call of sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression)) {
    const expr = call.getExpression();
    if (!Node.isPropertyAccessExpression(expr)) continue;

    const methodName = expr.getName().toLowerCase();
    const receiverExpr = expr.getExpression();
    const pos = expr.getNameNode().getStart();
    const line = expr.getNameNode().getStartLineNumber();

    if (methodName === 'use') {
      const sym = receiverExpr.getSymbol();
      const recName = receiverExpr.getText();
      const rec = (sym ? tracked.symbols.get(sym) : undefined) ?? tracked.names.get(recName);

      // Only process use() calls on tracked app/router variables or names
      if (!rec && recName !== 'app' && recName !== 'router' && !recName.endsWith('Router')) {
        continue;
      }

      const rawArgs = call.getArguments();
      if (rawArgs.length === 0) continue;

      let pathInfo: ExtractedPath | undefined = undefined;
      let remainingArgs = rawArgs;

      const firstArg = rawArgs[0];
      if (firstArg !== undefined && isPathArg(firstArg)) {
        pathInfo = extractPathFromNode(firstArg);
        remainingArgs = rawArgs.slice(1);
      }

      const flattened = flattenArgs(remainingArgs);

      items.push({
        pos,
        use: {
          routerSymbol: rec?.symbol ?? sym,
          routerVarName: rec?.name ?? recName,
          rawPath: pathInfo?.rawPath,
          isDynamicPath: pathInfo?.isDynamic ?? false,
          confidence: pathInfo?.confidence ?? 'high',
          args: flattened,
          file: filePath,
          line,
          order: 0, // Will be set after sorting
          callNode: call,
        },
      });
    } else if (HTTP_METHODS.includes(methodName as HttpMethodLower)) {
      const verb = methodName.toUpperCase() as HttpMethod;
      const rawArgs = call.getArguments();

      // Check if this is a chained route: router.route(path).get(...).patch(...)
      const chainedBase = resolveRouteBase(receiverExpr, tracked);
      if (chainedBase) {
        const pathInfo = extractPathFromNode(chainedBase.pathNode);
        const flattened = flattenArgs(rawArgs);
        const handler = flattened.length > 0 ? flattened[flattened.length - 1] : undefined;
        const middleware = flattened.length > 1 ? flattened.slice(0, -1) : [];

        items.push({
          pos,
          route: {
            method: verb,
            rawPath: pathInfo.rawPath,
            confidence: pathInfo.confidence,
            file: filePath,
            line,
            routerSymbol: chainedBase.routerSymbol,
            routerVarName: chainedBase.routerName,
            middlewareArgs: middleware,
            handlerArg: handler,
            order: 0,
            callNode: call,
          },
        });
      } else {
        // Direct verb call: app.get(path, ...middleware, handler)
        const sym = receiverExpr.getSymbol();
        const recName = receiverExpr.getText();
        const rec = (sym ? tracked.symbols.get(sym) : undefined) ?? tracked.names.get(recName);

        if (!rec && recName !== 'app' && recName !== 'router' && !recName.endsWith('Router')) {
          continue;
        }

        if (rawArgs.length === 0) continue;

        const firstArg = rawArgs[0];
        if (firstArg === undefined) continue;

        const pathInfo = extractPathFromNode(firstArg);
        const remainingArgs = rawArgs.slice(1);
        const flattened = flattenArgs(remainingArgs);
        const handler = flattened.length > 0 ? flattened[flattened.length - 1] : undefined;
        const middleware = flattened.length > 1 ? flattened.slice(0, -1) : [];

        items.push({
          pos,
          route: {
            method: verb,
            rawPath: pathInfo.rawPath,
            confidence: pathInfo.confidence,
            file: filePath,
            line,
            routerSymbol: rec?.symbol ?? sym,
            routerVarName: rec?.name ?? recName,
            middlewareArgs: middleware,
            handlerArg: handler,
            order: 0,
            callNode: call,
          },
        });
      }
    }
  }

  // Sort all items strictly by source character offset to guarantee monotonic order
  items.sort((a, b) => a.pos - b.pos);

  const routes: ExtractedRoute[] = [];
  const uses: ExtractedUse[] = [];

  items.forEach((item, index) => {
    const order = index + 1;
    if (item.route) {
      item.route.order = order;
      routes.push(item.route);
    } else if (item.use) {
      item.use.order = order;
      uses.push(item.use);
    }
  });

  return {
    file: filePath,
    routes,
    uses,
  };
}

/**
 * Extract all routes and uses across all non-declaration files in a project.
 */
export function extractRoutesFromProject(project: Project): {
  routes: ExtractedRoute[];
  uses: ExtractedUse[];
  byFile: Map<string, FileRoutesResult>;
} {
  const allRoutes: ExtractedRoute[] = [];
  const allUses: ExtractedUse[] = [];
  const byFile = new Map<string, FileRoutesResult>();

  for (const sourceFile of project.getSourceFiles()) {
    if (sourceFile.isDeclarationFile()) continue;
    const fileResult = extractRoutes(sourceFile);
    byFile.set(sourceFile.getFilePath(), fileResult);
    allRoutes.push(...fileResult.routes);
    allUses.push(...fileResult.uses);
  }

  return {
    routes: allRoutes,
    uses: allUses,
    byFile,
  };
}
