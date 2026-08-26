/**
 * Express router mount composition and effective middleware chain construction.
 *
 * Traverses router mount hierarchies, performs path normalization, builds
 * the effective middleware chain respecting registration order and path prefixes,
 * detects circular mounts, and flags dynamic mount parameters.
 *
 * @see context.md §6.3
 */

import {
  Node,
  type Symbol as TsMorphSymbol,
  type Project,
} from 'ts-morph';
import type { HttpMethod } from '../core/types.js';
import {
  type ExtractedRoute,
  type ExtractedUse,
  extractRoutesFromProject,
} from './routes.js';
import {
  resolveRouter,
  resolveHandler,
  type ResolvedHandler,
  ResolutionContext,
  getRootSymbol,
} from './handlers.js';

// ── Path Normalization & Prefix Matching ─────────────────────────────────────

/**
 * Join and normalize Express path segments into a canonical URL path.
 *
 * Normalizes repeated slashes, guarantees a leading slash, removes trailing
 * slashes unless the path is root '/', and preserves route parameters (:id).
 */
export function normalizePath(...segments: (string | undefined)[]): string {
  const parts: string[] = [];
  for (const seg of segments) {
    if (seg === undefined) continue;
    const str = seg.trim();
    if (str.length === 0) continue;
    parts.push(str);
  }

  if (parts.length === 0) {
    return '/';
  }

  const raw = parts.join('/');
  let normalized = raw.replace(/\/+/g, '/');
  if (!normalized.startsWith('/')) {
    normalized = '/' + normalized;
  }
  if (normalized.length > 1 && normalized.endsWith('/')) {
    normalized = normalized.slice(0, -1);
  }
  return normalized;
}

/**
 * Check if a middleware `use(path)` prefix matches a target route path.
 *
 * In Express, a path-less middleware matches every path. A path-scoped
 * middleware matches the exact path or any sub-path delimited by a slash.
 */
export function matchesPrefix(routePath: string, usePath?: string): boolean {
  if (usePath === undefined) return true;
  const trimmed = usePath.trim();
  if (trimmed === '' || trimmed === '/') return true;

  const normRoute = normalizePath(routePath);
  const normUse = normalizePath(trimmed);

  if (normRoute === normUse) return true;
  if (normRoute.startsWith(normUse + '/')) return true;
  return false;
}

// ── Types ────────────────────────────────────────────────────────────────────

export interface MountEdge {
  parentKey: string;
  parentName: string;
  parentFile: string;
  childKey: string;
  childName: string;
  mountPath: string;
  mountMiddleware: Node[];
  order: number;
  isDynamic: boolean;
  confidence: 'high' | 'medium' | 'low';
}

export interface RouterInfo {
  key: string;
  name: string;
  file: string;
  isApp: boolean;
  declarationNode?: Node | undefined;
  symbol?: TsMorphSymbol | undefined;
  routes: ExtractedRoute[];
  uses: ExtractedUse[];
  mountEdges: MountEdge[];
}

export interface ComposedRoute {
  method: HttpMethod;
  path: string;
  rawPath: string;
  confidence: 'high' | 'medium' | 'low';
  file: string;
  line: number;
  routerSymbol?: TsMorphSymbol | undefined;
  routerVarName: string;
  middlewareArgs: Node[];
  handlerArg?: Node | undefined;
  resolvedHandler?: ResolvedHandler | undefined;
  orphan: boolean;
  mountChain: MountEdge[];
}

export interface MountGraph {
  routers: Map<string, RouterInfo>;
  roots: string[];
  edges: MountEdge[];
  warnings: string[];
}

export interface MountCompositionResult {
  routes: ComposedRoute[];
  graph: MountGraph;
  warnings: string[];
}

// ── Graph Construction ───────────────────────────────────────────────────────

/**
 * Compute a unique, stable string key for a router or app.
 */
function getRouterKey(
  symbol: TsMorphSymbol | undefined,
  fallbackFile: string,
  fallbackName: string,
  declarationNode?: Node,
): string {
  if (declarationNode) {
    return declarationNode.getSourceFile().getFilePath() + '#' + String(declarationNode.getStart());
  }
  if (symbol) {
    const root = getRootSymbol(symbol);
    const decls = root.getDeclarations();
    const firstDecl = decls[0];
    if (firstDecl) {
      return firstDecl.getSourceFile().getFilePath() + '#' + String(firstDecl.getStart());
    }
  }
  return `${fallbackFile}#${fallbackName}`;
}

/**
 * Build the router mount graph from extracted routes and uses.
 */
export function buildMountGraph(
  routes: ExtractedRoute[],
  uses: ExtractedUse[],
  ctx: ResolutionContext = new ResolutionContext(),
  entryFiles: string[] = [],
): MountGraph {
  const routers = new Map<string, RouterInfo>();
  const edges: MountEdge[] = [];
  const warnings: string[] = [];

  function getOrCreateRouter(
    key: string,
    name: string,
    file: string,
    isApp: boolean,
    symbol?: TsMorphSymbol,
    decl?: Node,
  ): RouterInfo {
    let r = routers.get(key);
    if (!r) {
      r = {
        key,
        name,
        file,
        isApp,
        declarationNode: decl,
        symbol,
        routes: [],
        uses: [],
        mountEdges: [],
      };
      routers.set(key, r);
    } else {
      if (isApp) r.isApp = true;
      if (!r.declarationNode && decl) r.declarationNode = decl;
      if (!r.symbol && symbol) r.symbol = symbol;
    }
    return r;
  }

  // 1. Index routers by extracted routes
  for (const route of routes) {
    const decl = route.routerSymbol
      ? getRootSymbol(route.routerSymbol).getDeclarations()[0]
      : undefined;
    const key = getRouterKey(route.routerSymbol, route.file, route.routerVarName, decl);
    const isApp = route.routerVarName === 'app' || route.routerVarName.endsWith('App');
    const r = getOrCreateRouter(
      key,
      route.routerVarName,
      route.file,
      isApp,
      route.routerSymbol,
      decl,
    );
    r.routes.push(route);
  }

  // 2. Index routers and mounts by extracted uses
  for (const use of uses) {
    const decl = use.routerSymbol
      ? getRootSymbol(use.routerSymbol).getDeclarations()[0]
      : undefined;
    const parentKey = getRouterKey(use.routerSymbol, use.file, use.routerVarName, decl);
    const isApp = use.routerVarName === 'app' || use.routerVarName.endsWith('App');
    const parent = getOrCreateRouter(
      parentKey,
      use.routerVarName,
      use.file,
      isApp,
      use.routerSymbol,
      decl,
    );
    parent.uses.push(use);

    // Check arguments of use() for mounted routers
    const routerArgs: { index: number; resolved: ReturnType<typeof resolveRouter> }[] = [];
    use.args.forEach((arg, index) => {
      const res = resolveRouter(arg, ctx);
      if (res.resolved) {
        routerArgs.push({ index, resolved: res });
      }
    });

    if (routerArgs.length > 0) {
      for (const { index, resolved } of routerArgs) {
        const childDecl = resolved.declarationNode;
        const childKey = getRouterKey(
          resolved.symbol,
          resolved.file ?? use.file,
          resolved.name,
          childDecl,
        );
        const childRouter = getOrCreateRouter(
          childKey,
          resolved.name,
          resolved.file ?? use.file,
          false,
          resolved.symbol,
          childDecl,
        );

        // Middleware passed to this use() before this router argument
        const mountMiddleware = use.args.slice(0, index).filter((a) => {
          const res = resolveRouter(a, ctx);
          return !res.resolved;
        });

        const edge: MountEdge = {
          parentKey: parent.key,
          parentName: parent.name,
          parentFile: parent.file,
          childKey: childRouter.key,
          childName: childRouter.name,
          mountPath: use.rawPath ?? '',
          mountMiddleware,
          order: use.order,
          isDynamic: use.isDynamicPath,
          confidence: use.confidence,
        };

        parent.mountEdges.push(edge);
        edges.push(edge);
      }
    }
  }

  // 3. Determine roots (in-degree 0)
  const childKeys = new Set(edges.map((e) => e.childKey));
  const roots: string[] = [];

  for (const [key, router] of routers.entries()) {
    if (!childKeys.has(key)) {
      if (
        router.isApp ||
        entryFiles.includes(router.file) ||
        router.mountEdges.length > 0 ||
        router.name === 'app'
      ) {
        roots.push(key);
      }
    }
  }

  // Fallback if no explicit roots matched
  if (roots.length === 0) {
    for (const [key] of routers.entries()) {
      if (!childKeys.has(key)) {
        roots.push(key);
      }
    }
  }

  return {
    routers,
    roots,
    edges,
    warnings,
  };
}

// ── Mount Composition ────────────────────────────────────────────────────────

interface PathStep {
  routerKey: string;
  edge?: MountEdge | undefined;
}

/**
 * Compose concrete route nodes from the mount graph.
 */
export function composeMounts(
  input: Project | { routes: ExtractedRoute[]; uses: ExtractedUse[] },
  options: { entryFiles?: string[]; ctx?: ResolutionContext } = {},
): MountCompositionResult {
  const ctx = options.ctx ?? new ResolutionContext();
  let routes: ExtractedRoute[];
  let uses: ExtractedUse[];

  if ('getSourceFiles' in input) {
    const extracted = extractRoutesFromProject(input);
    routes = extracted.routes;
    uses = extracted.uses;
  } else {
    routes = input.routes;
    uses = input.uses;
  }

  const graph = buildMountGraph(routes, uses, ctx, options.entryFiles);
  const composedRoutes: ComposedRoute[] = [];
  const visitedRoutersInTraversal = new Set<string>();

  /**
   * Depth-first traversal along mount edges starting from root applications.
   */
  function traverse(
    currentKey: string,
    ancestorSteps: PathStep[], // ancestors leading to current router
    visitedInBranch: Set<string>,
  ): void {
    visitedRoutersInTraversal.add(currentKey);
    const router = graph.routers.get(currentKey);
    if (!router) return;

    // 1. Compose all direct routes belonging to current router
    for (const route of router.routes) {
      // Build composed path
      const pathSegments: string[] = [];
      for (const step of ancestorSteps) {
        if (step.edge) {
          pathSegments.push(step.edge.mountPath);
        }
      }
      pathSegments.push(route.rawPath);
      const composedPath = normalizePath(...pathSegments);

      // Determine confidence
      let confidence: 'high' | 'medium' | 'low' = route.confidence;
      if (confidence !== 'low') {
        for (const step of ancestorSteps) {
          if (step.edge?.confidence === 'low' || step.edge?.isDynamic) {
            confidence = 'low';
            break;
          } else if (step.edge?.confidence === 'medium') {
            confidence = 'medium';
          }
        }
      }

      // Build effective middleware chain:
      // (a) Ancestor-level use() middleware registered before the mount whose prefix matches
      // (b) Mount-level middleware
      // (c) Router-level use() middleware registered before the route whose prefix matches
      // (d) Route-level middleware args
      const effectiveMiddleware: Node[] = [];

      for (let i = 0; i < ancestorSteps.length; i++) {
        const step = ancestorSteps[i];
        if (!step || !step.edge) continue;

        const ancestorRouter = graph.routers.get(step.routerKey);
        if (ancestorRouter) {
          // Path at ancestor level
          const remainingSegments: string[] = [];
          for (const s of ancestorSteps.slice(i)) {
            if (s.edge) {
              remainingSegments.push(s.edge.mountPath);
            }
          }
          remainingSegments.push(route.rawPath);
          const pathAtAncestor = normalizePath(...remainingSegments);

          // Find ancestor use() registered before mount call
          for (const use of ancestorRouter.uses) {
            if (use.order < step.edge.order) {
              // Ignore use calls that only mounted routers
              const nonRouterArgs = use.args.filter((a) => !resolveRouter(a, ctx).resolved);
              if (nonRouterArgs.length > 0 && matchesPrefix(pathAtAncestor, use.rawPath)) {
                effectiveMiddleware.push(...nonRouterArgs);
              }
            }
          }
        }

        // Add mount middleware
        effectiveMiddleware.push(...step.edge.mountMiddleware);
      }

      // Router-level use() middleware declared before the route
      for (const use of router.uses) {
        if (use.order < route.order) {
          const nonRouterArgs = use.args.filter((a) => !resolveRouter(a, ctx).resolved);
          if (nonRouterArgs.length > 0 && matchesPrefix(route.rawPath, use.rawPath)) {
            effectiveMiddleware.push(...nonRouterArgs);
          }
        }
      }

      // Route's own middleware args
      effectiveMiddleware.push(...route.middlewareArgs);

      // Resolve handler if present
      const resolvedHandler = route.handlerArg
        ? resolveHandler(route.handlerArg, ctx)
        : undefined;

      const mountChain = ancestorSteps
        .map((s) => s.edge)
        .filter((e): e is MountEdge => e !== undefined);

      composedRoutes.push({
        method: route.method,
        path: composedPath,
        rawPath: route.rawPath,
        confidence,
        file: route.file,
        line: route.line,
        routerSymbol: route.routerSymbol,
        routerVarName: route.routerVarName,
        middlewareArgs: effectiveMiddleware,
        handlerArg: route.handlerArg,
        resolvedHandler,
        orphan: false,
        mountChain,
      });
    }

    // 2. Traverse child mounts
    for (const edge of router.mountEdges) {
      if (visitedInBranch.has(edge.childKey)) {
        // Cycle detected!
        const cycleNames = ancestorSteps
          .map((s) => graph.routers.get(s.routerKey)?.name ?? s.routerKey)
          .concat([router.name, edge.childName]);
        const warning = `Router cycle detected: ${cycleNames.join(' -> ')}`;
        graph.warnings.push(warning);
        console.warn(`[trailguard] ${warning}`);

        // Mark any child routes with confidence low
        const childRouter = graph.routers.get(edge.childKey);
        if (childRouter) {
          for (const route of childRouter.routes) {
            composedRoutes.push({
              method: route.method,
              path: normalizePath(edge.mountPath, route.rawPath),
              rawPath: route.rawPath,
              confidence: 'low',
              file: route.file,
              line: route.line,
              routerSymbol: route.routerSymbol,
              routerVarName: route.routerVarName,
              middlewareArgs: [...route.middlewareArgs],
              handlerArg: route.handlerArg,
              resolvedHandler: route.handlerArg ? resolveHandler(route.handlerArg, ctx) : undefined,
              orphan: false,
              mountChain: [edge],
            });
          }
        }
        continue;
      }

      const nextBranch = new Set(visitedInBranch);
      nextBranch.add(edge.childKey);

      const nextSteps: PathStep[] = [
        ...ancestorSteps,
        { routerKey: currentKey, edge },
      ];

      traverse(edge.childKey, nextSteps, nextBranch);
    }
  }

  // Traverse from each identified root
  for (const rootKey of graph.roots) {
    traverse(rootKey, [], new Set([rootKey]));
  }

  // 3. Handle orphan routers (routers never mounted from any root)
  for (const [key, router] of graph.routers.entries()) {
    if (!visitedRoutersInTraversal.has(key)) {
      for (const route of router.routes) {
        const effectiveMiddleware: Node[] = [];
        for (const use of router.uses) {
          if (use.order < route.order) {
            const nonRouterArgs = use.args.filter((a) => !resolveRouter(a, ctx).resolved);
            if (nonRouterArgs.length > 0 && matchesPrefix(route.rawPath, use.rawPath)) {
              effectiveMiddleware.push(...nonRouterArgs);
            }
          }
        }
        effectiveMiddleware.push(...route.middlewareArgs);

        composedRoutes.push({
          method: route.method,
          path: normalizePath(route.rawPath),
          rawPath: route.rawPath,
          confidence: route.confidence,
          file: route.file,
          line: route.line,
          routerSymbol: route.routerSymbol,
          routerVarName: route.routerVarName,
          middlewareArgs: effectiveMiddleware,
          handlerArg: route.handlerArg,
          resolvedHandler: route.handlerArg ? resolveHandler(route.handlerArg, ctx) : undefined,
          orphan: true,
          mountChain: [],
        });
      }
    }
  }

  return {
    routes: composedRoutes,
    graph,
    warnings: graph.warnings,
  };
}
