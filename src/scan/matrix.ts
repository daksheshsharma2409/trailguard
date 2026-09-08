/**
 * Matrix derivation from route nodes and resources.
 *
 * Maps HTTP verbs to actions (create, read, update, delete) and computes the union
 * of access policies (anonymous, any-authenticated, roles, ownership, uncertainty)
 * per (resource, action) cell.
 *
 * @see context.md §6.9
 */

import type { Action, MatrixCell, RouteNode } from '../core/types.js';

export const MATRIX_DISCLAIMER =
  'This matrix is derived statically from middleware declarations. It does not execute your handlers.' as const;

export const MATRIX_ACTIONS: readonly Action[] = ['create', 'read', 'update', 'delete'] as const;

/**
 * Map an HTTP method / verb to CRUD actions.
 *
 * GET/HEAD → read
 * POST → create
 * PUT/PATCH → update
 * DELETE → delete
 * all → [create, read, update, delete]
 * OPTIONS / others → []
 */
export function methodToActions(method: string): Action[] {
  switch (method.toLowerCase()) {
    case 'get':
    case 'head':
      return ['read'];
    case 'post':
      return ['create'];
    case 'put':
    case 'patch':
      return ['update'];
    case 'delete':
      return ['delete'];
    case 'all':
      return ['create', 'read', 'update', 'delete'];
    case 'options':
    default:
      return [];
  }
}

/**
 * Derive the RBAC access matrix across resources and actions.
 *
 * @param routes - Composed, classified route nodes.
 * @param models - Optional list of model/resource names to include in the matrix.
 */
export function deriveMatrix(
  routes: RouteNode[],
  models: string[] = [],
): MatrixCell[] {
  // Collect all unique resources from models and routes
  const resourceSet = new Set<string>(models);
  for (const r of routes) {
    if (r.resource?.model) {
      resourceSet.add(r.resource.model);
    }
  }

  const sortedResources = Array.from(resourceSet).sort((a, b) => a.localeCompare(b));
  const matrix: MatrixCell[] = [];

  for (const resource of sortedResources) {
    for (const action of MATRIX_ACTIONS) {
      const contributingRoutes = routes.filter((r) => {
        if (r.resource?.model !== resource) {
          return false;
        }
        const actions = methodToActions(r.method);
        return actions.includes(action);
      });

      if (contributingRoutes.length === 0) {
        matrix.push({
          resource,
          action,
          anonymous: false,
          anyAuthenticated: false,
          roles: [],
          own: false,
          uncertain: false,
        });
        continue;
      }

      // Anonymous: at least one contributing route has NO auth middleware
      const anonymous = contributingRoutes.some(
        (r) => !r.chain.some((m) => m.class.kind === 'auth'),
      );

      // Any-authenticated: at least one contributing route has auth BUT no role
      const anyAuthenticated = contributingRoutes.some((r) => {
        const hasAuth = r.chain.some((m) => m.class.kind === 'auth');
        const hasRole = r.chain.some((m) => m.class.kind === 'role');
        return hasAuth && !hasRole;
      });

      // Roles: union of all named roles across contributing routes
      const rolesSet = new Set<string>();
      for (const r of contributingRoutes) {
        for (const m of r.chain) {
          if (m.class.kind === 'role' && m.class.value !== 'unknown') {
            rolesSet.add(m.class.value);
          }
        }
      }
      const roles = Array.from(rolesSet).sort((a, b) => a.localeCompare(b));

      // Own: at least one contributing route has ownership === 'probable'
      const own = contributingRoutes.some((r) => r.ownership === 'probable');

      // Uncertain: any low confidence, unknown middleware, unknown ownership, or unknown role
      const uncertain = contributingRoutes.some((r) => {
        if (r.confidence === 'low') return true;
        if (r.ownership === 'unknown') return true;
        if (
          r.chain.some(
            (m) =>
              m.class.kind === 'unknown' ||
              (m.class.kind === 'role' && m.class.value === 'unknown'),
          )
        ) {
          return true;
        }
        return false;
      });

      matrix.push({
        resource,
        action,
        anonymous,
        anyAuthenticated,
        roles,
        own,
        uncertain,
      });
    }
  }

  return matrix;
}
