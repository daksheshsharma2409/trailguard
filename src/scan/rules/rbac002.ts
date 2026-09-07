/**
 * RBAC002: Mutating route with auth but no role or ownership check.
 *
 * Emitted when a state-changing route is authenticated, but has neither
 * role restrictions nor record ownership validation.
 *
 * Precedence: A route triggering RBAC001 does not emit RBAC002.
 *
 * @see context.md §6.10
 */

import type { Finding, HttpMethod } from '../../core/types.js';
import type { Rule, RuleContext } from '../findings.js';
import { computeRouteFingerprint, resolveEffectiveRisk } from '../findings.js';

const MUTATING_METHODS: HttpMethod[] = ['POST', 'PUT', 'PATCH', 'DELETE', 'ALL'];

export const rbac002: Rule = {
  id: 'RBAC002',
  title: 'Mutating route with auth but no role or ownership check',
  defaultRisk: 'high',

  run(ctx: RuleContext): Finding[] {
    const risk = resolveEffectiveRisk(rbac002.id, rbac002.defaultRisk, ctx.config.rules);
    if (risk === 'off') return [];

    const findings: Finding[] = [];

    for (const route of ctx.routes) {
      if (!MUTATING_METHODS.includes(route.method)) {
        continue;
      }

      const hasAuth = route.chain.some((m) => m.class.kind === 'auth');
      // Precedence: unauthenticated mutating routes are handled exclusively by RBAC001
      if (!hasAuth) {
        continue;
      }

      const hasRole = route.chain.some((m) => m.class.kind === 'role');
      const hasOwnership = route.ownership === 'probable';

      if (!hasRole && !hasOwnership) {
        findings.push({
          ruleId: rbac002.id,
          risk,
          confidence: route.confidence,
          message: `Mutating route ${route.method} ${route.path} is authenticated but has no role restriction and no record ownership validation.`,
          file: route.file,
          line: route.line,
          route: {
            method: route.method,
            path: route.path,
            handler: route.handler?.name,
          },
          resource: route.resource,
          fingerprint: computeRouteFingerprint(rbac002.id, route.method, route.path),
        });
      }
    }

    return findings;
  },
};
