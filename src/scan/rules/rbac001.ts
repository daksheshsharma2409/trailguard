/**
 * RBAC001: Mutating route without authentication.
 *
 * Emitted when a state-changing route (POST/PUT/PATCH/DELETE/ALL) has no
 * authentication middleware in its effective chain.
 *
 * @see context.md §6.10
 */

import type { Finding, HttpMethod } from '../../core/types.js';
import type { Rule, RuleContext } from '../findings.js';
import { computeRouteFingerprint, resolveEffectiveRisk } from '../findings.js';

const MUTATING_METHODS: HttpMethod[] = ['POST', 'PUT', 'PATCH', 'DELETE', 'ALL'];

export const rbac001: Rule = {
  id: 'RBAC001',
  title: 'Mutating route without authentication',
  defaultRisk: 'high',

  run(ctx: RuleContext): Finding[] {
    const risk = resolveEffectiveRisk(rbac001.id, rbac001.defaultRisk, ctx.config.rules);
    if (risk === 'off') return [];

    const findings: Finding[] = [];

    for (const route of ctx.routes) {
      if (!MUTATING_METHODS.includes(route.method)) {
        continue;
      }

      const hasAuth = route.chain.some((m) => m.class.kind === 'auth');
      if (!hasAuth) {
        findings.push({
          ruleId: rbac001.id,
          risk,
          confidence: route.confidence,
          message: `Mutating route ${route.method} ${route.path} has no authentication middleware in its effective chain.`,
          file: route.file,
          line: route.line,
          route: {
            method: route.method,
            path: route.path,
            handler: route.handler?.name,
          },
          resource: route.resource,
          fingerprint: computeRouteFingerprint(rbac001.id, route.method, route.path),
        });
      }
    }

    return findings;
  },
};
