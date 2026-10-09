/**
 * RBAC006: Unrecognized middleware.
 *
 * Emitted when a route's only non-neutral middleware is unknown (it has no
 * verified auth, role, or ownership middleware, but has at least one unknown
 * middleware, ignoring neutral boilerplate like express.json, cors, etc.).
 *
 * @see context.md §6.4, §6.10
 */

import type { Finding } from '../../core/types.js';
import type { Rule, RuleContext } from '../findings.js';
import { computeRouteFingerprint, resolveEffectiveRisk } from '../findings.js';

export const rbac006: Rule = {
  id: 'RBAC006',
  title: 'Route protected only by unrecognized middleware',
  defaultRisk: 'low',

  run(ctx: RuleContext): Finding[] {
    const risk = resolveEffectiveRisk(rbac006.id, rbac006.defaultRisk, ctx.config.rules);
    if (risk === 'off') return [];

    const findings: Finding[] = [];

    for (const route of ctx.routes) {
      const nonNeutral = route.chain.filter((m) => m.class.kind !== 'neutral');
      if (nonNeutral.length > 0 && nonNeutral.every((m) => m.class.kind === 'unknown')) {
        const mwNames = nonNeutral.map((m) => m.name).join(', ');
        const firstMw = nonNeutral[0];

        findings.push({
          ruleId: rbac006.id,
          risk,
          confidence: 'medium',
          message: `Route ${route.method} ${route.path} is protected only by unrecognized middleware (${mwNames}); unknown middleware is never counted as authentication or authorization.`,
          file: firstMw?.file || route.file,
          line: firstMw?.line || route.line,
          route: {
            method: route.method,
            path: route.path,
            handler: route.handler?.name,
          },
          resource: route.resource,
          fingerprint: computeRouteFingerprint(rbac006.id, route.method, route.path),
        });
      }
    }

    return findings;
  },
};
