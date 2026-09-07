/**
 * RBAC007: Dynamically mounted path or low-confidence route.
 *
 * Emitted when a route was mounted dynamically, contains non-literal template
 * expressions, or used regex paths, preventing full static guarantees.
 *
 * @see context.md §6.10
 */

import type { Finding } from '../../core/types.js';
import type { Rule, RuleContext } from '../findings.js';
import { computeRouteFingerprint, resolveEffectiveRisk } from '../findings.js';

export const rbac007: Rule = {
  id: 'RBAC007',
  title: 'Dynamically mounted path or low-confidence route',
  defaultRisk: 'low',

  run(ctx: RuleContext): Finding[] {
    const risk = resolveEffectiveRisk(rbac007.id, rbac007.defaultRisk, ctx.config.rules);
    if (risk === 'off') return [];

    const findings: Finding[] = [];

    for (const route of ctx.routes) {
      if (route.confidence === 'low') {
        findings.push({
          ruleId: rbac007.id,
          risk,
          confidence: 'low',
          message: `Route ${route.method} ${route.path} was mounted dynamically or with regex; static analysis cannot guarantee complete route coverage.`,
          file: route.file,
          line: route.line,
          route: {
            method: route.method,
            path: route.path,
            handler: route.handler?.name,
          },
          resource: route.resource,
          fingerprint: computeRouteFingerprint(rbac007.id, route.method, route.path),
        });
      }
    }

    return findings;
  },
};
