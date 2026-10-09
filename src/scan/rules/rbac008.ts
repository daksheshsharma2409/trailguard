/**
 * RBAC008: Orphan router.
 *
 * Emitted when an Express router file is defined in the source tree but never
 * mounted from any configured entry point.
 *
 * @see context.md §6.3, §6.10
 */

import type { Finding } from '../../core/types.js';
import type { Rule, RuleContext } from '../findings.js';
import { computeRouteFingerprint, resolveEffectiveRisk } from '../findings.js';

export const rbac008: Rule = {
  id: 'RBAC008',
  title: 'Orphan router never mounted from configured entry',
  defaultRisk: 'low',

  run(ctx: RuleContext): Finding[] {
    const risk = resolveEffectiveRisk(rbac008.id, rbac008.defaultRisk, ctx.config.rules);
    if (risk === 'off') return [];

    const findings: Finding[] = [];

    for (const route of ctx.routes) {
      if (route.orphan) {
        findings.push({
          ruleId: rbac008.id,
          risk,
          confidence: 'high',
          message: `Route ${route.method} ${route.path} belongs to an orphan router that is never mounted from any configured entry point.`,
          file: route.file,
          line: route.line,
          route: {
            method: route.method,
            path: route.path,
            handler: route.handler?.name,
          },
          resource: route.resource,
          fingerprint: computeRouteFingerprint(rbac008.id, route.method, route.path),
        });
      }
    }

    return findings;
  },
};
