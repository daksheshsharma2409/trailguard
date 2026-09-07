/**
 * RBAC005: Update/delete route without ownership check on model with owner field.
 *
 * Emitted when an update or delete route targets a model possessing owner fields,
 * but no ownership verification was detected in the handler.
 *
 * @see context.md §6.10
 */

import type { Finding, HttpMethod } from '../../core/types.js';
import type { Rule, RuleContext } from '../findings.js';
import { computeRouteFingerprint, resolveEffectiveRisk } from '../findings.js';

const RECORD_MODIFYING_METHODS: HttpMethod[] = ['PUT', 'PATCH', 'DELETE'];

export const rbac005: Rule = {
  id: 'RBAC005',
  title: 'Update/delete route without ownership check on model with owner field',
  defaultRisk: 'medium',

  run(ctx: RuleContext): Finding[] {
    const risk = resolveEffectiveRisk(rbac005.id, rbac005.defaultRisk, ctx.config.rules);
    if (risk === 'off') return [];

    const findings: Finding[] = [];

    for (const route of ctx.routes) {
      if (!RECORD_MODIFYING_METHODS.includes(route.method)) {
        continue;
      }

      const modelName = route.resource?.model;
      if (!modelName) {
        continue;
      }

      const model = ctx.prismaSchema.get(modelName);
      const ownerFields = model?.ownerFields ?? [];
      if (ownerFields.length === 0) {
        continue;
      }

      // Check if ownership is probable
      if (route.ownership !== 'probable') {
        findings.push({
          ruleId: rbac005.id,
          risk,
          confidence: 'medium',
          message: `Route ${route.method} ${route.path} modifies model '${modelName}' which has owner fields (${ownerFields.join(', ')}), but no ownership validation was detected.`,
          file: route.file,
          line: route.line,
          route: {
            method: route.method,
            path: route.path,
            handler: route.handler?.name,
          },
          resource: route.resource,
          fingerprint: computeRouteFingerprint(rbac005.id, route.method, route.path),
        });
      }
    }

    return findings;
  },
};
