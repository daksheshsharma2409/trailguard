/**
 * RBAC004: Unknown role reference.
 *
 * Emitted when role middleware references a role name that is not declared
 * in the configured known roles universe (`roles.known`).
 *
 * @see context.md §6.10
 */

import type { Finding } from '../../core/types.js';
import type { Rule, RuleContext } from '../findings.js';
import { computeRouteFingerprint, resolveEffectiveRisk } from '../findings.js';

export const rbac004: Rule = {
  id: 'RBAC004',
  title: 'Unknown role reference',
  defaultRisk: 'medium',

  run(ctx: RuleContext): Finding[] {
    const risk = resolveEffectiveRisk(rbac004.id, rbac004.defaultRisk, ctx.config.rules);
    if (risk === 'off') return [];

    const knownRoles = ctx.config.roles.known;
    if (knownRoles.length === 0) {
      return [];
    }

    const knownSet = new Set(knownRoles);
    const findings: Finding[] = [];

    for (const route of ctx.routes) {
      const seenUnknownRoles = new Set<string>();

      for (const mw of route.chain) {
        if (mw.class.kind === 'role') {
          const roleValue = mw.class.value;
          if (roleValue !== 'unknown' && !knownSet.has(roleValue) && !seenUnknownRoles.has(roleValue)) {
            seenUnknownRoles.add(roleValue);

            findings.push({
              ruleId: rbac004.id,
              risk,
              confidence: 'high',
              message: `Route ${route.method} ${route.path} references role '${roleValue}' which is not in configured known roles (${knownRoles.join(', ')}).`,
              file: mw.file || route.file,
              line: mw.line || route.line,
              route: {
                method: route.method,
                path: route.path,
                handler: route.handler?.name,
              },
              resource: route.resource,
              fingerprint: computeRouteFingerprint(rbac004.id, route.method, route.path),
            });
          }
        }
      }
    }

    return findings;
  },
};
