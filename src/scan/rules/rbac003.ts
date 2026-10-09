/**
 * RBAC003: Unauthenticated read of private resource.
 *
 * Emitted when a GET or HEAD route accesses a private resource (configured in
 * privateResources or possessing owner fields in the Prisma schema) without
 * any authentication middleware in its effective chain.
 *
 * @see context.md §6.10
 */

import type { Finding } from '../../core/types.js';
import type { Rule, RuleContext } from '../findings.js';
import { computeRouteFingerprint, resolveEffectiveRisk } from '../findings.js';

export const rbac003: Rule = {
  id: 'RBAC003',
  title: 'Unauthenticated read of private resource',
  defaultRisk: 'medium',

  run(ctx: RuleContext): Finding[] {
    const risk = resolveEffectiveRisk(rbac003.id, rbac003.defaultRisk, ctx.config.rules);
    if (risk === 'off') return [];

    const findings: Finding[] = [];
    const privateSet = new Set(ctx.config.privateResources);

    for (const route of ctx.routes) {
      if (route.method !== 'GET' && route.method !== 'HEAD') {
        continue;
      }

      const hasAuth = route.chain.some((m) => m.class.kind === 'auth');
      if (hasAuth) {
        continue;
      }

      const modelName = route.resource?.model;
      if (!modelName) {
        continue;
      }

      const isConfiguredPrivate = privateSet.has(modelName);
      const schemaModel = ctx.prismaSchema.get(modelName);
      const hasOwnerFields = (schemaModel?.ownerFields.length ?? 0) > 0;

      if (isConfiguredPrivate || hasOwnerFields) {
        findings.push({
          ruleId: rbac003.id,
          risk,
          confidence: isConfiguredPrivate ? 'high' : 'medium',
          message: `Read route ${route.method} ${route.path} accesses private resource '${modelName}' without authentication.`,
          file: route.file,
          line: route.line,
          route: {
            method: route.method,
            path: route.path,
            handler: route.handler?.name,
          },
          resource: route.resource,
          fingerprint: computeRouteFingerprint(rbac003.id, route.method, route.path),
        });
      }
    }

    return findings;
  },
};
