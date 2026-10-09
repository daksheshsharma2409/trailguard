/**
 * Rule registry and runner for static analysis.
 *
 * @see context.md §6.10
 */

import type { Finding } from '../../core/types.js';
import type { Rule, RuleContext } from '../findings.js';
import { rbac001 } from './rbac001.js';
import { rbac002 } from './rbac002.js';
import { rbac003 } from './rbac003.js';
import { rbac004 } from './rbac004.js';
import { rbac005 } from './rbac005.js';
import { rbac006 } from './rbac006.js';
import { rbac007 } from './rbac007.js';
import { rbac008 } from './rbac008.js';
import { aud001 } from './aud001.js';
import { aud002 } from './aud002.js';

export { rbac001 } from './rbac001.js';
export { rbac002 } from './rbac002.js';
export { rbac003 } from './rbac003.js';
export { rbac004 } from './rbac004.js';
export { rbac005 } from './rbac005.js';
export { rbac006 } from './rbac006.js';
export { rbac007 } from './rbac007.js';
export { rbac008 } from './rbac008.js';
export { aud001 } from './aud001.js';
export { aud002 } from './aud002.js';

/**
 * Standard rules enabled by default in Trailguard static scanner.
 */
export const DEFAULT_RULES: Rule[] = [
  rbac001,
  rbac002,
  rbac003,
  rbac004,
  rbac005,
  rbac006,
  rbac007,
  rbac008,
  aud001,
  aud002,
];

/**
 * Run rules over the static analysis context and collect findings.
 *
 * Enforces rule precedence (RBAC001 suppresses RBAC002 on the same route).
 */
export function runRules(
  ctx: RuleContext,
  rules: Rule[] = DEFAULT_RULES,
): Finding[] {
  const allFindings: Finding[] = [];

  for (const rule of rules) {
    const findings = rule.run(ctx);
    allFindings.push(...findings);
  }

  // Enforce precedence: if RBAC001 is present for a route, suppress RBAC002
  const rbac001Routes = new Set<string>();
  for (const f of allFindings) {
    if (f.ruleId === 'RBAC001' && f.route) {
      rbac001Routes.add(`${f.route.method}:${f.route.path}`);
    }
  }

  return allFindings.filter((f) => {
    if (f.ruleId === 'RBAC002' && f.route) {
      const key = `${f.route.method}:${f.route.path}`;
      if (rbac001Routes.has(key)) {
        return false;
      }
    }
    return true;
  });
}
