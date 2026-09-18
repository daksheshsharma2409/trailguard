/**
 * AUD002: Audit router mounted without required authentication and role guards.
 *
 * Emitted when an audit router (auditRouter, etc.) is mounted via app.use() / router.use()
 * without both authentication and role authorization middleware in its effective chain.
 *
 * @see context.md §6.10, §7.10
 */

import { Node, SyntaxKind, type CallExpression } from 'ts-morph';
import type { Finding, MiddlewareRef } from '../../core/types.js';
import type { Rule, RuleContext } from '../findings.js';
import { computeRouteFingerprint, resolveEffectiveRisk } from '../findings.js';
import { unwrapExpression } from '../handlers.js';
import { classifyMiddleware } from '../classify.js';
import { isPathArg, extractPathFromNode } from '../routes.js';
import { matchesPrefix, normalizePath } from '../mounts.js';
import type { Config } from '../../config/schema.js';

export function getAuditRouterCall(
  node: Node,
  routerNames: string[],
): CallExpression | undefined {
  const unwrapped = unwrapExpression(node);

  // 1. Direct CallExpression: auditRouter(...)
  if (Node.isCallExpression(unwrapped)) {
    const callee = unwrapped.getExpression();
    const calleeText = callee.getText();
    const calleeName = Node.isPropertyAccessExpression(callee) ? callee.getName() : calleeText;
    if (
      routerNames.includes(calleeName) ||
      routerNames.includes(calleeText) ||
      routerNames.some((rn) => calleeText.endsWith('.' + rn))
    ) {
      return unwrapped;
    }
  }

  // 2. Identifier reference: const audit = auditRouter(...)
  if (Node.isIdentifier(unwrapped)) {
    const defs = unwrapped.getDefinitions();
    for (const def of defs) {
      const decl = def.getDeclarationNode();
      if (decl && Node.isVariableDeclaration(decl)) {
        const init = decl.getInitializer();
        if (init) {
          const res = getAuditRouterCall(init, routerNames);
          if (res) return res;
        }
      }
    }
  }

  return undefined;
}

function classifyGuardNode(guardNode: Node, config: Config): MiddlewareRef[] {
  const unwrapped = unwrapExpression(guardNode);
  if (Node.isArrayLiteralExpression(unwrapped)) {
    return unwrapped.getElements().flatMap((el) => classifyGuardNode(el, config));
  }
  if (Node.isIdentifier(unwrapped)) {
    const defs = unwrapped.getDefinitions();
    for (const def of defs) {
      const decl = def.getDeclarationNode();
      if (decl && Node.isVariableDeclaration(decl)) {
        const init = decl.getInitializer();
        if (init) {
          const initUnwrapped = unwrapExpression(init);
          if (Node.isArrayLiteralExpression(initUnwrapped)) {
            return classifyGuardNode(initUnwrapped, config);
          }
        }
      }
    }
  }
  return classifyMiddleware(unwrapped, config);
}

export const aud002: Rule = {
  id: 'AUD002',
  title: 'Audit router mounted without auth and role guards',
  defaultRisk: 'high',

  run(ctx: RuleContext): Finding[] {
    const risk = resolveEffectiveRisk(aud002.id, aud002.defaultRisk, ctx.config.rules);
    if (risk === 'off') return [];

    const routerNames = ctx.config.audit.routerNames;
    if (routerNames.length === 0) return [];

    if (!ctx.project) return [];

    const findings: Finding[] = [];
    const sourceFiles = ctx.project.getSourceFiles();

    for (const sf of sourceFiles) {
      if (sf.isDeclarationFile()) continue;
      const filePath = sf.getFilePath();
      if (filePath.includes('node_modules')) continue;

      const callExpressions = sf.getDescendantsOfKind(SyntaxKind.CallExpression);

      for (const callExpr of callExpressions) {
        const expr = unwrapExpression(callExpr.getExpression());
        if (!Node.isPropertyAccessExpression(expr)) continue;

        const methodName = expr.getName();
        if (methodName !== 'use') continue;

        const routerVar = expr.getExpression().getText().trim();
        const args = callExpr.getArguments();
        if (args.length === 0) continue;

        let mountPath = '/';
        let mwStartIndex = 0;

        const firstArg = args[0];
        if (firstArg && isPathArg(firstArg)) {
          mountPath = extractPathFromNode(firstArg).rawPath;
          mwStartIndex = 1;
        }

        // Look for auditRouter in args starting from mwStartIndex
        for (let i = mwStartIndex; i < args.length; i++) {
          const arg = args[i];
          if (!arg) continue;

          const auditRouterCall = getAuditRouterCall(arg, routerNames);
          if (!auditRouterCall) continue;

          // Found an auditRouter mount! Collect its effective middleware chain.
          const effectiveChain: MiddlewareRef[] = [];

          // 1. Preceding middleware in the same use() call
          const precedingArgsInCall = args.slice(mwStartIndex, i);
          for (const pArg of precedingArgsInCall) {
            effectiveChain.push(...classifyMiddleware(pArg, ctx.config));
          }

          // 2. Preceding use() calls in the same file on the same router
          for (const prevCall of callExpressions) {
            if (prevCall === callExpr) break; // Only consider calls before this one
            const prevExpr = unwrapExpression(prevCall.getExpression());
            if (!Node.isPropertyAccessExpression(prevExpr) || prevExpr.getName() !== 'use') {
              continue;
            }
            if (prevExpr.getExpression().getText().trim() !== routerVar) {
              continue;
            }

            const prevArgs = prevCall.getArguments();
            if (prevArgs.length === 0) continue;

            let prevPath = '/';
            let prevMwStart = 0;
            const prevFirstArg = prevArgs[0];
            if (prevFirstArg && isPathArg(prevFirstArg)) {
              prevPath = extractPathFromNode(prevFirstArg).rawPath;
              prevMwStart = 1;
            }

            if (matchesPrefix(mountPath, prevPath)) {
              for (let j = prevMwStart; j < prevArgs.length; j++) {
                const prevMw = prevArgs[j];
                if (prevMw && !getAuditRouterCall(prevMw, routerNames)) {
                  effectiveChain.push(...classifyMiddleware(prevMw, ctx.config));
                }
              }
            }
          }

          // 3. Guard option inside auditRouter({ guard: ... })
          const auditArgs = auditRouterCall.getArguments();
          if (auditArgs.length > 0) {
            const firstAuditArg = auditArgs[0];
            let optNode = firstAuditArg ? unwrapExpression(firstAuditArg) : undefined;
            if (optNode && Node.isIdentifier(optNode)) {
              const defs = optNode.getDefinitions();
              for (const def of defs) {
                const decl = def.getDeclarationNode();
                if (decl && Node.isVariableDeclaration(decl)) {
                  const init = decl.getInitializer();
                  if (init) {
                    optNode = unwrapExpression(init);
                    break;
                  }
                }
              }
            }

            if (optNode && Node.isObjectLiteralExpression(optNode)) {
              const guardProp = optNode.getProperty('guard');
              if (guardProp && Node.isPropertyAssignment(guardProp)) {
                const guardVal = guardProp.getInitializer();
                if (guardVal) {
                  effectiveChain.push(...classifyGuardNode(guardVal, ctx.config));
                }
              }
            }
          }

          // Check if effective chain has both auth and role
          const hasAuth = effectiveChain.some((m) => m.class.kind === 'auth');
          const hasRole = effectiveChain.some((m) => m.class.kind === 'role');

          if (!hasAuth || !hasRole) {
            const normPath = normalizePath(mountPath);
            findings.push({
              ruleId: aud002.id,
              risk,
              confidence: 'high',
              message: `Audit router mounted at '${normPath}' requires both authentication and role middleware in its effective chain.`,
              file: sf.getFilePath(),
              line: callExpr.getStartLineNumber(),
              route: {
                method: 'USE',
                path: normPath,
              },
              fingerprint: computeRouteFingerprint(aud002.id, 'USE', normPath),
            });
          }
        }
      }
    }

    return findings;
  },
};
