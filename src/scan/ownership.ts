/**
 * Static ownership heuristic for Express route handlers.
 *
 * Inspects resolved handler bodies for ownership signals (req.user.id, user.id, etc.)
 * appearing within or near a `where` clause or owner field key.
 *
 * Returns 'probable' | 'none' | 'unknown'. Never returns 'verified'.
 *
 * @see context.md §6.7
 */

import { Node, SyntaxKind } from 'ts-morph';
import type { ResolvedHandler } from './handlers.js';
import { DEFAULT_OWNER_FIELDS } from './prisma-schema.js';

export type OwnershipResult = 'probable' | 'none' | 'unknown';

export interface OwnershipOptions {
  signals?: string[] | undefined;
  ownerFields?: string[] | undefined;
}

export const DEFAULT_OWNERSHIP_SIGNALS = [
  'req.user.id',
  'req.user?.id',
  'req.user.userId',
  'user.id',
];

/**
 * Check if a resolved handler demonstrates probable record ownership validation.
 *
 * Returns:
 * - 'probable' if an ownership signal is found within or near a where clause or owner field
 * - 'none' if handler is resolved and has no ownership validation signals
 * - 'unknown' if handler could not be resolved to a declaration body
 */
export function checkOwnershipHeuristic(
  handler: ResolvedHandler | undefined,
  options?: OwnershipOptions,
): OwnershipResult {
  // 1. Unresolvable handler → 'unknown' (never claim 'none')
  if (!handler || !handler.resolved || !handler.bodyNode) {
    return 'unknown';
  }

  const signals = options?.signals ?? DEFAULT_OWNERSHIP_SIGNALS;
  const ownerFields = options?.ownerFields ?? DEFAULT_OWNER_FIELDS;

  const bodyNode = handler.bodyNode;
  const bodyText = bodyNode.getText();

  // Fast path: if no signal is mentioned in the entire body text → 'none'
  const foundSignals = signals.filter((sig) => bodyText.includes(sig));
  if (foundSignals.length === 0) {
    return 'none';
  }

  // 2. AST inspection for signals within an object literal containing 'where' or owner field
  const objectLiterals = bodyNode.getDescendantsOfKind(SyntaxKind.ObjectLiteralExpression);

  for (const obj of objectLiterals) {
    const objText = obj.getText();
    const hasSignal = foundSignals.some((sig) => objText.includes(sig));
    if (!hasSignal) continue;

    // (a) Is this object literal assigned to a 'where' property?
    const parentProp = obj.getParentIfKind(SyntaxKind.PropertyAssignment);
    if (parentProp && parentProp.getName() === 'where') {
      return 'probable';
    }

    // (b) Does this object literal have a 'where' property?
    const whereProp = obj.getProperty('where');
    if (whereProp) {
      const whereText = whereProp.getText();
      if (foundSignals.some((sig) => whereText.includes(sig))) {
        return 'probable';
      }
    }

    // (c) Does this object literal have a property matching one of the owner fields?
    for (const ownerField of ownerFields) {
      const prop = obj.getProperty(ownerField);
      if (prop) {
        return 'probable';
      }
    }
  }

  // 3. Binary expressions comparing an owner field to an ownership signal
  // e.g. `if (post.authorId !== req.user.id)` or `if (req.user.id === item.userId)`
  const binaryExpressions = bodyNode.getDescendantsOfKind(SyntaxKind.BinaryExpression);
  for (const bin of binaryExpressions) {
    const op = bin.getOperatorToken().getText();
    if (op === '===' || op === '!==' || op === '==' || op === '!=') {
      const leftText = bin.getLeft().getText();
      const rightText = bin.getRight().getText();

      const leftHasSignal = foundSignals.some((sig) => leftText.includes(sig));
      const rightHasSignal = foundSignals.some((sig) => rightText.includes(sig));

      const leftHasOwnerField = ownerFields.some((f) => leftText.includes(f));
      const rightHasOwnerField = ownerFields.some((f) => rightText.includes(f));

      if (
        (leftHasSignal && rightHasOwnerField) ||
        (rightHasSignal && leftHasOwnerField)
      ) {
        return 'probable';
      }
    }
  }

  // 4. Statement-level proximity: a statement contains a signal and 'where'
  const statements = Node.isBlock(bodyNode)
    ? bodyNode.getStatements()
    : [bodyNode];

  for (const stmt of statements) {
    const stmtText = stmt.getText();
    const hasSignal = foundSignals.some((sig) => stmtText.includes(sig));
    if (hasSignal && (stmtText.includes('where') || ownerFields.some((f) => stmtText.includes(f)))) {
      // Check that where/ownerField is not just in a comment
      if (/\bwhere\s*:/.test(stmtText) || ownerFields.some((f) => new RegExp(`\\b${f}\\s*:`).test(stmtText))) {
        return 'probable';
      }
    }
  }

  return 'none';
}
