/**
 * Middleware classification for Express static analysis.
 *
 * Classifies Express middleware references into auth, role, ownership,
 * neutral, or unknown based on configuration and AST analysis.
 *
 * @see context.md §6.4
 */

import { Node } from 'ts-morph';
import type { MiddlewareRef } from '../core/types.js';
import type { Config } from '../config/schema.js';
import { unwrapExpression } from './handlers.js';

// ── Known Neutral Middleware ────────────────────────────────────────────────

export const KNOWN_NEUTRAL_MIDDLEWARE = [
  'express.json',
  'json',
  'express.urlencoded',
  'urlencoded',
  'express.static',
  'static',
  'cors',
  'helmet',
  'morgan',
  'compression',
  'cookieParser',
  'cookie-parser',
] as const;

/**
 * Check if a reference or callee matches known framework boilerplate/noise middleware.
 */
export function isNeutralMiddleware(target: string): boolean {
  const clean = target.replace(/\(.*\)$/, '').trim();
  for (const item of KNOWN_NEUTRAL_MIDDLEWARE) {
    if (clean === item || clean.endsWith('.' + item)) {
      return true;
    }
  }
  return false;
}

// ── Role Arg Extraction ─────────────────────────────────────────────────────

export interface RoleExtractionResult {
  literals: string[];
  hasNonLiteral: boolean;
}

/**
 * Extract role strings from a role middleware call expression according to configured extractor.
 */
function extractFirstStringArg(args: Node[]): RoleExtractionResult {
  const first = args[0];
  if (!first) return { literals: [], hasNonLiteral: true };
  const unwrapped = unwrapExpression(first);
  if (Node.isStringLiteral(unwrapped)) {
    return { literals: [unwrapped.getLiteralValue()], hasNonLiteral: false };
  }
  if (Node.isNoSubstitutionTemplateLiteral(unwrapped)) {
    return { literals: [unwrapped.getLiteralText()], hasNonLiteral: false };
  }
  return { literals: [], hasNonLiteral: true };
}

function extractAllStringArgs(args: Node[]): RoleExtractionResult {
  const literals: string[] = [];
  let hasNonLiteral = false;
  for (const rawArg of args) {
    const arg = unwrapExpression(rawArg);
    if (Node.isStringLiteral(arg)) {
      literals.push(arg.getLiteralValue());
    } else if (Node.isNoSubstitutionTemplateLiteral(arg)) {
      literals.push(arg.getLiteralText());
    } else {
      hasNonLiteral = true;
    }
  }
  return { literals, hasNonLiteral: hasNonLiteral || literals.length === 0 };
}

function extractArrayArg(args: Node[]): RoleExtractionResult {
  const first = args[0];
  if (!first) return { literals: [], hasNonLiteral: true };
  const unwrapped = unwrapExpression(first);
  if (!Node.isArrayLiteralExpression(unwrapped)) {
    return { literals: [], hasNonLiteral: true };
  }
  const elements = unwrapped.getElements();
  if (elements.length === 0) {
    return { literals: [], hasNonLiteral: true };
  }
  const literals: string[] = [];
  let hasNonLiteral = false;
  for (const rawElem of elements) {
    const elem = unwrapExpression(rawElem);
    if (Node.isStringLiteral(elem)) {
      literals.push(elem.getLiteralValue());
    } else if (Node.isNoSubstitutionTemplateLiteral(elem)) {
      literals.push(elem.getLiteralText());
    } else {
      hasNonLiteral = true;
    }
  }
  return { literals, hasNonLiteral: hasNonLiteral || literals.length === 0 };
}

export function extractRoleArgs(
  callNode: Node,
  extractor: 'firstStringArg' | 'allStringArgs' | 'arrayArg',
): RoleExtractionResult {
  if (!Node.isCallExpression(callNode)) {
    return { literals: [], hasNonLiteral: true };
  }

  const args = callNode.getArguments();
  if (args.length === 0) {
    return { literals: [], hasNonLiteral: true };
  }

  switch (extractor) {
    case 'firstStringArg':
      return extractFirstStringArg(args);
    case 'allStringArgs':
      return extractAllStringArgs(args);
    case 'arrayArg':
      return extractArrayArg(args);
  }
}

// ── Inline Function Analysis ────────────────────────────────────────────────

const ROLE_BODY_PATTERN = /\b(req\.)?user(\?)?\.role\b/;

/**
 * Check if an inline function body mentions user role checks.
 */
export function mentionsUserRole(node: Node): boolean {
  if (Node.isArrowFunction(node) || Node.isFunctionExpression(node)) {
    return ROLE_BODY_PATTERN.test(node.getBody().getText());
  }
  return false;
}

// ── Classification Config Type ──────────────────────────────────────────────

export type ClassificationConfig = Pick<Config, 'auth' | 'roles' | 'ownership'>;

// ── Main Classifier ─────────────────────────────────────────────────────────

/**
 * Classify a middleware AST node into one or more MiddlewareRef records.
 *
 * Handles identifiers, property access, call expressions with role extractors,
 * inline functions with body inspection, and neutral library middleware.
 *
 * Unknown middleware is never classified as auth or role.
 */
export function classifyMiddleware(
  rawNode: Node,
  config: ClassificationConfig,
): MiddlewareRef[] {
  const node = unwrapExpression(rawNode);
  const text = node.getText();
  const file = node.getSourceFile().getFilePath();
  const line = node.getStartLineNumber();

  // 1. Inline ArrowFunction or FunctionExpression
  if (Node.isArrowFunction(node) || Node.isFunctionExpression(node)) {
    if (mentionsUserRole(node)) {
      return [
        {
          text,
          name: '(inline)',
          args: [],
          class: { kind: 'role', value: 'unknown' },
          file,
          line,
        },
      ];
    }
    return [
      {
        text,
        name: '(inline)',
        args: [],
        class: { kind: 'unknown' },
        file,
        line,
      },
    ];
  }

  // 2. Determine reference name and callee
  let name = text;
  let callee = text;

  if (Node.isIdentifier(node) || Node.isPropertyAccessExpression(node)) {
    name = node.getText();
    callee = name;
  } else if (Node.isCallExpression(node)) {
    callee = node.getExpression().getText();
    name = callee;
  }

  // Strip trailing parens if any for comparison
  const baseName = name.replace(/\(.*\)$/, '').trim();
  const baseCallee = callee.replace(/\(.*\)$/, '').trim();

  // 3. Table-driven classification:
  // (a) name ∈ auth.middleware
  if (
    config.auth.middleware.includes(name) ||
    config.auth.middleware.includes(baseName) ||
    config.auth.middleware.includes(callee) ||
    config.auth.middleware.includes(baseCallee)
  ) {
    return [
      {
        text,
        name,
        args: [],
        class: { kind: 'auth' },
        file,
        line,
      },
    ];
  }

  // (b) callee ∈ roles.middleware
  if (
    config.roles.middleware.includes(callee) ||
    config.roles.middleware.includes(baseCallee) ||
    config.roles.middleware.includes(name) ||
    config.roles.middleware.includes(baseName)
  ) {
    if (Node.isCallExpression(node)) {
      const extraction = extractRoleArgs(node, config.roles.extractor);
      if (extraction.hasNonLiteral || extraction.literals.length === 0) {
        return [
          {
            text,
            name,
            args: extraction.literals,
            class: { kind: 'role', value: 'unknown' },
            file,
            line,
          },
        ];
      }

      // One entry per extracted literal
      return extraction.literals.map((lit) => ({
        text,
        name,
        args: extraction.literals,
        class: { kind: 'role', value: lit },
        file,
        line,
      }));
    }

    // Role middleware referenced but not called
    return [
      {
        text,
        name,
        args: [],
        class: { kind: 'role', value: 'unknown' },
        file,
        line,
      },
    ];
  }

  // (c) name ∈ ownership.middleware
  if (
    config.ownership.middleware.includes(name) ||
    config.ownership.middleware.includes(baseName) ||
    config.ownership.middleware.includes(callee) ||
    config.ownership.middleware.includes(baseCallee)
  ) {
    return [
      {
        text,
        name,
        args: [],
        class: { kind: 'ownership' },
        file,
        line,
      },
    ];
  }

  // (d) Known neutral middleware (express.json, cors, helmet, etc.)
  if (isNeutralMiddleware(baseCallee) || isNeutralMiddleware(baseName)) {
    return [
      {
        text,
        name,
        args: [],
        class: { kind: 'neutral' },
        file,
        line,
      },
    ];
  }

  // (e) Fallback to unknown
  return [
    {
      text,
      name,
      args: [],
      class: { kind: 'unknown' },
      file,
      line,
    },
  ];
}

/**
 * Classify a single middleware node, returning the primary MiddlewareRef.
 */
export function classifySingleMiddleware(
  rawNode: Node,
  config: ClassificationConfig,
): MiddlewareRef {
  const refs = classifyMiddleware(rawNode, config);
  const first = refs[0];
  if (first) return first;
  return {
    text: rawNode.getText(),
    name: rawNode.getText(),
    args: [],
    class: { kind: 'unknown' },
    file: rawNode.getSourceFile().getFilePath(),
    line: rawNode.getStartLineNumber(),
  };
}
