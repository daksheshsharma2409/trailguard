/**
 * Prisma write discovery and raw SQL detection.
 *
 * Scans ts-morph project source files for direct Prisma write operations
 * on audited models that bypass the configured audited client, as well as
 * raw SQL executions containing mutating keywords.
 *
 * @see context.md §6.8, §6.10
 */

import {
  Node,
  Project,
  SyntaxKind,
  type SourceFile,
} from 'ts-morph';
import type { Config } from '../config/schema.js';
import type { RouteNode } from '../core/types.js';
import { unwrapExpression } from './handlers.js';

export const WRITE_OPS = new Set([
  'create',
  'createMany',
  'update',
  'updateMany',
  'upsert',
  'delete',
  'deleteMany',
]);

export const RAW_SQL_METHODS = new Set([
  '$executeRaw',
  '$executeRawUnsafe',
  '$queryRaw',
  '$queryRawUnsafe',
]);

export const RAW_SQL_WRITE_REGEX = /\b(insert|update|delete|replace|truncate|alter|drop)\b/i;

export interface DiscoveredModelWrite {
  kind: 'model-write';
  file: string;
  line: number;
  receiver: string;
  model: string;
  op: string;
  enclosingFunction?: string | undefined;
  routeNode?: RouteNode | undefined;
}

export interface DiscoveredRawSqlWrite {
  kind: 'raw-sql';
  file: string;
  line: number;
  receiver: string;
  method: string;
  sql: string;
  enclosingFunction?: string | undefined;
  routeNode?: RouteNode | undefined;
}

export type DiscoveredWrite = DiscoveredModelWrite | DiscoveredRawSqlWrite;

export interface PrismaWriteDiscoveryResult {
  writes: DiscoveredWrite[];
  modelWrites: DiscoveredModelWrite[];
  rawSqlWrites: DiscoveredRawSqlWrite[];
}

function toLowerCamel(s: string): string {
  if (!s) return '';
  return s.charAt(0).toLowerCase() + s.slice(1);
}

function isAuditedClient(receiverText: string, clientNames: string[]): boolean {
  if (clientNames.includes(receiverText)) {
    return true;
  }
  const parts = receiverText.split('.');
  const last = parts[parts.length - 1]?.trim();
  if (last && clientNames.includes(last)) {
    return true;
  }
  return false;
}

export function findEnclosingFunctionName(node: Node): string | undefined {
  let curr: Node | undefined = node.getParent();
  while (curr) {
    if (Node.isFunctionDeclaration(curr)) {
      return curr.getName();
    }
    if (Node.isMethodDeclaration(curr)) {
      return curr.getName();
    }
    if (Node.isFunctionExpression(curr)) {
      const name = curr.getName();
      if (name) return name;
      const parent = curr.getParent();
      if (Node.isVariableDeclaration(parent)) {
        return parent.getName();
      }
      if (Node.isPropertyAssignment(parent)) {
        return parent.getName();
      }
    }
    if (Node.isArrowFunction(curr)) {
      const parent = curr.getParent();
      if (Node.isVariableDeclaration(parent)) {
        return parent.getName();
      }
      if (Node.isPropertyAssignment(parent)) {
        return parent.getName();
      }
    }
    curr = curr.getParent();
  }
  return undefined;
}

export function findMatchingRouteNode(
  node: Node,
  routes: RouteNode[] | undefined,
  filePath: string,
  enclosingFn?: string,
): RouteNode | undefined {
  if (!routes || routes.length === 0) {
    return undefined;
  }

  // 1. Direct ancestor: check if an ancestor is an Express route call (app.get, router.post, etc.)
  let curr: Node | undefined = node.getParent();
  while (curr) {
    if (Node.isCallExpression(curr)) {
      const line = curr.getStartLineNumber();
      const match = routes.find((r) => r.file === filePath && r.line === line);
      if (match) {
        return match;
      }
    }
    curr = curr.getParent();
  }

  // 2. Named function match: if write is inside a named handler function
  if (enclosingFn) {
    const match = routes.find(
      (r) =>
        r.handler?.name &&
        (r.handler.name === enclosingFn || r.handler.name.endsWith(`.${enclosingFn}`)) &&
        (r.handler.file === filePath || !r.handler.file),
    );
    if (match) {
      return match;
    }
  }

  return undefined;
}

export function findPrismaWrites(
  target: Project | SourceFile | SourceFile[],
  config: Config,
  routes?: RouteNode[],
): PrismaWriteDiscoveryResult {
  let sourceFiles: SourceFile[];
  if (Array.isArray(target)) {
    sourceFiles = target;
  } else if ('getSourceFiles' in target && typeof target.getSourceFiles === 'function') {
    sourceFiles = target.getSourceFiles();
  } else {
    sourceFiles = [target as SourceFile];
  }

  const auditedModelMap = new Map<string, string>();
  for (const m of config.audit.models) {
    auditedModelMap.set(toLowerCamel(m), m);
    auditedModelMap.set(m.toLowerCase(), m);
    auditedModelMap.set(m, m);
  }

  const modelWrites: DiscoveredModelWrite[] = [];
  const rawSqlWrites: DiscoveredRawSqlWrite[] = [];

  for (const sf of sourceFiles) {
    if (sf.isDeclarationFile()) continue;
    const filePath = sf.getFilePath();
    if (filePath.includes('node_modules')) continue;

    // 1. Model write calls: <receiver>.<modelDelegate>.<op>(...)
    const callExpressions = sf.getDescendantsOfKind(SyntaxKind.CallExpression);
    for (const callExpr of callExpressions) {
      const expr = unwrapExpression(callExpr.getExpression());
      if (Node.isPropertyAccessExpression(expr)) {
        const op = expr.getName();
        if (WRITE_OPS.has(op)) {
          const innerExpr = unwrapExpression(expr.getExpression());
          if (Node.isPropertyAccessExpression(innerExpr)) {
            const delegateName = innerExpr.getName();
            const canonicalModel = auditedModelMap.get(delegateName);
            if (canonicalModel) {
              const receiverNode = unwrapExpression(innerExpr.getExpression());
              const receiverText = receiverNode.getText().trim();
              if (!isAuditedClient(receiverText, config.audit.clientNames)) {
                const line = callExpr.getStartLineNumber();
                const enclosingFunction = findEnclosingFunctionName(callExpr);
                const routeNode = findMatchingRouteNode(callExpr, routes, filePath, enclosingFunction);
                modelWrites.push({
                  kind: 'model-write',
                  file: filePath,
                  line,
                  receiver: receiverText,
                  model: canonicalModel,
                  op,
                  enclosingFunction,
                  routeNode,
                });
              }
            }
          }
        } else if (RAW_SQL_METHODS.has(op)) {
          // Check raw SQL called via CallExpression e.g. prisma.$executeRawUnsafe("UPDATE...")
          const receiverText = expr.getExpression().getText().trim();
          const args = callExpr.getArguments();
          const firstArg = args[0];
          if (firstArg) {
            let sqlText = '';
            if (Node.isStringLiteral(firstArg) || Node.isNoSubstitutionTemplateLiteral(firstArg)) {
              sqlText = firstArg.getLiteralText();
            } else if (Node.isTemplateExpression(firstArg)) {
              sqlText = firstArg.getText();
            } else if (Node.isTaggedTemplateExpression(firstArg)) {
              sqlText = firstArg.getTemplate().getText();
            } else if (Node.isIdentifier(firstArg)) {
              const defs = firstArg.getDefinitions();
              for (const def of defs) {
                const decl = def.getDeclarationNode();
                if (decl && Node.isVariableDeclaration(decl)) {
                  const init = decl.getInitializer();
                  if (init) {
                    sqlText = init.getText();
                    break;
                  }
                }
              }
            }

            if (RAW_SQL_WRITE_REGEX.test(sqlText)) {
              const line = callExpr.getStartLineNumber();
              const enclosingFunction = findEnclosingFunctionName(callExpr);
              const routeNode = findMatchingRouteNode(callExpr, routes, filePath, enclosingFunction);
              rawSqlWrites.push({
                kind: 'raw-sql',
                file: filePath,
                line,
                receiver: receiverText,
                method: op,
                sql: sqlText,
                enclosingFunction,
                routeNode,
              });
            }
          }
        }
      }
    }

    // 2. Raw SQL via TaggedTemplateExpression e.g. prisma.$executeRaw`UPDATE ...`
    const taggedTemplates = sf.getDescendantsOfKind(SyntaxKind.TaggedTemplateExpression);
    for (const tt of taggedTemplates) {
      const tag = unwrapExpression(tt.getTag());
      if (Node.isPropertyAccessExpression(tag)) {
        const methodName = tag.getName();
        if (RAW_SQL_METHODS.has(methodName)) {
          const template = tt.getTemplate();
          const sqlText = template.getText();
          if (RAW_SQL_WRITE_REGEX.test(sqlText)) {
            const receiverText = tag.getExpression().getText().trim();
            const line = tt.getStartLineNumber();
            const enclosingFunction = findEnclosingFunctionName(tt);
            const routeNode = findMatchingRouteNode(tt, routes, filePath, enclosingFunction);
            rawSqlWrites.push({
              kind: 'raw-sql',
              file: filePath,
              line,
              receiver: receiverText,
              method: methodName,
              sql: sqlText,
              enclosingFunction,
              routeNode,
            });
          }
        }
      }
    }
  }

  // Combine and sort writes by file and line
  const allWrites: DiscoveredWrite[] = [...modelWrites, ...rawSqlWrites].sort((a, b) => {
    const fileCmp = a.file.localeCompare(b.file);
    if (fileCmp !== 0) return fileCmp;
    return a.line - b.line;
  });

  return {
    writes: allWrites,
    modelWrites,
    rawSqlWrites,
  };
}
