/**
 * AUD003: Raw SQL write when audited models exist.
 *
 * Emitted when raw SQL write operations ($executeRaw, $executeRawUnsafe,
 * $queryRaw, $queryRawUnsafe matching mutating keywords) are performed
 * when audited models are configured.
 *
 * @see context.md §6.8, §6.10, §6.11
 */

import * as path from 'node:path';
import type { Finding } from '../../core/types.js';
import type { Rule, RuleContext } from '../findings.js';
import { computeWriteFingerprint, resolveEffectiveRisk } from '../findings.js';
import { findPrismaWrites } from '../prisma-writes.js';

export const aud003: Rule = {
  id: 'AUD003',
  title: 'Raw SQL write when audited models exist',
  defaultRisk: 'medium',

  run(ctx: RuleContext): Finding[] {
    const risk = resolveEffectiveRisk(aud003.id, aud003.defaultRisk, ctx.config.rules);
    if (risk === 'off') return [];

    if (ctx.config.audit.models.length === 0) return [];

    let writesResult = ctx.prismaWrites;
    if (!writesResult && ctx.project) {
      writesResult = findPrismaWrites(ctx.project, ctx.config, ctx.routes);
    }
    if (!writesResult) {
      return [];
    }

    const findings: Finding[] = [];

    for (const write of writesResult.rawSqlWrites) {
      const relFile = (
        path.isAbsolute(write.file) ? path.relative(process.cwd(), write.file) : write.file
      ).replace(/\\/g, '/');

      const routeInfo = write.routeNode
        ? {
            method: write.routeNode.method,
            path: write.routeNode.path,
            handler: write.routeNode.handler?.name,
          }
        : undefined;

      // Check if any audited model is mentioned in the raw SQL statement
      const matchedModel = ctx.config.audit.models.find((m) =>
        new RegExp(`\\b${m}\\b`, 'i').test(write.sql),
      );
      if (!matchedModel) {
        continue;
      }

      findings.push({
        ruleId: aud003.id,
        risk,
        confidence: 'medium',
        message: `Raw SQL write (${write.method}) at ${relFile}:${String(write.line)} bypasses audit logging.`,
        file: write.file,
        line: write.line,
        route: routeInfo,
        resource: matchedModel
          ? {
              model: matchedModel,
              source: 'heuristic',
            }
          : undefined,
        fingerprint: computeWriteFingerprint(aud003.id, relFile, write.method, write.enclosingFunction),
      });
    }

    return findings;
  },
};
