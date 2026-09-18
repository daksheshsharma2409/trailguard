/**
 * AUD001: Direct Prisma write bypassing audited client.
 *
 * Emitted when direct Prisma write operations (create, update, delete, etc.)
 * are performed on an audited model using a raw client (e.g. prisma, tx)
 * instead of the configured audited client.
 *
 * @see context.md §6.8, §6.10, §6.11
 */

import * as path from 'node:path';
import type { Finding } from '../../core/types.js';
import type { Rule, RuleContext } from '../findings.js';
import { computeWriteFingerprint, resolveEffectiveRisk } from '../findings.js';
import { findPrismaWrites } from '../prisma-writes.js';

export const aud001: Rule = {
  id: 'AUD001',
  title: 'Direct Prisma write bypassing audited client',
  defaultRisk: 'high',

  run(ctx: RuleContext): Finding[] {
    const risk = resolveEffectiveRisk(aud001.id, aud001.defaultRisk, ctx.config.rules);
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

    for (const write of writesResult.modelWrites) {
      const relFile = (
        path.isAbsolute(write.file) ? path.relative(process.cwd(), write.file) : write.file
      ).replace(/\\/g, '/');

      const modelOp = `${write.model}.${write.op}`;
      const routeInfo = write.routeNode
        ? {
            method: write.routeNode.method,
            path: write.routeNode.path,
            handler: write.routeNode.handler?.name,
          }
        : undefined;

      findings.push({
        ruleId: aud001.id,
        risk,
        confidence: 'high',
        message: `Direct Prisma write to ${modelOp} at ${relFile}:${String(write.line)} bypasses the audited client.`,
        file: write.file,
        line: write.line,
        route: routeInfo,
        resource: {
          model: write.model,
          source: 'config',
        },
        fingerprint: computeWriteFingerprint(aud001.id, relFile, modelOp, write.enclosingFunction),
      });
    }

    return findings;
  },
};
