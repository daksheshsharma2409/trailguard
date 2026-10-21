/**
 * auditRouter — Express router for querying and verifying the audit log.
 *
 * Exposes:
 * - GET /logs: Query logs with filtering and capped pagination.
 * - GET /logs/:seq: Retrieve a single audit log entry.
 * - GET /history/:model/:recordId: Retrieve history for a specific record.
 * - GET /verify: Verify cryptographic integrity of the audit chain.
 *
 * Guard middleware is strictly REQUIRED to prevent unauthorized exposure.
 *
 * @see context.md §7.10
 */

import { Router, type Request, type Response, type NextFunction, type RequestHandler } from 'express';
import { z } from 'zod';
import { MAX_PAGE_SIZE } from '../core/constants.js';
import { AuditConfigError } from '../core/errors.js';
import type { AuditAction, Checkpoint, KeysOptions, KeysShorthand } from '../core/types.js';
import { getHistory, getRestorePreview, type HistoryPrismaClient } from './history.js';
import { verifyAuditChain, type VerifyPrismaClient } from './verify.js';
import { exportAuditLogsToStream, type ExportPrismaClient } from './export.js';

export interface RouterPrismaClient {
  auditLog: {
    findMany: (args: Record<string, unknown>) => Promise<Array<Record<string, unknown>>>;
    findUnique?: (args: { where: { seq: bigint } }) => Promise<Record<string, unknown> | null>;
    count?: (args: Record<string, unknown>) => Promise<number>;
  };
  auditHead?: {
    findUnique?: (args: { where: { id: number } }) => Promise<{ lastSeq: bigint; lastHash: string } | null>;
  };
  $queryRaw?: <T = unknown>(query: TemplateStringsArray, ...values: unknown[]) => Promise<T>;
}

export interface AuditRouterOptions {
  guard: RequestHandler | RequestHandler[];
  prisma: RouterPrismaClient;
  keys: KeysOptions | KeysShorthand;
  models?: string[] | undefined;
  checkpoints?: Checkpoint[] | undefined;
}

const logsQuerySchema = z.object({
  model: z.string().optional(),
  recordId: z.string().optional(),
  actorId: z.string().optional(),
  action: z.enum(['CREATE', 'UPDATE', 'DELETE', 'READ']).optional(),
  from: z
    .string()
    .refine((val) => !isNaN(Date.parse(val)), { message: 'Invalid ISO date string for "from"' })
    .optional(),
  to: z
    .string()
    .refine((val) => !isNaN(Date.parse(val)), { message: 'Invalid ISO date string for "to"' })
    .optional(),
  page: z.coerce.number().int().positive().optional().default(1),
  pageSize: z.coerce.number().int().positive().optional().default(50),
});

function serializeAuditRow(row: Record<string, unknown>): Record<string, unknown> {
  const result: Record<string, unknown> = { ...row };
  if (typeof result['seq'] === 'bigint') {
    result['seq'] = result['seq'].toString();
  }
  return result;
}

function asyncHandler(
  fn: (req: Request, res: Response, next: NextFunction) => Promise<void>,
): RequestHandler {
  return (req, res, next) => {
    void fn(req, res, next).catch(next);
  };
}

/**
 * Creates an Express Router mounted with audit query and verification endpoints.
 *
 * @param options - Router configuration including required guard middleware.
 * @returns Express router instance.
 * @throws {AuditConfigError} If guard is missing or empty.
 */
export function auditRouter(options: AuditRouterOptions): Router {
  const opts = options as Partial<AuditRouterOptions> | null | undefined;

  if (!opts) {
    throw new AuditConfigError('auditRouter options are required');
  }

  const guard = opts.guard;
  if (!guard) {
    throw new AuditConfigError('auditRouter requires guard middleware (none provided)');
  }

  if (Array.isArray(guard) && guard.length === 0) {
    throw new AuditConfigError('auditRouter requires a non-empty guard array');
  }

  const prisma = opts.prisma;
  if (!prisma) {
    throw new AuditConfigError('auditRouter requires a prisma client instance');
  }

  const keys = opts.keys;
  if (!keys) {
    throw new AuditConfigError('auditRouter requires keys configuration');
  }

  const router = Router();
  const guards = Array.isArray(guard) ? guard : [guard];

  for (const g of guards) {
    router.use(g);
  }

  // GET /logs
  router.get(
    '/logs',
    asyncHandler(async (req: Request, res: Response): Promise<void> => {
      const parseResult = logsQuerySchema.safeParse(req.query);
      if (!parseResult.success) {
        res.status(400).json({
          error: 'Invalid query parameters',
          details: parseResult.error.issues,
        });
        return;
      }

      const { model, recordId, actorId, action, from, to, page, pageSize } = parseResult.data;

      if (model && opts.models && opts.models.length > 0) {
        const isKnown = opts.models.some((m) => m.toLowerCase() === model.toLowerCase());
        if (!isKnown) {
          res.status(400).json({
            error: `Unknown model '${model}'. Valid models: ${opts.models.join(', ')}`,
          });
          return;
        }
      }

      const where: Record<string, unknown> = {};
      if (model) where['model'] = model;
      if (recordId) where['recordId'] = recordId;
      if (actorId) where['actorId'] = actorId;
      if (action) where['action'] = action as AuditAction;
      if (from || to) {
        const dateFilter: Record<string, Date> = {};
        if (from) dateFilter['gte'] = new Date(from);
        if (to) dateFilter['lte'] = new Date(to);
        where['createdAt'] = dateFilter;
      }

      const cappedPageSize = Math.min(pageSize, MAX_PAGE_SIZE);
      const currentPage = page;
      const skip = (currentPage - 1) * cappedPageSize;

      const [total, rows] = await Promise.all([
        typeof prisma.auditLog.count === 'function'
          ? prisma.auditLog.count({ where })
          : prisma.auditLog.findMany({ where }).then((r) => r.length),
        prisma.auditLog.findMany({
          where,
          orderBy: { seq: 'desc' },
          skip,
          take: cappedPageSize,
        }),
      ]);

      const serializedRows = rows.map(serializeAuditRow);

      res.status(200).json({
        logs: serializedRows,
        data: serializedRows,
        total,
        page: currentPage,
        pageSize: cappedPageSize,
        totalPages: Math.ceil(total / cappedPageSize),
      });
    }),
  );

  // GET /logs/:seq
  router.get(
    '/logs/:seq',
    asyncHandler(async (req: Request, res: Response): Promise<void> => {
      const rawSeq = req.params['seq'];
      if (!rawSeq || !/^\d+$/.test(rawSeq)) {
        res.status(400).json({ error: 'Sequence number must be a positive integer' });
        return;
      }

      const seq = BigInt(rawSeq);
      let row: Record<string, unknown> | null = null;

      if (typeof prisma.auditLog.findUnique === 'function') {
        row = await prisma.auditLog.findUnique({ where: { seq } });
      } else {
        const rows = await prisma.auditLog.findMany({ where: { seq }, take: 1 });
        row = rows[0] ?? null;
      }

      if (!row) {
        res.status(404).json({ error: `Audit log record with seq ${rawSeq} not found` });
        return;
      }

      res.status(200).json(serializeAuditRow(row));
    }),
  );

  // GET /history/:model/:recordId
  router.get(
    '/history/:model/:recordId',
    asyncHandler(async (req: Request, res: Response): Promise<void> => {
      const model = req.params['model'];
      const recordId = req.params['recordId'];

      if (!model || !recordId) {
        res.status(400).json({ error: 'model and recordId parameters are required' });
        return;
      }

      if (opts.models && opts.models.length > 0) {
        const isKnown = opts.models.some((m) => m.toLowerCase() === model.toLowerCase());
        if (!isKnown) {
          res.status(400).json({
            error: `Unknown model '${model}'. Valid models: ${opts.models.join(', ')}`,
          });
          return;
        }
      }

      const rows = await getHistory(
        prisma as unknown as HistoryPrismaClient,
        model,
        recordId,
        { order: 'asc' },
      );

      const serializedRows = rows.map((r) => serializeAuditRow(r as unknown as Record<string, unknown>));

      res.status(200).json({
        model,
        recordId,
        count: serializedRows.length,
        history: serializedRows,
      });
    }),
  );

  // GET /verify
  router.get(
    '/verify',
    asyncHandler(async (req: Request, res: Response): Promise<void> => {
      const all = req.query['all'] === 'true';
      const result = await verifyAuditChain({
        prisma: prisma as unknown as VerifyPrismaClient,
        keys,
        checkpoints: opts.checkpoints,
        all,
      });

      // context.md §7.10: "HTTP 200 either way; body.valid tells truth"
      res.status(200).json(result);
    }),
  );

  // GET /export?format=json|csv
  router.get(
    '/export',
    asyncHandler(async (req: Request, res: Response): Promise<void> => {
      const format = req.query['format'] === 'csv' ? 'csv' : 'json';
      const model = typeof req.query['model'] === 'string' ? req.query['model'] : undefined;
      const recordId = typeof req.query['recordId'] === 'string' ? req.query['recordId'] : undefined;
      const actorId = typeof req.query['actorId'] === 'string' ? req.query['actorId'] : undefined;
      const action =
        typeof req.query['action'] === 'string' && ['CREATE', 'UPDATE', 'DELETE'].includes(req.query['action'])
          ? (req.query['action'] as AuditAction)
          : undefined;
      const from = typeof req.query['from'] === 'string' ? req.query['from'] : undefined;
      const to = typeof req.query['to'] === 'string' ? req.query['to'] : undefined;

      if (model && opts.models && opts.models.length > 0) {
        const isKnown = opts.models.some((m) => m.toLowerCase() === model.toLowerCase());
        if (!isKnown) {
          res.status(400).json({
            error: `Unknown model '${model}'. Valid models: ${opts.models.join(', ')}`,
          });
          return;
        }
      }

      if (format === 'csv') {
        res.setHeader('Content-Type', 'text/csv; charset=utf-8');
        res.setHeader('Content-Disposition', 'attachment; filename="audit-log.csv"');
      } else {
        res.setHeader('Content-Type', 'application/json; charset=utf-8');
        res.setHeader('Content-Disposition', 'attachment; filename="audit-log.json"');
      }

      await exportAuditLogsToStream(
        prisma as unknown as ExportPrismaClient,
        { format, model, recordId, actorId, action, from, to },
        res,
      );
      res.end();
    }),
  );

  // GET /restore-preview/:model/:recordId
  router.get(
    '/restore-preview/:model/:recordId',
    asyncHandler(async (req: Request, res: Response): Promise<void> => {
      const model = req.params['model'];
      const recordId = req.params['recordId'];

      if (!model || !recordId) {
        res.status(400).json({ error: 'model and recordId parameters are required' });
        return;
      }

      if (opts.models && opts.models.length > 0) {
        const isKnown = opts.models.some((m) => m.toLowerCase() === model.toLowerCase());
        if (!isKnown) {
          res.status(400).json({
            error: `Unknown model '${model}'. Valid models: ${opts.models.join(', ')}`,
          });
          return;
        }
      }

      const preview = await getRestorePreview(
        prisma as unknown as HistoryPrismaClient,
        model,
        recordId,
      );

      if (!preview) {
        res.status(404).json({
          error: `No audit history found for ${model}:${recordId}`,
        });
        return;
      }

      const baseResponse: Record<string, unknown> = {
        model: preview.model,
        recordId: preview.recordId,
        action: preview.action,
        seq: preview.seq,
        state: preview.state,
      };

      if (
        typeof preview.state === 'object' &&
        preview.state !== null &&
        !Array.isArray(preview.state)
      ) {
        res.status(200).json({
          ...(preview.state as Record<string, unknown>),
          ...baseResponse,
        });
      } else {
        res.status(200).json(baseResponse);
      }
    }),
  );

  return router;
}
