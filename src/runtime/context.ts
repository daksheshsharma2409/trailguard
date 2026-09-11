/**
 * Audit context management via AsyncLocalStorage.
 *
 * Provides request-scoped actor, request ID, IP address, and user agent to the
 * runtime audit log.
 *
 * @see context.md §7.6
 */

import { AsyncLocalStorage } from 'node:async_hooks';
import { randomUUID } from 'node:crypto';
import type { Request, Response, NextFunction } from 'express';
import { AuditContextMissingError } from '../core/errors.js';
import type { AuditContext } from '../core/types.js';

export interface AuditContextStore {
  requestId: string;
  actorId?: string | undefined;
  actorRole?: string | undefined;
  ipAddress?: string | undefined;
  userAgent?: string | undefined;
  req?: Request | undefined;
  getActor?: ((req: Request) => { id?: string | undefined; role?: string | undefined } | undefined) | undefined;
}

export interface AuditContextMiddlewareOptions {
  /**
   * Custom actor extractor from the Express request.
   * Defaults to reading `req.user.id` and `req.user.role`.
   */
  getActor?: (req: Request) => { id?: string | undefined; role?: string | undefined } | undefined;
  /**
   * Whether to trust proxy headers for IP address resolution.
   */
  trustProxy?: boolean;
  /**
   * Whether to trust client-supplied `x-request-id` header.
   * Default: false (always generates a new random UUID).
   */
  trustRequestIdHeader?: boolean;
}

const ALS_SYMBOL = Symbol.for('trailguard.als');

type GlobalWithAls = typeof globalThis & {
  [ALS_SYMBOL]?: AsyncLocalStorage<AuditContextStore>;
};

const globalAny = globalThis as GlobalWithAls;

/**
 * Singleton AsyncLocalStorage store, shared across package instances via globalThis.
 */
export const auditAls: AsyncLocalStorage<AuditContextStore> =
  globalAny[ALS_SYMBOL] ?? (globalAny[ALS_SYMBOL] = new AsyncLocalStorage<AuditContextStore>());

interface RequestWithUser {
  user?: {
    id?: string | number | undefined;
    role?: string | undefined;
  };
}

function defaultGetActor(
  req: Request,
): { id?: string | undefined; role?: string | undefined } | undefined {
  const reqWithUser = req as unknown as RequestWithUser;
  const user = reqWithUser.user;
  if (!user || typeof user !== 'object') {
    return undefined;
  }
  const id =
    typeof user.id === 'string'
      ? user.id
      : typeof user.id === 'number'
        ? String(user.id)
        : undefined;
  const role = typeof user.role === 'string' ? user.role : undefined;

  return { id, role };
}

/**
 * Express middleware that initializes audit context for the request.
 *
 * Place early in the middleware pipeline (before authentication/routes).
 * Actor resolution is evaluated lazily at write time.
 */
export function auditContext(options: AuditContextMiddlewareOptions = {}) {
  const getActor = options.getActor ?? defaultGetActor;

  return (req: Request, _res: Response, next: NextFunction): void => {
    let requestId: string;
    if (options.trustRequestIdHeader) {
      const headerReqId = req.get('x-request-id');
      requestId = headerReqId ? headerReqId : randomUUID();
    } else {
      requestId = randomUUID();
    }

    let ipAddress: string | undefined;
    if (options.trustProxy) {
      const forwarded = req.get('x-forwarded-for');
      if (forwarded) {
        const rawIp = forwarded.split(',')[0];
        ipAddress = rawIp ? rawIp.trim() : undefined;
      }
    }
    if (!ipAddress) {
      ipAddress = req.ip || req.socket.remoteAddress || undefined;
    }

    const userAgent = req.get('user-agent');

    const store: AuditContextStore = {
      requestId,
      ipAddress,
      userAgent,
      req,
      getActor,
    };

    auditAls.run(store, () => {
      next();
    });
  };
}

/**
 * Run a synchronous or asynchronous callback within a specified audit context.
 * Useful for non-HTTP workloads (background workers, scripts, seeds).
 */
export function runWithAuditContext<T>(
  context: AuditContext,
  fn: () => T,
): T {
  const store: AuditContextStore = {
    requestId: context.requestId ?? randomUUID(),
    actorId: context.actorId,
    actorRole: context.actorRole,
    ipAddress: context.ipAddress,
    userAgent: context.userAgent,
  };

  return auditAls.run(store, fn);
}

/**
 * Resolve current audit context from AsyncLocalStorage.
 *
 * @param onMissingContext - Policy if no ALS context is active ('throw' | 'system'). Default: 'throw'.
 */
export function getAuditContext(
  onMissingContext: 'throw' | 'system' = 'throw',
): AuditContext {
  const store = auditAls.getStore();

  if (!store) {
    if (onMissingContext === 'system') {
      return {
        requestId: randomUUID(),
        actorId: 'system',
        actorRole: 'SYSTEM',
        ipAddress: undefined,
        userAgent: undefined,
      };
    }
    throw new AuditContextMissingError(
      'No audit context found. Did you add auditContext() middleware or use runWithAuditContext()?',
    );
  }

  let actorId = store.actorId;
  let actorRole = store.actorRole;

  if (store.req && store.getActor) {
    const actor = store.getActor(store.req);
    if (actor) {
      if (actor.id !== undefined) actorId = actor.id;
      if (actor.role !== undefined) actorRole = actor.role;
    }
  }

  return {
    requestId: store.requestId,
    actorId,
    actorRole,
    ipAddress: store.ipAddress,
    userAgent: store.userAgent,
  };
}
