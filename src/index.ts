/**
 * trailguard — Runtime public API.
 *
 * This entry point must NOT import ts-morph or any static-analysis code.
 * It is the entry point for users who only need the runtime audit log.
 *
 * @module trailguard
 */

// Error classes (shared)
export {
  TrailguardError,
  AuditChainBrokenError,
  AuditContextMissingError,
  AuditConfigError,
  AuditWriteError,
  ScanConfigError,
  ScanParseError,
} from './core/errors.js';

// Core types re-exported for consumers
export type {
  AuditContext,
  AuditEntry,
  AuditOptions,
  VerifyResult,
  VerifyProblem,
  Checkpoint,
  CheckpointSink,
  Risk,
  Action,
  HttpMethod,
} from './core/types.js';

// Runtime API — stubs until Phase 3 tasks implement them
// export { createAuditClient } from './runtime/client.js';
// export { auditContext, runWithAuditContext, getAuditContext } from './runtime/context.js';
// export { auditRouter } from './runtime/router.js';
// export { verifyAuditChain } from './runtime/verify.js';
// export { createCheckpoint } from './runtime/checkpoint.js';
// export { exportAuditLogs } from './runtime/export.js';
// export { AuditChainService } from './runtime/service.js';
