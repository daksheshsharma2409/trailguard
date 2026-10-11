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

// Core constants re-exported for consumers
export {
  GENESIS_HASH,
  PAYLOAD_VERSION,
  AUDIT_LOG_TABLE,
  AUDIT_HEAD_TABLE,
  AUDIT_HEAD_ID,
  DEFAULT_KEY_ENV,
  DEFAULT_KEY_ID,
  MAX_PAGE_SIZE,
  VERIFY_BATCH_SIZE,
  DEFAULT_MAX_BULK_ROWS,
  CHECKPOINT_SIG_PREFIX,
} from './core/constants.js';


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

// Runtime API
export { createAuditClient } from './runtime/client.js';
export {
  auditContext,
  runWithAuditContext,
  getAuditContext,
} from './runtime/context.js';
export { verifyAuditChain } from './runtime/verify.js';
export {
  createCheckpoint,
  verifyCheckpointSignature,
  fileSink,
  stdoutSink,
  callbackSink,
} from './runtime/checkpoint.js';
export {
  AuditChainService,
  type ManualLogInput,
  type AuditServicePrismaClient,
} from './runtime/service.js';
export {
  getHistory,
  getRestorePreview,
  type HistoryEntry,
  type GetHistoryOptions,
  type RestorePreviewResult,
} from './runtime/history.js';
export {
  auditRouter,
  type AuditRouterOptions,
  type RouterPrismaClient,
} from './runtime/router.js';
export {
  exportAuditLogs,
  exportAuditLogsToStream,
  exportAuditLogsToFile,
  escapeCsvCell,
  serializeRowForJson,
  CSV_COLUMNS,
  type ExportAuditLogsOptions,
  type ExportPrismaClient,
} from './runtime/export.js';

