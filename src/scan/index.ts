/**
 * trailguard/scan — Static analysis public API.
 *
 * This entry point may import ts-morph and all static-analysis code.
 * Users who only need the runtime audit log should import from 'trailguard'.
 *
 * @module trailguard/scan
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
} from '../core/errors.js';

// Static types
export type {
  Risk,
  Confidence,
  HttpMethod,
  Action,
  MiddlewareClass,
  MiddlewareRef,
  RouteNode,
  MatrixCell,
  ScanResult,
  Finding,
} from '../core/types.js';

// Config
export { defineConfig } from '../config/schema.js';
export { loadConfig } from '../config/load.js';
export type { Config } from '../config/schema.js';

// Static API — stubs until Phase 2 tasks implement them
// export { scan } from './scan.js';
// export { deriveMatrix } from './matrix.js';
// export { drift } from './drift.js';
