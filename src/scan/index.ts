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
export { defineConfig, ConfigSchema } from '../config/schema.js';
export { loadConfig, findConfigFile } from '../config/load.js';
export type { Config, UserConfig } from '../config/schema.js';

// Static analysis core
export { createProject } from './project.js';
export {
  extractRoutes,
  extractRoutesFromProject,
  HTTP_METHODS,
  isPathArg,
  extractPathFromNode,
  flattenArgs,
} from './routes.js';
export type {
  ExtractedRoute,
  ExtractedUse,
  ExtractedPath,
  FileRoutesResult,
} from './routes.js';
export {
  resolveHandler,
  resolveRouter,
  ResolutionContext,
  getRootSymbol,
  resolveModuleSourceFile,
} from './handlers.js';
export type { ResolvedHandler, ResolvedRouter } from './handlers.js';
export {
  normalizePath,
  matchesPrefix,
  buildMountGraph,
  composeMounts,
} from './mounts.js';
export type {
  MountEdge,
  RouterInfo,
  ComposedRoute,
  MountGraph,
  MountCompositionResult,
} from './mounts.js';
export {
  classifyMiddleware,
  classifySingleMiddleware,
  extractRoleArgs,
  mentionsUserRole,
  isNeutralMiddleware,
  KNOWN_NEUTRAL_MIDDLEWARE,
} from './classify.js';
export type { RoleExtractionResult, ClassificationConfig } from './classify.js';
export {
  parsePrismaSchema,
  loadPrismaSchema,
  stripComments,
  DEFAULT_OWNER_FIELDS,
} from './prisma-schema.js';
export type {
  PrismaField,
  PrismaModel,
  PrismaSchemaResult,
  RelationInfo,
} from './prisma-schema.js';
export {
  mapResource,
  singularize,
  toPascalCase,
  extractResourceSegment,
} from './resources.js';
export type { ResourceMapping } from './resources.js';
export {
  checkOwnershipHeuristic,
  DEFAULT_OWNERSHIP_SIGNALS,
} from './ownership.js';
export type { OwnershipResult, OwnershipOptions } from './ownership.js';

// Static API — stubs until Phase 2 tasks implement them
// export { scan } from './scan.js';
// export { deriveMatrix } from './matrix.js';
// export { drift } from './drift.js';
