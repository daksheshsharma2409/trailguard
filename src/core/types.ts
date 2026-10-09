/**
 * Shared types for trailguard.
 *
 * These are the authoritative shapes used across both the static and runtime sides.
 *
 * @see context.md §10
 */

// ── Enumerations ────────────────────────────────────────────────────────────

export type Risk = 'high' | 'medium' | 'low';
export type Confidence = 'high' | 'medium' | 'low';
export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'HEAD' | 'OPTIONS' | 'ALL';
export type Action = 'read' | 'create' | 'update' | 'delete';
export type AuditAction = 'CREATE' | 'UPDATE' | 'DELETE';

// ── Middleware classification ────────────────────────────────────────────────

export type MiddlewareClass =
  | { kind: 'auth' }
  | { kind: 'role'; value: string }  // value may be a role name or the literal 'unknown'
  | { kind: 'ownership' }
  | { kind: 'neutral' }
  | { kind: 'unknown' };

export interface MiddlewareRef {
  /** Source text of the middleware expression. */
  text: string;
  /** Resolved name (identifier, callee, property-access text). */
  name: string;
  /** String literal arguments, if any. */
  args: string[];
  /** Classification result. */
  class: MiddlewareClass;
  /** Source file path. */
  file: string;
  /** Line number (1-indexed). */
  line: number;
}

// ── Route node ──────────────────────────────────────────────────────────────

export interface RouteNode {
  method: HttpMethod;
  /** Composed (full) path after mount resolution. */
  path: string;
  /** Raw path as written in source (before mount composition). */
  rawPath: string;
  confidence: Confidence;
  /** Effective middleware chain (all middleware that runs before handler). */
  chain: MiddlewareRef[];
  handler?: {
    name: string;
    file?: string | undefined;
    line?: number | undefined;
    resolved: boolean;
  } | undefined;
  file: string;
  line: number;
  resource?: {
    model: string | null;
    source: 'config' | 'heuristic';
  } | undefined;
  ownership: 'probable' | 'none' | 'unknown';
  orphan?: boolean | undefined;
}

// ── Matrix ──────────────────────────────────────────────────────────────────

export interface MatrixCell {
  resource: string;
  action: Action;
  anonymous: boolean;
  anyAuthenticated: boolean;
  roles: string[];
  /** True if at least one contributing route has `ownership: 'probable'`. */
  own: boolean;
  /** True if any contributing route has low confidence or unknown middleware. */
  uncertain: boolean;
}

// ── Finding ─────────────────────────────────────────────────────────────────

export interface Finding {
  ruleId: string;
  risk: Risk;
  confidence: Confidence;
  message: string;
  file: string;
  line: number;
  route?: {
    method: string;
    path: string;
    handler?: string | undefined;
  } | undefined;
  resource?: {
    model: string | null;
    source: 'config' | 'heuristic';
  } | undefined;
  /**
   * Stable fingerprint — no line numbers so it survives unrelated edits.
   * sha256(ruleId|method|composedPath) or (ruleId|relativeFile|model.op|enclosingFn)
   */
  fingerprint: string;
  suppressed?: boolean | undefined;
}

// ── Scan result ─────────────────────────────────────────────────────────────

export interface ScanResult {
  version: string;
  routes: RouteNode[];
  findings: Finding[];
  matrix: MatrixCell[];
  models: string[];
  stats: {
    routes: number;
    protectedRoutes: number;
    unprotectedRoutes: number;
    byRisk: Record<Risk, number>;
    suppressed: number;
  };
}

// ── Audit context ───────────────────────────────────────────────────────────

export interface AuditContext {
  requestId?: string | undefined;
  actorId?: string | undefined;
  actorRole?: string | undefined;
  ipAddress?: string | undefined;
  userAgent?: string | undefined;
}

// ── Audit entry (what gets stored) ─────────────────────────────────────────

export interface AuditEntry {
  seq: bigint;
  model: string;
  recordId: string;
  action: AuditAction;
  actorId: string | null;
  actorRole: string | null;
  requestId: string | null;
  ipAddress: string | null;
  userAgent: string | null;
  payload: string;
  before: unknown;
  after: unknown;
  diff: unknown;
  prevHash: string;
  hash: string;
  keyId: string;
  createdAt: Date;
}

// ── Audit client options ────────────────────────────────────────────────────

export interface KeysOptions {
  current: string;
  secrets: Record<string, string>;
}

export interface KeysShorthand {
  secret: string;
}

export type CheckpointSink = (checkpoint: Checkpoint) => void | Promise<void>;

export interface AuditOptions {
  /** Prisma model names to audit (required, non-empty). */
  models: string[];
  /** HMAC keys. Use { secret } shorthand → keyId 'default'. */
  keys: KeysOptions | KeysShorthand;
  /** Field names redacted globally. */
  redactFields?: string[];
  /** Per-model field redaction. */
  redact?: Record<string, string[]>;
  /** Fields excluded entirely (not even stored). */
  ignoreFields?: Record<string, string[]>;
  /** Override the id field name(s) per model. Default: 'id'. */
  idFields?: Record<string, string | string[]>;
  /** What to do when no ALS context is found at write time. Default: 'throw'. */
  onMissingContext?: 'throw' | 'system';
  /** Max rows for updateMany/deleteMany. Default: 1000. */
  maxBulkRows?: number;
  /** Checkpoint emission config. */
  checkpoint?: { every: number; sink: CheckpointSink };
  /** Transaction timeout options. */
  tx?: { maxWait?: number; timeout?: number };
  /** Error handler for non-fatal errors (e.g. checkpoint sink failures). */
  onError?: (e: Error) => void;
  /** Internal test hooks — do not use in production. */
  testHooks?: { beforeAppend?: () => void | Promise<void> };
}

// ── Checkpoint ──────────────────────────────────────────────────────────────

export interface Checkpoint {
  v: 1;
  /** Sequence number as decimal string (BigInt-safe). */
  seq: string;
  hash: string;
  ts: string;
  keyId: string;
  sig: string;
}

// ── Verify result ───────────────────────────────────────────────────────────

export type VerifyProblemCode =
  | 'SEQ_GAP'
  | 'PREV_HASH_MISMATCH'
  | 'UNKNOWN_KEY'
  | 'HASH_MISMATCH'
  | 'COLUMN_PAYLOAD_MISMATCH'
  | 'HEAD_MISMATCH'
  | 'CHECKPOINT_BAD_SIGNATURE'
  | 'CHECKPOINT_MISMATCH'
  | 'TRUNCATION_DETECTED';

export interface VerifyProblem {
  code: VerifyProblemCode;
  seq?: string;
  message: string;
}

export interface VerifyResult {
  valid: boolean;
  checkedRecords: number;
  head?: { seq: string; hash: string } | undefined;
  checkpointsChecked: number;
  problems: VerifyProblem[];
  brokenAt?: string | undefined;
  reason?: string | undefined;
}
