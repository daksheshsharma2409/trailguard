/**
 * Error class hierarchy for trailguard.
 *
 * All errors carry a `code` string for programmatic handling.
 * Never throw plain strings.
 *
 * @see context.md §7.11
 */

/** Base error for all trailguard errors. */
export class TrailguardError extends Error {
  /** Stable error code string. */
  readonly code: string;

  constructor(code: string, message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'TrailguardError';
    this.code = code;
    // Maintain proper prototype chain in ES5 transpilation targets
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/** Thrown when the audit chain is found to be invalid during verification. */
export class AuditChainBrokenError extends TrailguardError {
  /** Sequence number where the chain broke, as a decimal string. */
  readonly brokenAt?: string;
  readonly reason?: string;

  constructor(
    message: string,
    options?: { brokenAt?: string; reason?: string; cause?: unknown },
  ) {
    super('AUDIT_CHAIN_BROKEN', message, { cause: options?.cause });
    this.name = 'AuditChainBrokenError';
    if (options?.brokenAt !== undefined) this.brokenAt = options.brokenAt;
    if (options?.reason !== undefined) this.reason = options.reason;
  }
}

/** Thrown when a write to an audited model is attempted with no ALS context present. */
export class AuditContextMissingError extends TrailguardError {
  constructor(message = 'No audit context found. Did you add auditContext() middleware?') {
    super('AUDIT_CONTEXT_MISSING', message);
    this.name = 'AuditContextMissingError';
  }
}

/** Thrown for configuration errors (bad options, missing required fields). */
export class AuditConfigError extends TrailguardError {
  constructor(message: string, options?: ErrorOptions) {
    super('AUDIT_CONFIG_ERROR', message, options);
    this.name = 'AuditConfigError';
  }
}

/** Thrown when an audit write fails (e.g. DB error during append). */
export class AuditWriteError extends TrailguardError {
  constructor(message: string, options?: ErrorOptions) {
    super('AUDIT_WRITE_ERROR', message, options);
    this.name = 'AuditWriteError';
  }
}

/** Thrown when a scan configuration file is invalid or missing. */
export class ScanConfigError extends TrailguardError {
  readonly filePath?: string;

  constructor(
    message: string,
    options?: { filePath?: string; cause?: unknown },
  ) {
    super('SCAN_CONFIG_ERROR', message, { cause: options?.cause });
    this.name = 'ScanConfigError';
    if (options?.filePath !== undefined) this.filePath = options.filePath;
  }
}

/** Thrown when the Prisma schema or source file cannot be parsed. */
export class ScanParseError extends TrailguardError {
  readonly filePath?: string;
  readonly lineNumber?: number;

  constructor(
    message: string,
    options?: { filePath?: string; lineNumber?: number; cause?: unknown },
  ) {
    super('SCAN_PARSE_ERROR', message, { cause: options?.cause });
    this.name = 'ScanParseError';
    if (options?.filePath !== undefined) this.filePath = options.filePath;
    if (options?.lineNumber !== undefined) this.lineNumber = options.lineNumber;
  }
}
