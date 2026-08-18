/**
 * Constants used across trailguard.
 *
 * These values are part of the stable API — never change them
 * without a major version bump and a migration guide.
 *
 * @see context.md §5, §7.2
 */

/**
 * The `prevHash` value used for the first `AuditLog` row (seq = 1).
 * A 64-character string of zeros — never `null` or an empty string.
 */
export const GENESIS_HASH: string = '0'.repeat(64);

/**
 * Version field inside every canonical payload object.
 * Increment only on breaking changes to the payload schema.
 */
export const PAYLOAD_VERSION = 1 as const;

/** Database table name for the audit log. */
export const AUDIT_LOG_TABLE = 'trailguard_audit_log' as const;

/** Database table name for the audit head (single-row sequence tracker). */
export const AUDIT_HEAD_TABLE = 'trailguard_audit_head' as const;

/** The fixed id of the single AuditHead row. */
export const AUDIT_HEAD_ID = 1 as const;

/** Default environment variable name for the HMAC key. */
export const DEFAULT_KEY_ENV = 'TRAILGUARD_KEY' as const;

/** keyId used when the user passes the `{ secret }` shorthand. */
export const DEFAULT_KEY_ID = 'default' as const;

/** Max page size for audit log queries via the router. */
export const MAX_PAGE_SIZE = 200 as const;

/** Default batch size for verify streaming. */
export const VERIFY_BATCH_SIZE = 1000 as const;

/** Default max bulk rows for updateMany / deleteMany. */
export const DEFAULT_MAX_BULK_ROWS = 1000 as const;

/** Checkpoint signature prefix — used in HMAC input. */
export const CHECKPOINT_SIG_PREFIX = 'trailguard.checkpoint:' as const;
