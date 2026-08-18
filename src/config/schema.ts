/**
 * Zod schema for trailguard.config.ts + inferred Config type + defineConfig().
 *
 * Uses `.strict()` so unknown keys are an error (typo protection).
 *
 * @see context.md §9
 */

import { z } from 'zod';

// ── Sub-schemas ─────────────────────────────────────────────────────────────

const AuthConfigSchema = z
  .object({
    middleware: z.array(z.string()).default([]),
  })
  .strict();

const RolesExtractorSchema = z.enum(['firstStringArg', 'allStringArgs', 'arrayArg']);

const RolesConfigSchema = z
  .object({
    middleware: z.array(z.string()).default([]),
    extractor: RolesExtractorSchema.default('firstStringArg'),
    known: z.array(z.string()).default([]),
  })
  .strict();

const OwnershipConfigSchema = z
  .object({
    signals: z
      .array(z.string())
      .default(['req.user.id', 'req.user?.id', 'req.user.userId', 'user.id']),
    ownerFields: z
      .array(z.string())
      .default(['authorId', 'userId', 'ownerId', 'tenantId', 'createdById']),
    middleware: z.array(z.string()).default([]),
  })
  .strict();

const RuleRiskSchema = z.union([z.enum(['high', 'medium', 'low']), z.literal('off')]);

const AuditScanConfigSchema = z
  .object({
    models: z.array(z.string()).default([]),
    clientNames: z.array(z.string()).default(['auditClient', 'audited', 'db']),
    routerNames: z.array(z.string()).default(['auditRouter']),
  })
  .strict();

const CheckpointsConfigSchema = z
  .object({
    file: z.string().optional(),
  })
  .strict();

const DriftConfigSchema = z
  .object({
    strict: z.boolean().default(false),
    allowRoles: z.array(z.string()).default(['SYSTEM']),
  })
  .strict();

// ── Root schema ─────────────────────────────────────────────────────────────

export const ConfigSchema = z
  .object({
    /** Entry files that create the Express app(s). Imports are followed. */
    entry: z.array(z.string()),
    /** Path to tsconfig used for module resolution. */
    tsconfig: z.string().default('./tsconfig.json'),
    /** Path to schema.prisma. */
    prismaSchema: z.string().default('./prisma/schema.prisma'),
    /** Glob patterns to ignore. */
    ignore: z.array(z.string()).default(['**/*.test.ts', '**/node_modules/**']),

    auth: AuthConfigSchema.default({}),
    roles: RolesConfigSchema.default({}),
    ownership: OwnershipConfigSchema.default({}),

    /** Path-prefix → Prisma model overrides. Longest-prefix wins. */
    resources: z.record(z.string()).default({}),
    /** Models for which unauthenticated reads are suspicious (RBAC003). */
    privateResources: z.array(z.string()).default([]),

    audit: AuditScanConfigSchema.default({}),
    /** Per-rule risk override or 'off'. */
    rules: z.record(RuleRiskSchema).default({}),
    /** Baseline file path. */
    baseline: z.string().optional(),
    checkpoints: CheckpointsConfigSchema.default({}),
    /** Env var holding the HMAC key. */
    keyEnv: z.string().default('TRAILGUARD_KEY'),
    drift: DriftConfigSchema.default({}),
  })
  .strict();

/** Fully resolved trailguard configuration (all defaults applied). */
export type Config = z.infer<typeof ConfigSchema>;

/** Raw user config (before defaults; `entry` is required). */
export type UserConfig = z.input<typeof ConfigSchema>;

/**
 * Type-safe helper to define a trailguard configuration.
 * Call this in trailguard.config.ts — it provides IntelliSense and validation.
 *
 * @example
 * ```ts
 * import { defineConfig } from 'trailguard/scan';
 * export default defineConfig({ entry: ['./src/app.ts'], ... });
 * ```
 */
export function defineConfig(config: UserConfig): UserConfig {
  return config;
}
