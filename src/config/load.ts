/**
 * Config loader — discovers and loads trailguard.config.{ts,js,mjs,json}
 * using jiti (so .ts configs work without compiling first).
 *
 * @see context.md §9
 */

import * as path from 'node:path';
import * as fs from 'node:fs';
import { ConfigSchema, type Config, type UserConfig } from './schema.js';
import { ScanConfigError } from '../core/errors.js';

const CONFIG_NAMES = [
  'trailguard.config.ts',
  'trailguard.config.js',
  'trailguard.config.mjs',
  'trailguard.config.json',
];

/**
 * Find the config file by searching from `startDir` upward to the filesystem root.
 * Returns the absolute path of the first match, or `undefined` if not found.
 */
function findConfigFile(startDir: string): string | undefined {
  let dir = startDir;
  for (;;) {
    for (const name of CONFIG_NAMES) {
      const candidate = path.join(dir, name);
      if (fs.existsSync(candidate)) {
        return candidate;
      }
    }
    const parent = path.dirname(dir);
    if (parent === dir) {
      // Reached filesystem root
      return undefined;
    }
    dir = parent;
  }
}

/**
 * Resolve relative paths inside the config against the config file's directory.
 */
function resolveConfigPaths(raw: UserConfig, configDir: string): UserConfig {
  const resolve = (p: string) => (path.isAbsolute(p) ? p : path.resolve(configDir, p));

  return {
    ...raw,
    entry: raw.entry.map(resolve),
    tsconfig: raw.tsconfig !== undefined ? resolve(raw.tsconfig) : undefined,
    prismaSchema: raw.prismaSchema !== undefined ? resolve(raw.prismaSchema) : undefined,
    baseline: raw.baseline !== undefined ? resolve(raw.baseline) : undefined,
  };
}

/** jiti v1 factory type: (callerFile, opts) → require-like function */
type JitiV1Factory = (callerFile: string, opts?: Record<string, unknown>) => (id: string) => unknown;

/**
 * Load a TS/JS/MJS config file using jiti v1.
 * jiti v1 exports: `module.exports = function jiti(filename, opts) { return requireFn; }`
 */
async function loadViaJiti(filePath: string): Promise<unknown> {
  // Dynamic import of jiti; the default export is the factory in v1
  const mod: unknown = await import('jiti');

  // In jiti v1 with CJS, the module has a `.default` pointing to the factory function
  // In some ESM interop scenarios, the module itself is the function
  let factory: JitiV1Factory | undefined;

  if (typeof mod === 'function') {
    factory = mod as JitiV1Factory;
  } else if (mod !== null && typeof mod === 'object') {
    const candidate = (mod as Record<string, unknown>)['default'];
    if (typeof candidate === 'function') {
      factory = candidate as JitiV1Factory;
    }
  }

  if (typeof factory !== 'function') {
    throw new Error('jiti module did not export a factory function (expected jiti v1 API)');
  }

  const requireLike = factory(filePath, {
    interopDefault: true,
    requireCache: false,
  });

  return requireLike(filePath);
}

/**
 * Load and validate a trailguard config.
 *
 * @param configPath - Explicit path to the config file.
 *   If omitted, auto-discovers by searching from `process.cwd()` upward.
 * @returns Fully resolved Config with all defaults applied.
 * @throws {ScanConfigError} If the file cannot be found, loaded, or validated.
 */
export async function loadConfig(configPath?: string): Promise<Config> {
  let resolvedPath: string;

  if (configPath !== undefined) {
    const abs = path.resolve(configPath);
    if (!fs.existsSync(abs)) {
      throw new ScanConfigError(`Config file not found: ${abs}`, { filePath: abs });
    }
    resolvedPath = abs;
  } else {
    const found = findConfigFile(process.cwd());
    if (found === undefined) {
      throw new ScanConfigError(
        `No trailguard config found. Run \`trailguard init\` to create one, or pass --config.`,
      );
    }
    resolvedPath = found;
  }

  const configDir = path.dirname(resolvedPath);
  let rawExport: unknown;

  if (resolvedPath.endsWith('.json')) {
    // JSON: parse directly
    try {
      const text = fs.readFileSync(resolvedPath, 'utf-8');
      rawExport = JSON.parse(text) as unknown;
    } catch (err) {
      throw new ScanConfigError(`Failed to parse JSON config: ${resolvedPath}`, {
        filePath: resolvedPath,
        cause: err,
      });
    }
  } else {
    // TS / JS / MJS: use jiti to execute without compiling
    try {
      rawExport = await loadViaJiti(resolvedPath);
    } catch (err) {
      throw new ScanConfigError(`Failed to load config: ${resolvedPath}`, {
        filePath: resolvedPath,
        cause: err,
      });
    }
  }

  // Handle `export default defineConfig({...})` — jiti may give us {default: ...}
  const rawConfig: unknown =
    rawExport !== null &&
    typeof rawExport === 'object' &&
    'default' in rawExport
      ? (rawExport as { default: unknown }).default
      : rawExport;

  // Resolve relative paths before validation.
  // We cast to UserConfig here since safeParse will validate the shape.
  const configWithPaths = resolveConfigPaths(rawConfig as UserConfig, configDir);


  // Validate with zod
  const result = ConfigSchema.safeParse(configWithPaths);
  if (!result.success) {
    const issues = result.error.issues
      .map((i) => `  - ${i.path.join('.')}: ${i.message}`)
      .join('\n');
    throw new ScanConfigError(
      `Invalid trailguard config at ${resolvedPath}:\n${issues}`,
      { filePath: resolvedPath },
    );
  }

  return result.data;
}
