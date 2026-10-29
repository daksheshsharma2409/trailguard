/**
 * Dynamic version resolution for trailguard.
 *
 * Resolves the package version from package.json at runtime,
 * caching the result so subsequent calls are instantaneous.
 */

import { createRequire } from 'node:module';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

let cachedVersion: string | undefined;

export function getPackageVersion(): string {
  if (cachedVersion) {
    return cachedVersion;
  }

  try {
    const _require = createRequire(import.meta.url);
    const _dirname = path.dirname(fileURLToPath(import.meta.url));

    let currentDir = _dirname;
    // Walk up directory hierarchy to find trailguard package.json
    for (let i = 0; i < 4; i++) {
      try {
        const pkgPath = path.join(currentDir, 'package.json');
        const pkg = _require(pkgPath) as { name?: string; version?: string };
        if (pkg.name === 'trailguard' && pkg.version) {
          cachedVersion = pkg.version;
          return cachedVersion;
        }
      } catch {
        // try parent directory
      }
      const parent = path.dirname(currentDir);
      if (parent === currentDir) break;
      currentDir = parent;
    }
  } catch {
    // fallback if file system access fails in unusual environments
  }

  // Fallback version if package.json cannot be read
  return '0.1.6';
}
