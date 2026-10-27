/**
 * Lightweight stdlib-only helper to load .env variables if not already present in process.env.
 * Checks candidate directories in order. Never overwrites existing environment variables.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';

export function loadDotenvIfPresent(dirs: (string | undefined)[]): void {
  for (const dir of dirs) {
    if (!dir) continue;
    const envPath = path.join(dir, '.env');
    if (!fs.existsSync(envPath)) continue;

    try {
      const content = fs.readFileSync(envPath, 'utf-8');
      for (const line of content.split('\n')) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;
        const eq = trimmed.indexOf('=');
        if (eq > 0) {
          const key = trimmed.slice(0, eq).trim();
          let val = trimmed.slice(eq + 1).trim();
          if (
            (val.startsWith('"') && val.endsWith('"')) ||
            (val.startsWith("'") && val.endsWith("'"))
          ) {
            val = val.slice(1, -1);
          }
          if (process.env[key] === undefined || process.env[key] === '') {
            process.env[key] = val;
          }
        }
      }
    } catch {
      // ignore read errors
    }
  }
}
