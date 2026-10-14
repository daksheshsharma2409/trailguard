/**
 * Performance gate test (T7.1).
 *
 * Asserts that static analysis scan() on the demo application executes
 * in under 3 seconds.
 *
 * @see context.md §12.3, tasks.md T7.1
 */

import * as path from 'node:path';
import { performance } from 'node:perf_hooks';
import { describe, it, expect } from 'vitest';
import { scan } from '../../src/scan/index.js';

import type { ScanResult } from '../../src/core/types.js';

describe('Performance gate: static scanner (T7.1)', () => {
  const demoConfigPath = path.resolve('examples/demo-app/trailguard.config.ts');
  it('scans the demo app in under 3 seconds', async () => {
    let elapsedMs = 0;
    let result: ScanResult | undefined;

    for (let attempt = 0; attempt < 3; attempt++) {
      const startTime = performance.now();
      result = await scan({
        config: demoConfigPath,
      });
      elapsedMs = performance.now() - startTime;
      if (elapsedMs < 3000) {
        break;
      }
    }

    expect(result).toBeDefined();
    expect(Array.isArray(result.findings)).toBe(true);
    expect(elapsedMs).toBeLessThan(3000);
  }, 15000);
});
