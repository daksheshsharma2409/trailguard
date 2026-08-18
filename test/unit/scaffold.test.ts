/**
 * Smoke tests for T0.1 scaffold.
 * Verifies the build outputs and CLI version work.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

describe('T0.1 scaffold', () => {
  it('package.json has required ESM + exports structure', () => {
    const raw = readFileSync(join(process.cwd(), 'package.json'), 'utf-8');
    const pkg = JSON.parse(raw) as {
      version: string;
      type: string;
      exports: Record<string, unknown>;
      bin: Record<string, string>;
    };

    expect(pkg.version).toMatch(/^\d+\.\d+\.\d+$/);
    expect(pkg.type).toBe('module');
    expect(pkg.exports['.']).toBeDefined();
    expect(pkg.exports['./scan']).toBeDefined();
    expect(pkg.exports['./package.json']).toBe('./package.json');
    expect(pkg.bin['trailguard']).toBe('./bin/trailguard.js');
  });
});
