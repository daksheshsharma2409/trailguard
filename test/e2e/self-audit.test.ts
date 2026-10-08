/**
 * E2E test for self-audit in CI (T7.5).
 *
 * Asserts:
 *  - Fixed demo app passes `trailguard ci --no-db --fail-on high` (exit code 0).
 *  - Vulnerable demo app fails `trailguard ci --no-db --fail-on high` (exit code 1 with ≥ high findings).
 *
 * @see tasks.md T7.5
 */

import * as path from 'node:path';
import { execSync } from 'node:child_process';
import { describe, it, expect } from 'vitest';

describe('Self-audit in CI: demo app gating (T7.5)', () => {
  const rootDir = process.cwd();
  const cliPath = path.join(rootDir, 'bin/trailguard.js');
  const demoConfig = path.join(rootDir, 'examples/demo-app/trailguard.config.ts');

  it('runs trailguard ci --no-db on the fixed demo app and exits 0', () => {
    const stdout = execSync(
      `node "${cliPath}" ci --config "${demoConfig}" --no-db --fail-on high`,
      {
        cwd: rootDir,
        encoding: 'utf8',
      },
    );

    expect(stdout).toContain('Result: PASS (exit code: 0)');
    expect(stdout).toContain('Static Scan');
    expect(stdout).toContain('PASS');
  });

  it('proves the vulnerable branch fails with exit code 1 when findings >= high', () => {
    // 1. Break demo app
    execSync('npm run demo:break', { cwd: rootDir, encoding: 'utf8' });

    try {
      let exitCode = 0;
      let output = '';

      try {
        output = execSync(
          `node "${cliPath}" ci --config "${demoConfig}" --no-db --fail-on high`,
          {
            cwd: rootDir,
            encoding: 'utf8',
            stdio: ['pipe', 'pipe', 'pipe'],
          },
        );
      } catch (err: unknown) {
        const error = err as { status?: number; stdout?: string; stderr?: string };
        exitCode = error.status ?? 0;
        output = (error.stdout ?? '') + (error.stderr ?? '');
      }

      // Assert exit code 1 and findings detected
      expect(exitCode).toBe(1);
      expect(output).toContain('Result: FAIL (exit code: 1)');
      expect(output).toContain('3 unsuppressed finding(s) exceeded threshold (high)');
    } finally {
      // 2. Always revert the break patch
      execSync('npm run demo:fix', { cwd: rootDir, encoding: 'utf8' });
    }
  });
});
