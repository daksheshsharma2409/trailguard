/**
 * Package hygiene and bundle isolation tests (T7.4).
 *
 * Asserts:
 *  - Whitelist: package.json 'files' includes only dist, bin, prisma, README.md, LICENSE.
 *  - Bundle isolation: dist/index.js (runtime) does NOT import ts-morph.
 *  - Tarball audit: npm pack lists only whitelisted artifacts.
 *
 * @see tasks.md T7.4
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { execSync } from 'node:child_process';
import { describe, it, expect } from 'vitest';

describe('Package hygiene & bundle isolation (T7.4)', () => {
  const rootDir = process.cwd();
  const pkgPath = path.join(rootDir, 'package.json');
  const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8')) as {
    files?: string[];
  };

  it('declares exact files whitelist in package.json', () => {
    expect(pkg.files).toBeDefined();
    expect(pkg.files).toEqual(['dist', 'bin', 'prisma', 'README.md', 'LICENSE']);
  });

  it('dist/index.js exists and does not import ts-morph', () => {
    const runtimeBundlePath = path.join(rootDir, 'dist/index.js');
    expect(fs.existsSync(runtimeBundlePath)).toBe(true);

    const runtimeBundle = fs.readFileSync(runtimeBundlePath, 'utf8');

    // Assert ts-morph is nowhere in the runtime bundle
    expect(runtimeBundle.includes('ts-morph')).toBe(false);
    expect(runtimeBundle.includes('from "ts-morph"')).toBe(false);
    expect(runtimeBundle.includes("from 'ts-morph'")).toBe(false);
    expect(runtimeBundle.includes('import("ts-morph")')).toBe(false);
  });

  it('npm pack --dry-run packages only intended whitelist files', () => {
    const stdout = execSync('npm pack --dry-run --json', {
      cwd: rootDir,
      encoding: 'utf8',
    });

    const parsed = JSON.parse(stdout) as Array<{
      files: Array<{ path: string }>;
    }>;

    expect(parsed.length).toBeGreaterThan(0);
    const packedFiles = parsed[0]?.files.map((f) => f.path) ?? [];

    for (const file of packedFiles) {
      const allowed =
        file.startsWith('dist/') ||
        file.startsWith('bin/') ||
        file.startsWith('prisma/') ||
        file === 'package.json' ||
        file === 'README.md' ||
        file === 'LICENSE';

      expect(
        allowed,
        `Unexpected file in npm pack: ${file}`,
      ).toBe(true);
    }

    // Must include the key entry points
    expect(packedFiles).toContain('dist/index.js');
    expect(packedFiles).toContain('dist/scan/index.js');
    expect(packedFiles).toContain('dist/cli.js');
    expect(packedFiles).toContain('bin/trailguard.js');
    expect(packedFiles).toContain('prisma/trailguard.prisma');
    expect(packedFiles).toContain('README.md');
    expect(packedFiles).toContain('LICENSE');

    // Must NOT package tests, fixtures, or source code
    expect(packedFiles.some((f) => f.startsWith('test/'))).toBe(false);
    expect(packedFiles.some((f) => f.startsWith('src/'))).toBe(false);
    expect(packedFiles.some((f) => f.startsWith('examples/'))).toBe(false);
    expect(packedFiles.some((f) => f.startsWith('scripts/'))).toBe(false);
  });

  it('.d.ts audit passes with tsc --noEmit on consumer imports', () => {
    const scratchDir = path.join(rootDir, 'node_modules/.hygiene-ts-check');
    try {
      fs.mkdirSync(scratchDir, { recursive: true });
      fs.writeFileSync(
        path.join(scratchDir, 'consumer.ts'),
        `
        import { createAuditClient, auditContext, verifyAuditChain, type AuditEntry } from '../../dist/index.js';
        import { scan, defineConfig, deriveMatrix, type ScanResult, type RouteNode } from '../../dist/scan/index.js';

        const cfg = defineConfig({
          entry: ['app.ts'],
          auth: { middleware: ['auth'] },
          roles: { middleware: ['role'], extractor: 'firstStringArg' },
        });
        `,
      );
      fs.writeFileSync(
        path.join(scratchDir, 'tsconfig.json'),
        JSON.stringify({
          compilerOptions: {
            target: 'ES2022',
            module: 'NodeNext',
            moduleResolution: 'NodeNext',
            strict: true,
            noEmit: true,
            skipLibCheck: true,
          },
          include: ['consumer.ts'],
        }),
      );
      execSync('npx tsc --noEmit', { cwd: scratchDir, encoding: 'utf8' });
    } finally {
      fs.rmSync(scratchDir, { recursive: true, force: true });
    }
  });
});
