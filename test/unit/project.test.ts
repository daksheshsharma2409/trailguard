import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { createProject, globToRegex, isIgnored } from '../../src/scan/project.js';
import { ScanConfigError } from '../../src/core/errors.js';
import {
  getFixturePath,
  loadFixtureConfig,
  loadFixtureExpected,
  loadFixture,
} from '../helpers/fixture.js';

describe('T2.1 — ts-morph project + fixture harness', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'trailguard-project-test-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  describe('globToRegex and isIgnored', () => {
    it('matches glob patterns correctly', () => {
      const testRegex = globToRegex('**/*.test.ts');
      expect(testRegex.test('app.test.ts')).toBe(true);
      expect(testRegex.test('/path/to/app.test.ts')).toBe(true);
      expect(testRegex.test('app.ts')).toBe(false);

      const nmRegex = globToRegex('**/node_modules/**');
      expect(nmRegex.test('node_modules/express/index.js')).toBe(true);
      expect(nmRegex.test('/var/project/node_modules/express/index.js')).toBe(true);
      expect(nmRegex.test('/var/project/src/index.js')).toBe(false);
      const qRegex = globToRegex('file?.ts');
      expect(qRegex.test('file1.ts')).toBe(true);
      expect(qRegex.test('file12.ts')).toBe(false);
    });

    it('isIgnored checks file paths and file names against ignore list', () => {
      const ignore = ['**/*.spec.ts', '**/dist/**', 'ignored-file.ts'];
      expect(isIgnored('/project/src/math.spec.ts', ignore)).toBe(true);
      expect(isIgnored('/project/dist/bundle.js', ignore)).toBe(true);
      expect(isIgnored('/project/src/ignored-file.ts', ignore)).toBe(true);
      expect(isIgnored('/project/src/math.ts', ignore)).toBe(false);
    });
  });

  describe('createProject', () => {
    it('throws ScanConfigError when entry is empty', () => {
      expect(() => createProject({ entry: [] })).toThrow(ScanConfigError);
    });

    it('throws ScanConfigError when an entry file does not exist', () => {
      const missing = path.join(tmpDir, 'does-not-exist.ts');
      expect(() => createProject({ entry: [missing] })).toThrow(ScanConfigError);

      try {
        createProject({ entry: [missing] });
      } catch (err) {
        expect(err).toBeInstanceOf(ScanConfigError);
        const scanErr = err as ScanConfigError;
        expect(scanErr.code).toBe('SCAN_CONFIG_ERROR');
        expect(scanErr.message).toContain('Entry file not found');
        expect(scanErr.filePath).toBe(missing);
      }
    });

    it('supports JavaScript files via allowJs: true', () => {
      const jsFile = path.join(tmpDir, 'index.js');
      fs.writeFileSync(jsFile, 'const a = 1; module.exports = a;');

      const project = createProject({ entry: [jsFile] });
      const sourceFiles = project.getSourceFiles();

      expect(sourceFiles.map((sf) => sf.getFilePath())).toContain(jsFile);
      const sf = project.getSourceFileOrThrow(jsFile);
      expect(sf.getStatements().length).toBeGreaterThan(0);
    });

    it('filters out source files matching ignore patterns', () => {
      const entryFile = path.join(tmpDir, 'entry.ts');
      const testFile = path.join(tmpDir, 'entry.test.ts');
      const helperFile = path.join(tmpDir, 'helper.ts');

      fs.writeFileSync(helperFile, 'export const h = 10;');
      fs.writeFileSync(
        testFile,
        `import { h } from "./helper.js"; export const t = h;`,
      );
      fs.writeFileSync(
        entryFile,
        `import { h } from "./helper.js"; import { t } from "./entry.test.js"; export const e = h + t;`,
      );

      // Create project ignoring test files
      const project = createProject({
        entry: [entryFile],
        ignore: ['**/*.test.ts'],
      });

      const paths = project.getSourceFiles().map((sf) => sf.getFilePath());
      expect(paths).toContain(entryFile);
      expect(paths).toContain(helperFile);
      expect(paths).not.toContain(testFile);
    });

    it('loads project with custom tsconfig option', () => {
      const entryFile = path.join(tmpDir, 'app.ts');
      const tsconfigFile = path.join(tmpDir, 'tsconfig.json');
      fs.writeFileSync(entryFile, 'export const val = 42;');
      fs.writeFileSync(
        tsconfigFile,
        JSON.stringify({ compilerOptions: { target: 'ES2022' } }),
      );

      const project = createProject({
        entry: [entryFile],
        tsconfig: tsconfigFile,
      });

      expect(project.getSourceFiles().map((sf) => sf.getFilePath())).toContain(entryFile);
    });
  });

  describe('fixture harness', () => {
    it('getFixturePath resolves to correct fixture directory', () => {
      const p = getFixturePath('clean');
      expect(fs.existsSync(p)).toBe(true);
      expect(fs.existsSync(path.join(p, 'trailguard.config.ts'))).toBe(true);
    });

    it('loadFixtureConfig loads clean fixture config with resolved paths', async () => {
      const config = await loadFixtureConfig('clean');
      expect(config.entry.length).toBe(1);
      expect(config.entry[0]).toContain(path.join('test', 'fixtures', 'clean', 'src', 'app.ts'));
      expect(config.auth.middleware).toEqual(['authenticate']);
      expect(config.roles.known).toEqual(['ADMIN', 'USER']);
    });

    it('loadFixtureExpected loads expected.json for clean fixture', () => {
      const expected = loadFixtureExpected('clean') as { findings: unknown[]; exitCode: number };
      expect(expected.findings).toEqual([]);
      expect(expected.exitCode).toBe(0);
    });

    it('loadFixture loads clean fixture, creates Project, and follows transitive imports', async () => {
      const { project, config, expected } = await loadFixture('clean');
      const exp = expected as { exitCode: number };

      expect(config).toBeDefined();
      expect(exp.exitCode).toBe(0);

      // Verify that both app.ts and routes.ts were loaded into the ts-morph Project
      const filePaths = project.getSourceFiles().map((sf) => sf.getFilePath());
      const hasApp = filePaths.some((p) => p.endsWith('app.ts'));
      const hasRoutes = filePaths.some((p) => p.endsWith('routes.ts'));

      expect(hasApp).toBe(true);
      expect(hasRoutes).toBe(true);
    });
  });
});
