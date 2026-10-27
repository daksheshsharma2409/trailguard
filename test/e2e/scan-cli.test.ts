/**
 * End-to-end tests for the built trailguard CLI `trailguard scan`.
 *
 * Spawns the CLI process via node ./bin/trailguard.js across fixtures and verifies
 * exit codes, options, output formatting, and error handling.
 *
 * @see context.md §4.4, §4.5
 */

import * as path from 'node:path';
import * as fs from 'node:fs';
import * as os from 'node:os';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { describe, it, expect, beforeAll } from 'vitest';
import { getFixturePath } from '../helpers/fixture.js';
import { scan } from '../../src/scan/index.js';
import { ScanResultSchema } from '../../src/scan/report/json.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT_DIR = path.resolve(__dirname, '../..');
const BIN_PATH = path.resolve(ROOT_DIR, 'bin/trailguard.js');

interface CliResult {
  status: number | null;
  stdout: string;
  stderr: string;
}
function runCli(args: string[]): CliResult {
  const env = { ...process.env };
  delete env.NODE_V8_COVERAGE;
  const result = spawnSync('node', [BIN_PATH, ...args], {
    cwd: ROOT_DIR,
    encoding: 'utf-8',
    env,
  });

  return {
    status: result.status,
    stdout: result.stdout,
    stderr: result.stderr,
  };
}

describe('trailguard scan CLI e2e tests', () => {
  beforeAll(() => {
    // Ensure dist/ is built
    const cliDist = path.resolve(ROOT_DIR, 'dist/cli.js');
    if (!fs.existsSync(cliDist)) {
      throw new Error('dist/cli.js does not exist. Run npm run build first.');
    }
  });

  it('exits 0 on clean fixture (no findings)', () => {
    const configPath = path.join(getFixturePath('clean'), 'trailguard.config.ts');
    const result = runCli(['scan', '--config', configPath]);

    expect(result.status).toBe(0);
    expect(result.stdout).toContain('# Trailguard Scan Report');
    expect(result.stdout).toContain('_No findings detected._');
  });

  it('exits 1 on missing-auth fixture with --fail-on high', () => {
    const configPath = path.join(getFixturePath('missing-auth'), 'trailguard.config.ts');
    const result = runCli(['scan', '--config', configPath, '--fail-on', 'high']);

    expect(result.status).toBe(1);
    expect(result.stdout).toContain('# Trailguard Scan Report');
    expect(result.stdout).toContain('RBAC001');
    expect(result.stdout).toContain('DELETE /api/posts/:id');
  });

  it('exits 2 on bad/non-existent config path', () => {
    const badPath = path.join(ROOT_DIR, 'non-existent-trailguard.config.ts');
    const result = runCli(['scan', '--config', badPath]);

    expect(result.status).toBe(2);
    expect(result.stderr).toContain('trailguard scan error');
  });

  it('exits 0 on missing-auth when --fail-on none is passed', () => {
    const configPath = path.join(getFixturePath('missing-auth'), 'trailguard.config.ts');
    const result = runCli(['scan', '--config', configPath, '--fail-on', 'none']);

    // Findings are present, but failOn none guarantees exit code 0
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('RBAC001');
  });

  it('supports --format json and outputs valid ScanResult JSON to stdout', () => {
    const configPath = path.join(getFixturePath('clean'), 'trailguard.config.ts');
    const result = runCli(['scan', '--config', configPath, '--format', 'json']);

    expect(result.status).toBe(0);
    const parsed = JSON.parse(result.stdout) as unknown;
    const validated = ScanResultSchema.safeParse(parsed);
    expect(validated.success).toBe(true);
  });

  it('supports --out <file> writing report to disk instead of stdout', () => {
    const configPath = path.join(getFixturePath('clean'), 'trailguard.config.ts');
    const tmpOut = path.join(os.tmpdir(), `trailguard-out-${String(Date.now())}.md`);

    try {
      const result = runCli(['scan', '--config', configPath, '--out', tmpOut]);

      expect(result.status).toBe(0);
      expect(result.stdout).toBe(''); // stdout should be empty when --out is used
      expect(fs.existsSync(tmpOut)).toBe(true);

      const content = fs.readFileSync(tmpOut, 'utf-8');
      expect(content).toContain('# Trailguard Scan Report');
    } finally {
      if (fs.existsSync(tmpOut)) {
        fs.unlinkSync(tmpOut);
      }
    }
  });

  it('supports --update-baseline to suppress findings', () => {
    const fixtureDir = getFixturePath('missing-auth');
    const configPath = path.join(fixtureDir, 'trailguard.config.ts');
    const tmpBaseline = path.join(os.tmpdir(), `tmp-baseline-${String(Date.now())}.json`);

    try {
      // 1. First run with --update-baseline rewrites the baseline file
      const resultUpdate = runCli([
        'scan',
        '--config',
        configPath,
        '--baseline',
        tmpBaseline,
        '--update-baseline',
      ]);

      expect(fs.existsSync(tmpBaseline)).toBe(true);
      expect(resultUpdate.status).toBe(0); // findings now baselined

      // 2. Subsequent run with that baseline passes with exit 0
      const resultPass = runCli([
        'scan',
        '--config',
        configPath,
        '--baseline',
        tmpBaseline,
        '--fail-on',
        'high',
      ]);

      expect(resultPass.status).toBe(0);
      expect(resultPass.stdout).toContain('**Suppressed (baselined):** 1');
    } finally {
      if (fs.existsSync(tmpBaseline)) {
        fs.unlinkSync(tmpBaseline);
      }
    }
  });
});

describe('scan() programmatic API', () => {
  it('returns structured ScanOutput with report and exitCode', async () => {
    const configPath = path.join(getFixturePath('clean'), 'trailguard.config.ts');
    const output = await scan({ config: configPath });

    expect(output.version).toBe('0.1.2');
    expect(output.exitCode).toBe(0);
    expect(output.thresholdExceeded).toBe(false);
    expect(output.findings.length).toBe(0);
    expect(output.report).toContain('# Trailguard Scan Report');
  });

  it('computes thresholdExceeded: true on unsuppressed findings matching failOn', async () => {
    const configPath = path.join(getFixturePath('missing-auth'), 'trailguard.config.ts');
    const output = await scan({ config: configPath, failOn: 'high' });

    expect(output.exitCode).toBe(1);
    expect(output.thresholdExceeded).toBe(true);
    expect(output.findings.length).toBe(1);
  });
});
