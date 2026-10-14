/**
 * Unit tests for `trailguard init` (T5.4).
 *
 * Asserts:
 *  - Writes starter `trailguard.config.ts`.
 *  - Refuses to overwrite without `--force`.
 *  - Overwrites when `--force` is provided.
 *  - Output contains Prisma schema snippet and 5-line next steps.
 *
 * @see tasks.md T5.4
 */

import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { tmpdir } from 'node:os';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  runInitCommand,
  STARTER_CONFIG_CONTENT,
  PRISMA_SCHEMA_SNIPPET,
  NEXT_STEPS_TEXT,
} from '../../src/cli/init-command.js';

describe('trailguard init (T5.4)', () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(tmpdir(), 'trailguard-init-test-'));
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  it('writes starter trailguard.config.ts and returns exit code 0', async () => {
    const outcome = await runInitCommand({ cwd: tempDir });

    expect(outcome.exitCode).toBe(0);
    expect(outcome.configPath).toBe(path.join(tempDir, 'trailguard.config.ts'));

    const written = await fs.readFile(path.join(tempDir, 'trailguard.config.ts'), 'utf8');
    expect(written).toBe(STARTER_CONFIG_CONTENT);
    expect(written).toContain("import { defineConfig } from 'trailguard/scan'");

    // Verifies Prisma schema snippet is printed
    expect(outcome.message).toContain('model AuditLog');
    expect(outcome.message).toContain('model AuditHead');
    expect(outcome.message).toContain(PRISMA_SCHEMA_SNIPPET);

    // Verifies 5-line next steps
    expect(outcome.message).toContain(NEXT_STEPS_TEXT);
    expect(outcome.message).toContain('1. Add the AuditLog and AuditHead models');
    expect(outcome.message).toContain('5. Run `npx trailguard scan`');
  });

  it('refuses to overwrite existing config without --force and returns exit code 1', async () => {
    const configPath = path.join(tempDir, 'trailguard.config.ts');
    await fs.writeFile(configPath, '// Existing config content', 'utf8');

    const outcome = await runInitCommand({ cwd: tempDir, force: false });

    expect(outcome.exitCode).toBe(1);
    expect(outcome.message).toContain('already exists. Pass --force to overwrite.');

    // Ensure content was NOT overwritten
    const content = await fs.readFile(configPath, 'utf8');
    expect(content).toBe('// Existing config content');
  });

  it('overwrites existing config when --force is true', async () => {
    const configPath = path.join(tempDir, 'trailguard.config.ts');
    await fs.writeFile(configPath, '// Old content to be replaced', 'utf8');

    const outcome = await runInitCommand({ cwd: tempDir, force: true });

    expect(outcome.exitCode).toBe(0);
    expect(outcome.message).toContain(`Created ${configPath}`);

    const content = await fs.readFile(configPath, 'utf8');
    expect(content).toBe(STARTER_CONFIG_CONTENT);
  });
});
