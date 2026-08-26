/**
 * Test fixture loader harness.
 *
 * Provides utilities to load static analysis test fixtures from `test/fixtures/<name>`.
 * Each fixture is a mini-project containing `trailguard.config.ts`, route source files,
 * and an `expected.json` asserting expected findings and routes.
 *
 * @see context.md §12.2
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Project } from 'ts-morph';
import { loadConfig } from '../../src/config/load.js';
import type { Config } from '../../src/config/schema.js';
import { createProject } from '../../src/scan/project.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const FIXTURES_DIR = path.resolve(__dirname, '../fixtures');

/**
 * Get the absolute directory path for a test fixture.
 *
 * @param name - The directory name of the fixture inside `test/fixtures/`.
 */
export function getFixturePath(name: string): string {
  return path.join(FIXTURES_DIR, name);
}

/**
 * Load the `trailguard.config.{ts,json,js}` for a given fixture.
 *
 * @param name - Fixture name.
 */
export async function loadFixtureConfig(name: string): Promise<Config> {
  const fixtureDir = getFixturePath(name);
  return loadConfig(path.join(fixtureDir, 'trailguard.config.ts'));
}

/**
 * Load and parse the `expected.json` file for a fixture.
 *
 * @param name - Fixture name.
 */
export function loadFixtureExpected(name: string): unknown {
  const expectedPath = path.join(getFixturePath(name), 'expected.json');
  if (!fs.existsSync(expectedPath)) {
    throw new Error(`Fixture ${name} does not have an expected.json file at ${expectedPath}`);
  }
  const content = fs.readFileSync(expectedPath, 'utf-8');
  return JSON.parse(content) as unknown;
}

export interface LoadedFixture {
  fixtureDir: string;
  config: Config;
  project: Project;
  expected: unknown;
}

/**
 * Load a full fixture environment: loads its config, creates its ts-morph Project,
 * and reads its `expected.json`.
 *
 * @param name - Fixture name.
 */
export async function loadFixture(name: string): Promise<LoadedFixture> {
  const fixtureDir = getFixturePath(name);
  const config = await loadFixtureConfig(name);
  const project = createProject(config);
  const expected = loadFixtureExpected(name);

  return {
    fixtureDir,
    config,
    project,
    expected,
  };
}
