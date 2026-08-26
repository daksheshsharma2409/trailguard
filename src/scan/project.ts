/**
 * ts-morph Project setup and source file management for static analysis.
 *
 * @see context.md §6.1, §6.2
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { Project, type ProjectOptions as TsMorphProjectOptions } from 'ts-morph';
import { ScanConfigError } from '../core/errors.js';

export interface CreateProjectOptions {
  /** Entry point file paths */
  entry: string[];
  /** Optional path to tsconfig.json */
  tsconfig?: string;
  /** Glob patterns of files to ignore */
  ignore?: string[];
}

/**
 * Convert a glob pattern into a RegExp.
 *
 * Supports `**` (any directories), `*` (any non-slash characters), `?` (single char),
 * and standard character escapes.
 */
export function globToRegex(pattern: string): RegExp {
  const normalized = pattern.replace(/\\/g, '/');
  let regexStr = '';
  let i = 0;

  if (normalized.startsWith('**/')) {
    regexStr += '(?:.*/)?';
    i = 3;
  }

  while (i < normalized.length) {
    const c = normalized[i];
    if (c === undefined) {
      i++;
      continue;
    }
    if (c === '*' && normalized[i + 1] === '*') {
      if (normalized[i + 2] === '/') {
        regexStr += '(?:.*/)?';
        i += 3;
      } else {
        regexStr += '.*';
        i += 2;
      }
    } else if (c === '*') {
      regexStr += '[^/]*';
      i++;
    } else if (c === '?') {
      regexStr += '[^/]';
      i++;
    } else if ('./\\+^$()[]{}|'.includes(c)) {
      regexStr += `\\${c}`;
      i++;
    } else {
      regexStr += c;
      i++;
    }
  }

  return new RegExp(`^${regexStr}$`);
}

/**
 * Check if a file path matches any of the given ignore glob patterns.
 */
export function isIgnored(filePath: string, ignorePatterns: string[]): boolean {
  const normalizedPath = filePath.replace(/\\/g, '/');
  for (const pattern of ignorePatterns) {
    const regex = globToRegex(pattern);
    if (regex.test(normalizedPath)) {
      return true;
    }
    const fileName = path.basename(normalizedPath);
    if (regex.test(fileName)) {
      return true;
    }
  }
  return false;
}

/**
 * Create a ts-morph Project configured for Trailguard static scanning.
 *
 * Loads specified entry files, resolves and follows transitive imports, supports both
 * TypeScript (.ts) and JavaScript (.js) via `allowJs: true`, and filters out any files
 * matching the ignore patterns.
 *
 * @throws {ScanConfigError} If an entry file does not exist on disk.
 */
export function createProject(options: CreateProjectOptions): Project {
  if (options.entry.length === 0) {
    throw new ScanConfigError('No entry files specified for project creation.');
  }

  // Validate that all entry files exist
  for (const entryPath of options.entry) {
    const absPath = path.resolve(entryPath);
    if (!fs.existsSync(absPath)) {
      throw new ScanConfigError(`Entry file not found: ${absPath}`, { filePath: absPath });
    }
  }

  const projectOptions: TsMorphProjectOptions = {
    compilerOptions: {
      allowJs: true,
      checkJs: false,
      noEmit: true,
    },
    skipAddingFilesFromTsConfig: true,
  };

  if (options.tsconfig && fs.existsSync(path.resolve(options.tsconfig))) {
    projectOptions.tsConfigFilePath = path.resolve(options.tsconfig);
  }

  const project = new Project(projectOptions);

  // Add entry files
  for (const entryPath of options.entry) {
    project.addSourceFileAtPath(path.resolve(entryPath));
  }

  // Follow transitive imports
  project.resolveSourceFileDependencies();

  // Apply ignore patterns
  const ignorePatterns = options.ignore ?? ['**/*.test.ts', '**/node_modules/**'];
  if (ignorePatterns.length > 0) {
    const sourceFiles = project.getSourceFiles();
    for (const sf of sourceFiles) {
      if (isIgnored(sf.getFilePath(), ignorePatterns)) {
        project.removeSourceFile(sf);
      }
    }
  }

  return project;
}
