/**
 * Resource mapping for Express routes to Prisma models.
 *
 * Implements two-layer mapping:
 * 1. Configuration prefix map (longest-prefix wins, source: 'config')
 * 2. Heuristic singularization (first non-api/non-version segment, PascalCase, source: 'heuristic')
 *
 * @see context.md §6.6
 */

import { normalizePath, matchesPrefix } from './mounts.js';
import type { PrismaSchemaResult } from './prisma-schema.js';

export interface ResourceMapping {
  model: string | null;
  source: 'config' | 'heuristic';
}

const API_VERSION_SEGMENT = /^(api|v\d+(\.\d+)?)$/i;

/**
 * Singularize an English noun segment.
 *
 * Handles common suffixes:
 * - ies → y (categories → category)
 * - sses → ss (classes → class)
 * - es → base (boxes → box, watches → watch)
 * - s → base (students → student)
 */
export function singularize(word: string): string {
  const lower = word.toLowerCase();
  if (lower.endsWith('ies') && lower.length > 3) {
    return word.slice(0, -3) + 'y';
  }
  if (lower.endsWith('sses')) {
    return word.slice(0, -2);
  }
  if (lower.endsWith('es') && !lower.endsWith('ees') && lower.length > 3) {
    if (/(?:[sxhz]|ch|sh)es$/i.test(word)) {
      return word.slice(0, -2);
    }
  }
  if (lower.endsWith('s') && !lower.endsWith('ss') && lower.length > 1) {
    return word.slice(0, -1);
  }
  return word;
}

/**
 * Convert a string to PascalCase (handles snake_case and kebab-case).
 */
export function toPascalCase(str: string): string {
  return str
    .split(/[-_]+/)
    .filter((part) => part.length > 0)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1).toLowerCase())
    .join('');
}

/**
 * Extract the primary resource name candidate from URL path segments.
 *
 * Skips leading 'api' and version segments (v1, v2, etc.) as well as param segments (:id).
 */
export function extractResourceSegment(path: string): string | null {
  const normalized = normalizePath(path);
  const segments = normalized
    .split('/')
    .filter((s) => s.length > 0 && !s.startsWith(':') && s !== '<regex>');

  for (const seg of segments) {
    if (!API_VERSION_SEGMENT.test(seg)) {
      return seg;
    }
  }

  return null;
}

/**
 * Map a route path to a Prisma model name.
 *
 * Layer 1: Config override map (longest prefix wins, source: 'config').
 * Layer 2: Heuristic singularization and case-insensitive model matching (source: 'heuristic').
 * Unmatched routes return { model: null, source: 'heuristic' }.
 */
export function mapResource(
  path: string,
  configResources: Record<string, string> = {},
  knownModels: string[] | Set<string> | PrismaSchemaResult = [],
): ResourceMapping {
  const normalizedPath = normalizePath(path);

  // Layer 1: Config override (longest-prefix wins)
  let longestMatchKey: string | null = null;
  let longestMatchLength = -1;

  for (const prefix of Object.keys(configResources)) {
    if (matchesPrefix(normalizedPath, prefix)) {
      const normPrefix = normalizePath(prefix);
      if (normPrefix.length > longestMatchLength) {
        longestMatchLength = normPrefix.length;
        longestMatchKey = prefix;
      }
    }
  }

  if (longestMatchKey !== null) {
    const model = configResources[longestMatchKey];
    if (model !== undefined) {
      return {
        model,
        source: 'config',
      };
    }
  }

  // Layer 2: Heuristic mapping
  const segment = extractResourceSegment(normalizedPath);
  if (!segment) {
    return {
      model: null,
      source: 'heuristic',
    };
  }

  const singular = singularize(segment);
  const candidate = toPascalCase(singular);

  // Normalize known models list
  const modelList: string[] =
    knownModels instanceof Map
      ? Array.from(knownModels.keys())
      : knownModels instanceof Set
        ? Array.from(knownModels)
        : knownModels;

  const matched = modelList.find(
    (m) => m.toLowerCase() === candidate.toLowerCase(),
  );

  if (matched) {
    return {
      model: matched,
      source: 'heuristic',
    };
  }

  return {
    model: null,
    source: 'heuristic',
  };
}
