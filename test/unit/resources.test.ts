/**
 * Unit tests for resource mapping.
 *
 * @see context.md §6.6
 */

import { describe, it, expect } from 'vitest';
import {
  mapResource,
  singularize,
  toPascalCase,
  extractResourceSegment,
} from '../../src/scan/resources.js';

describe('singularize', () => {
  it('handles -ies plural suffix', () => {
    expect(singularize('categories')).toBe('category');
    expect(singularize('companies')).toBe('company');
  });

  it('handles -sses and -es plural suffixes', () => {
    expect(singularize('classes')).toBe('class');
    expect(singularize('boxes')).toBe('box');
    expect(singularize('watches')).toBe('watch');
    expect(singularize('buses')).toBe('bus');
  });

  it('handles standard -s plural suffix without damaging -ss words', () => {
    expect(singularize('students')).toBe('student');
    expect(singularize('posts')).toBe('post');
    expect(singularize('items')).toBe('item');
    expect(singularize('class')).toBe('class');
    expect(singularize('access')).toBe('access');
  });
});

describe('toPascalCase', () => {
  it('converts plain, snake_case, and kebab-case strings to PascalCase', () => {
    expect(toPascalCase('student')).toBe('Student');
    expect(toPascalCase('blog_post')).toBe('BlogPost');
    expect(toPascalCase('user-profile')).toBe('UserProfile');
    expect(toPascalCase('category')).toBe('Category');
  });
});

describe('extractResourceSegment', () => {
  it('extracts first non-api, non-version, non-param segment', () => {
    expect(extractResourceSegment('/api/v1/students/:id')).toBe('students');
    expect(extractResourceSegment('/api/posts')).toBe('posts');
    expect(extractResourceSegment('/api/v2.1/categories/:id')).toBe('categories');
    expect(extractResourceSegment('/items/:id/details')).toBe('items');
    expect(extractResourceSegment('/:dynamic/users')).toBe('users');
  });

  it('returns null when no valid resource segment is present', () => {
    expect(extractResourceSegment('/api/v1')).toBeNull();
    expect(extractResourceSegment('/api')).toBeNull();
    expect(extractResourceSegment('/')).toBeNull();
  });
});

describe('mapResource', () => {
  const knownModels = ['Student', 'Post', 'Category', 'User', 'BlogPost'];

  it('maps /api/v1/students/:id to Student via heuristic and records source', () => {
    const res = mapResource('/api/v1/students/:id', {}, knownModels);
    expect(res).toEqual({
      model: 'Student',
      source: 'heuristic',
    });
  });

  it('maps various REST path shapes to models via heuristic', () => {
    expect(mapResource('/api/posts', {}, knownModels)).toEqual({
      model: 'Post',
      source: 'heuristic',
    });

    expect(mapResource('/api/v2/categories/:id', {}, knownModels)).toEqual({
      model: 'Category',
      source: 'heuristic',
    });

    expect(mapResource('/blog_posts/:id', {}, knownModels)).toEqual({
      model: 'BlogPost',
      source: 'heuristic',
    });
  });

  it('allows config override to win over heuristic and records source: config', () => {
    const configOverrides = {
      '/api/v1/students': 'Pupil',
    };

    const res = mapResource('/api/v1/students/:id', configOverrides, knownModels);
    expect(res).toEqual({
      model: 'Pupil',
      source: 'config',
    });
  });

  it('selects the longest-prefix match when multiple config overrides match', () => {
    const configOverrides = {
      '/api': 'BaseModel',
      '/api/posts': 'Post',
      '/api/posts/featured': 'FeaturedPost',
    };

    // /api/posts/featured/:id matches /api, /api/posts, and /api/posts/featured
    // Longest prefix wins -> FeaturedPost
    expect(mapResource('/api/posts/featured/:id', configOverrides, knownModels)).toEqual({
      model: 'FeaturedPost',
      source: 'config',
    });

    // /api/posts/:id matches /api and /api/posts -> Post
    expect(mapResource('/api/posts/:id', configOverrides, knownModels)).toEqual({
      model: 'Post',
      source: 'config',
    });

    // /api/other matches /api -> BaseModel
    expect(mapResource('/api/other/:id', configOverrides, knownModels)).toEqual({
      model: 'BaseModel',
      source: 'config',
    });
  });

  it('returns { model: null, source: "heuristic" } for unmatched routes', () => {
    expect(mapResource('/health', {}, knownModels)).toEqual({
      model: null,
      source: 'heuristic',
    });

    expect(mapResource('/api/v1/unknown_resource', {}, knownModels)).toEqual({
      model: null,
      source: 'heuristic',
    });
  });
});
