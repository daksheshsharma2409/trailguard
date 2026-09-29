import { describe, it, expect } from 'vitest';
import { createDiff } from '../../src/runtime/diff.js';

describe('runtime/diff', () => {
  it('returns null for CREATE action', () => {
    const after = { id: 'std_1', name: 'Alice' };
    expect(createDiff(null, after, 'CREATE')).toBeNull();
    expect(createDiff(undefined, after, 'CREATE')).toBeNull();
  });

  it('returns null for DELETE action', () => {
    const before = { id: 'std_1', name: 'Alice' };
    expect(createDiff(before, null, 'DELETE')).toBeNull();
    expect(createDiff(before, undefined, 'DELETE')).toBeNull();
  });

  it('infers null for CREATE and DELETE when action is omitted', () => {
    const state = { id: 'std_1', name: 'Alice' };
    expect(createDiff(null, state)).toBeNull();
    expect(createDiff(state, null)).toBeNull();
    expect(createDiff(null, null)).toBeNull();
  });

  it('returns empty object when no fields have changed', () => {
    const before = { id: 'std_1', name: 'Alice', age: 20 };
    const after = { id: 'std_1', name: 'Alice', age: 20 };

    const diff = createDiff(before, after, 'UPDATE');
    expect(diff).toEqual({});
  });

  it('compares canonically so key reordering produces NO diff', () => {
    const before = {
      id: 'std_1',
      meta: { a: 1, b: 2 },
    };
    const after = {
      id: 'std_1',
      meta: { b: 2, a: 1 },
    };

    const diff = createDiff(before, after, 'UPDATE');
    expect(diff).toEqual({});
  });

  it('captures changes in scalar fields', () => {
    const before = { id: 'std_1', name: 'Alice', score: 85 };
    const after = { id: 'std_1', name: 'Alice', score: 95 };

    const diff = createDiff(before, after, 'UPDATE');
    expect(diff).toEqual({
      score: { old: 85, new: 95 },
    });
  });

  it('captures changes in nested objects', () => {
    const before = { id: 'std_1', config: { theme: 'dark', notifications: true } };
    const after = { id: 'std_1', config: { theme: 'light', notifications: true } };

    const diff = createDiff(before, after, 'UPDATE');
    expect(diff).toEqual({
      config: {
        old: { theme: 'dark', notifications: true },
        new: { theme: 'light', notifications: true },
      },
    });
  });

  it('handles added and removed fields', () => {
    const before = { id: 'std_1', oldField: 'value' };
    const after = { id: 'std_1', newField: 'value' };

    const diff = createDiff(before, after, 'UPDATE');
    expect(diff).toEqual({
      oldField: { old: 'value', new: null },
      newField: { old: null, new: 'value' },
    });
  });

  it('compares Dates and BigInts canonically without false diffs', () => {
    const d1 = new Date('2026-01-01T12:00:00.000Z');
    const d2 = new Date('2026-01-01T12:00:00.000Z');
    const b1 = BigInt(123456);
    const b2 = BigInt(123456);

    const before = { id: 'std_1', createdAt: d1, count: b1 };
    const after = { id: 'std_1', createdAt: d2, count: b2 };

    const diff = createDiff(before, after, 'UPDATE');
    expect(diff).toEqual({});
  });

  it('skips keys where both before and after values are undefined', () => {
    const before = { id: 'std_1', extra: undefined };
    const after = { id: 'std_1', extra: undefined };
    const diff = createDiff(before, after, 'UPDATE');
    expect(diff).toEqual({});
  });
});
