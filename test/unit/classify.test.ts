/**
 * Unit tests for middleware classification and role extractors.
 *
 * @see context.md §6.4
 */

import { describe, it, expect } from 'vitest';
import { Project, Node } from 'ts-morph';
import { loadFixture } from '../helpers/fixture.js';
import {
  classifyMiddleware,
  classifySingleMiddleware,
  extractRoleArgs,
  isNeutralMiddleware,
  KNOWN_NEUTRAL_MIDDLEWARE,
  type ClassificationConfig,
} from '../../src/scan/classify.js';
import { composeMounts } from '../../src/scan/mounts.js';

function createSnippetNode(code: string): Node {
  const project = new Project({ useInMemoryFileSystem: true });
  const sf = project.createSourceFile('test.ts', `const mw = ${code};`);
  const vd = sf.getVariableDeclarationOrThrow('mw');
  const init = vd.getInitializerOrThrow();
  return init;
}

const defaultConfig: ClassificationConfig = {
  auth: {
    middleware: ['authenticate', 'auth.required', 'passport.authenticate'],
  },
  roles: {
    middleware: ['requireRole', 'auth.hasRole'],
    extractor: 'firstStringArg',
    known: ['admin', 'editor', 'user'],
  },
  ownership: {
    signals: ['req.user.id'],
    ownerFields: ['authorId'],
    middleware: ['checkOwnership', 'ownership.verify'],
  },
};

describe('Middleware classification table-driven tests (§6.4)', () => {
  interface TestCase {
    name: string;
    code: string;
    extractor?: 'firstStringArg' | 'allStringArgs' | 'arrayArg';
    expected: Array<{ kind: string; value?: string }>;
  }

  const tableCases: TestCase[] = [
    // Row 1: name ∈ auth.middleware
    {
      name: 'Row 1a: auth middleware identifier',
      code: 'authenticate',
      expected: [{ kind: 'auth' }],
    },
    {
      name: 'Row 1b: auth middleware property access',
      code: 'auth.required',
      expected: [{ kind: 'auth' }],
    },
    {
      name: 'Row 1c: auth middleware call expression',
      code: "passport.authenticate('jwt')",
      expected: [{ kind: 'auth' }],
    },

    // Row 2: callee ∈ roles.middleware + firstStringArg
    {
      name: 'Row 2: roles middleware with firstStringArg extractor',
      code: "requireRole('admin')",
      extractor: 'firstStringArg',
      expected: [{ kind: 'role', value: 'admin' }],
    },
    {
      name: 'Row 2b: roles property access with firstStringArg',
      code: "auth.hasRole('editor')",
      extractor: 'firstStringArg',
      expected: [{ kind: 'role', value: 'editor' }],
    },

    // Row 3: callee ∈ roles.middleware + allStringArgs
    {
      name: 'Row 3: roles middleware with allStringArgs extractor',
      code: "requireRole('admin', 'editor')",
      extractor: 'allStringArgs',
      expected: [
        { kind: 'role', value: 'admin' },
        { kind: 'role', value: 'editor' },
      ],
    },

    // Row 4: callee ∈ roles.middleware + arrayArg
    {
      name: 'Row 4: roles middleware with arrayArg extractor',
      code: "requireRole(['admin', 'editor'])",
      extractor: 'arrayArg',
      expected: [
        { kind: 'role', value: 'admin' },
        { kind: 'role', value: 'editor' },
      ],
    },

    // Row 5: callee ∈ roles.middleware but args not literal → role:unknown
    {
      name: 'Row 5a: non-literal variable arg in requireRole',
      code: 'requireRole(ROLE_VAR)',
      extractor: 'firstStringArg',
      expected: [{ kind: 'role', value: 'unknown' }],
    },
    {
      name: 'Row 5b: empty args in requireRole',
      code: 'requireRole()',
      extractor: 'firstStringArg',
      expected: [{ kind: 'role', value: 'unknown' }],
    },
    {
      name: 'Row 5c: mixed literal and non-literal in arrayArg',
      code: "requireRole(['admin', SOME_VAR])",
      extractor: 'arrayArg',
      expected: [{ kind: 'role', value: 'unknown' }],
    },
    {
      name: 'Row 5d: role middleware passed as uncalled reference',
      code: 'requireRole',
      extractor: 'firstStringArg',
      expected: [{ kind: 'role', value: 'unknown' }],
    },

    // Row 6: inline fn body mentions req.user.role / req.user?.role → role:unknown
    {
      name: 'Row 6a: inline arrow function mentioning req.user?.role',
      code: "(req, res, next) => { if (req.user?.role !== 'admin') return res.status(403); next(); }",
      expected: [{ kind: 'role', value: 'unknown' }],
    },
    {
      name: 'Row 6b: inline function expression mentioning req.user.role',
      code: "function(req, res, next) { if (req.user.role === 'admin') next(); }",
      expected: [{ kind: 'role', value: 'unknown' }],
    },

    // Row 7: name ∈ ownership.middleware
    {
      name: 'Row 7a: ownership middleware identifier',
      code: 'checkOwnership',
      expected: [{ kind: 'ownership' }],
    },
    {
      name: 'Row 7b: ownership middleware property access',
      code: 'ownership.verify',
      expected: [{ kind: 'ownership' }],
    },

    // Row 8: Known neutral middleware
    {
      name: 'Row 8a: express.json() call',
      code: 'express.json()',
      expected: [{ kind: 'neutral' }],
    },
    {
      name: 'Row 8b: cors() call',
      code: 'cors()',
      expected: [{ kind: 'neutral' }],
    },
    {
      name: 'Row 8c: helmet() call',
      code: 'helmet()',
      expected: [{ kind: 'neutral' }],
    },
    {
      name: 'Row 8d: morgan() call',
      code: "morgan('combined')",
      expected: [{ kind: 'neutral' }],
    },
    {
      name: 'Row 8e: compression() call',
      code: 'compression()',
      expected: [{ kind: 'neutral' }],
    },

    // Row 9: Anything else → unknown
    {
      name: 'Row 9a: custom arbitrary identifier',
      code: 'customAuditTracker',
      expected: [{ kind: 'unknown' }],
    },
    {
      name: 'Row 9b: arbitrary call expression',
      code: 'rateLimiter({ max: 100 })',
      expected: [{ kind: 'unknown' }],
    },
    {
      name: 'Row 9c: inline function without role check',
      code: '(req, res, next) => { console.log(req.url); next(); }',
      expected: [{ kind: 'unknown' }],
    },
  ];

  for (const tc of tableCases) {
    it(tc.name, () => {
      const node = createSnippetNode(tc.code);
      const cfg: ClassificationConfig = {
        ...defaultConfig,
        roles: {
          ...defaultConfig.roles,
          extractor: tc.extractor ?? 'firstStringArg',
        },
      };

      const refs = classifyMiddleware(node, cfg);
      expect(refs.length).toBe(tc.expected.length);

      for (let i = 0; i < tc.expected.length; i++) {
        const exp = tc.expected[i];
        const act = refs[i];
        expect(act).toBeDefined();
        expect(act?.class.kind).toBe(exp?.kind);
        if (exp?.value !== undefined) {
          expect(act?.class).toEqual({ kind: exp.kind, value: exp.value });
        }
      }
    });
  }
});

describe('Safety guarantees: unknown middleware is never classified as auth/role', () => {
  it('guarantees unknown middleware never produces auth or role kind', () => {
    const unknownSnippets = [
      'customTelemetry',
      'rateLimiter()',
      'requestLogger',
      'validator()',
      'encryptPayload',
      '(req, res, next) => next()',
    ];

    for (const code of unknownSnippets) {
      const node = createSnippetNode(code);
      const refs = classifyMiddleware(node, defaultConfig);
      for (const ref of refs) {
        expect(ref.class.kind).not.toBe('auth');
        expect(ref.class.kind).not.toBe('role');
        expect(ref.class.kind).toBe('unknown');
      }
    }
  });

  it('classifies single middleware helper', () => {
    const node = createSnippetNode("requireRole('admin')");
    const ref = classifySingleMiddleware(node, defaultConfig);
    expect(ref.class).toEqual({ kind: 'role', value: 'admin' });
    expect(ref.args).toEqual(['admin']);
  });
});

describe('Role extractors unit tests', () => {
  it('extracts role with firstStringArg', () => {
    const call1 = createSnippetNode("requireRole('admin', 'editor')");
    const res1 = extractRoleArgs(call1, 'firstStringArg');
    expect(res1.literals).toEqual(['admin']);
    expect(res1.hasNonLiteral).toBe(false);

    const call2 = createSnippetNode('requireRole(MY_ROLE)');
    const res2 = extractRoleArgs(call2, 'firstStringArg');
    expect(res2.hasNonLiteral).toBe(true);
  });

  it('extracts roles with allStringArgs', () => {
    const call1 = createSnippetNode("requireRole('admin', 'editor', 'viewer')");
    const res1 = extractRoleArgs(call1, 'allStringArgs');
    expect(res1.literals).toEqual(['admin', 'editor', 'viewer']);
    expect(res1.hasNonLiteral).toBe(false);

    const call2 = createSnippetNode("requireRole('admin', DYNAMIC_ROLE)");
    const res2 = extractRoleArgs(call2, 'allStringArgs');
    expect(res2.hasNonLiteral).toBe(true);
  });

  it('extracts roles with arrayArg', () => {
    const call1 = createSnippetNode("requireRole(['admin', 'editor'])");
    const res1 = extractRoleArgs(call1, 'arrayArg');
    expect(res1.literals).toEqual(['admin', 'editor']);
    expect(res1.hasNonLiteral).toBe(false);

    const call2 = createSnippetNode("requireRole(['admin', SOME_VAR])");
    const res2 = extractRoleArgs(call2, 'arrayArg');
    expect(res2.hasNonLiteral).toBe(true);
  });
});

describe('Known neutral middleware list', () => {
  it('recognizes all items in KNOWN_NEUTRAL_MIDDLEWARE', () => {
    for (const item of KNOWN_NEUTRAL_MIDDLEWARE) {
      expect(isNeutralMiddleware(item)).toBe(true);
      expect(isNeutralMiddleware(`${item}()`)).toBe(true);
    }
    expect(isNeutralMiddleware('express.json')).toBe(true);
    expect(isNeutralMiddleware('express.json()')).toBe(true);
    expect(isNeutralMiddleware('authenticate')).toBe(false);
  });
});

describe('Classification with unknown-mw fixture', () => {
  it('loads unknown-mw fixture and correctly classifies neutral vs unknown middleware', async () => {
    const { project, config } = await loadFixture('unknown-mw');
    const { routes } = composeMounts(project);

    expect(routes.length).toBe(1);
    const route = routes[0];
    expect(route).toBeDefined();
    expect(route?.path).toBe('/data');

    const classified = route?.middlewareArgs.flatMap((m) =>
      classifyMiddleware(m, config),
    ) ?? [];

    expect(classified.length).toBe(2);

    const jsonMw = classified.find((c) => c.text.includes('express.json'));
    expect(jsonMw).toBeDefined();
    expect(jsonMw?.class.kind).toBe('neutral');

    const customMw = classified.find((c) => c.text === 'customTelemetry');
    expect(customMw).toBeDefined();
    expect(customMw?.class.kind).toBe('unknown');
  });
});
