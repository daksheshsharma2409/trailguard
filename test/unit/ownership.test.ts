/**
 * Unit tests for the ownership heuristic.
 *
 * @see context.md §6.7
 */

import { describe, it, expect } from 'vitest';
import { Project } from 'ts-morph';
import { loadFixture } from '../helpers/fixture.js';
import { checkOwnershipHeuristic } from '../../src/scan/ownership.js';
import { resolveHandler } from '../../src/scan/handlers.js';
import { composeMounts } from '../../src/scan/mounts.js';
import { loadPrismaSchema } from '../../src/scan/prisma-schema.js';

function createResolvedHandler(bodyCode: string) {
  const project = new Project({ useInMemoryFileSystem: true });
  const sf = project.createSourceFile('handler.ts', `const h = (req: any, res: any) => { ${bodyCode} };`);
  const vd = sf.getVariableDeclarationOrThrow('h');
  const init = vd.getInitializerOrThrow();
  return resolveHandler(init);
}

describe('checkOwnershipHeuristic', () => {
  it('returns "probable" for where: { id, authorId: req.user.id }', () => {
    const handler = createResolvedHandler(`
      const deleted = await prisma.post.delete({
        where: { id: req.params.id, authorId: req.user.id },
      });
    `);

    const result = checkOwnershipHeuristic(handler, {
      ownerFields: ['authorId'],
      signals: ['req.user.id'],
    });

    expect(result).toBe('probable');
  });

  it('returns "probable" for where: { authorId: req.user?.id }', () => {
    const handler = createResolvedHandler(`
      const updated = await prisma.post.update({
        where: { authorId: req.user?.id },
        data: { title: 'Updated' },
      });
    `);

    const result = checkOwnershipHeuristic(handler, {
      ownerFields: ['authorId'],
      signals: ['req.user?.id'],
    });

    expect(result).toBe('probable');
  });

  it('returns "probable" for binary check if (post.authorId !== req.user.id)', () => {
    const handler = createResolvedHandler(`
      const post = await prisma.post.findUnique({ where: { id } });
      if (post.authorId !== req.user.id) {
        return res.status(403).json({ error: 'Forbidden' });
      }
      await prisma.post.delete({ where: { id } });
    `);

    const result = checkOwnershipHeuristic(handler, {
      ownerFields: ['authorId'],
      signals: ['req.user.id'],
    });

    expect(result).toBe('probable');
  });

  it('returns "none" for handler without any ownership signals', () => {
    const handler = createResolvedHandler(`
      const deleted = await prisma.post.delete({
        where: { id: req.params.id },
      });
      res.json(deleted);
    `);

    const result = checkOwnershipHeuristic(handler, {
      ownerFields: ['authorId'],
      signals: ['req.user.id'],
    });

    expect(result).toBe('none');
  });

  it('returns "none" when signal is logged but not tied to where or owner field', () => {
    const handler = createResolvedHandler(`
      console.log('Accessed by user:', req.user.id);
      const deleted = await prisma.post.delete({
        where: { id: req.params.id },
      });
      res.json(deleted);
    `);

    const result = checkOwnershipHeuristic(handler, {
      ownerFields: ['authorId'],
      signals: ['req.user.id'],
    });

    expect(result).toBe('none');
  });

  it('returns "unknown" for unresolved handler', () => {
    const unresolved = {
      resolved: false,
      name: 'externalPackageHandler',
    };

    const result = checkOwnershipHeuristic(unresolved);
    expect(result).toBe('unknown');
  });

  it('returns "unknown" for undefined handler', () => {
    const result = checkOwnershipHeuristic(undefined);
    expect(result).toBe('unknown');
  });

  it('handles non-block arrow function bodies', () => {
    const project = new Project({ useInMemoryFileSystem: true });
    const sf = project.createSourceFile('handler.ts', `const h = (req: any, res: any) => res.json({ authorId: req.user.id });`);
    const vd = sf.getVariableDeclarationOrThrow('h');
    const handler = resolveHandler(vd.getInitializerOrThrow());
    const result = checkOwnershipHeuristic(handler, {
      ownerFields: ['authorId'],
      signals: ['req.user.id'],
    });
    expect(result).toBe('probable');
  });

  it('matches statement-level regex for where or ownerField', () => {
    const handler = createResolvedHandler(`
      rawQuery("where: authorId = ?", req.user.id);
    `);
    const result = checkOwnershipHeuristic(handler, {
      ownerFields: ['authorId'],
      signals: ['req.user.id'],
    });
    expect(result).toBe('probable');
  });
});

describe('Ownership heuristic over fixtures', () => {
  it('detects "probable" ownership on ownership-ok fixture', async () => {
    const { project, config } = await loadFixture('ownership-ok');
    const schema = loadPrismaSchema(config.prismaSchema, config.ownership.ownerFields);
    const postModel = schema.get('Post');
    expect(postModel).toBeDefined();

    const { routes } = composeMounts(project);
    expect(routes.length).toBe(1);

    const deleteRoute = routes[0];
    expect(deleteRoute?.method).toBe('DELETE');
    expect(deleteRoute?.resolvedHandler).toBeDefined();

    const ownership = checkOwnershipHeuristic(deleteRoute?.resolvedHandler, {
      signals: config.ownership.signals,
      ownerFields: postModel?.ownerFields,
    });

    expect(ownership).toBe('probable');
  });

  it('detects "none" ownership on ownership-missing fixture', async () => {
    const { project, config } = await loadFixture('ownership-missing');
    const schema = loadPrismaSchema(config.prismaSchema, config.ownership.ownerFields);
    const postModel = schema.get('Post');
    expect(postModel).toBeDefined();

    const { routes } = composeMounts(project);
    expect(routes.length).toBe(1);

    const deleteRoute = routes[0];
    expect(deleteRoute?.method).toBe('DELETE');
    expect(deleteRoute?.resolvedHandler).toBeDefined();

    const ownership = checkOwnershipHeuristic(deleteRoute?.resolvedHandler, {
      signals: config.ownership.signals,
      ownerFields: postModel?.ownerFields,
    });

    expect(ownership).toBe('none');
  });
});
