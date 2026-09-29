/**
 * Unit tests for the Prisma schema parser.
 *
 * @see context.md §6.5
 */

import { describe, it, expect } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import {
  parsePrismaSchema,
  loadPrismaSchema,
  stripComments,
} from '../../src/scan/prisma-schema.js';
import { ScanConfigError } from '../../src/core/errors.js';

describe('stripComments', () => {
  it('strips line comments and doc comments', () => {
    expect(stripComments('// comment')).toBe('');
    expect(stripComments('/// doc comment')).toBe('');
    expect(stripComments('id String @id // primary key')).toBe('id String @id');
  });

  it('preserves slashes inside string literals', () => {
    expect(stripComments('url String @default("https://example.com") // link')).toBe(
      'url String @default("https://example.com")',
    );
  });
});

describe('parsePrismaSchema', () => {
  const sampleSchema = `
    // Datasource block to skip
    datasource db {
      provider = "mysql"
      url      = env("DATABASE_URL")
    }

    generator client {
      provider = "prisma-client-js"
    }

    /// User model documentation
    model User {
      id        String   @id @default(cuid())
      email     String   @unique
      bio       String?
      role      String   @default("USER")
      posts     Post[]
      createdAt DateTime @default(now())

      @@map("users")
    }

    model Post {
      id        Int      @id @default(autoincrement())
      title     String
      content   String?
      authorId  String
      author    User     @relation("UserPosts", fields: [authorId], references: [id])
      tags      String[]
      tenantId  String

      @@index([tenantId])
    }

    model CompositeKeyRecord {
      tenantId  String
      recordId  String
      data      String

      @@id([tenantId, recordId])
    }
  `;

  it('parses models and respects @@map for table names', () => {
    const result = parsePrismaSchema(sampleSchema);

    expect(result.size).toBe(3);
    expect(result.has('User')).toBe(true);
    expect(result.has('Post')).toBe(true);
    expect(result.has('CompositeKeyRecord')).toBe(true);

    const user = result.get('User');
    expect(user).toBeDefined();
    expect(user?.tableName).toBe('users');

    const post = result.get('Post');
    expect(post).toBeDefined();
    expect(post?.tableName).toBe('Post');
  });

  it('parses optional and list field modifiers', () => {
    const result = parsePrismaSchema(sampleSchema);
    const user = result.get('User');
    const post = result.get('Post');

    // Optional field bio?
    const bio = user?.fields.get('bio');
    expect(bio?.isOptional).toBe(true);
    expect(bio?.isList).toBe(false);
    expect(bio?.type).toBe('String');

    // Non-optional field email
    const email = user?.fields.get('email');
    expect(email?.isOptional).toBe(false);
    expect(email?.isList).toBe(false);

    // List field tags String[]
    const tags = post?.fields.get('tags');
    expect(tags?.isList).toBe(true);
    expect(tags?.isOptional).toBe(false);
    expect(tags?.type).toBe('String');

    // Model relation list posts Post[]
    const posts = user?.fields.get('posts');
    expect(posts?.isList).toBe(true);
    expect(posts?.type).toBe('Post');
  });

  it('parses @id, @@id, and @unique attributes', () => {
    const result = parsePrismaSchema(sampleSchema);

    const user = result.get('User');
    expect(user?.idFields).toEqual(['id']);
    expect(user?.fields.get('id')?.isId).toBe(true);
    expect(user?.fields.get('email')?.isUnique).toBe(true);

    const composite = result.get('CompositeKeyRecord');
    expect(composite?.idFields).toEqual(['tenantId', 'recordId']);
  });

  it('parses @relation attributes with fields, references, and relation name', () => {
    const result = parsePrismaSchema(sampleSchema);
    const post = result.get('Post');

    expect(post?.relations.has('author')).toBe(true);
    const rel = post?.relations.get('author');
    expect(rel?.relationField).toBe('author');
    expect(rel?.targetModel).toBe('User');
    expect(rel?.fields).toEqual(['authorId']);
    expect(rel?.references).toEqual(['id']);
    expect(rel?.name).toBe('UserPosts');
  });

  it('detects owner fields (in relation or *Id scalar matching config list)', () => {
    const result = parsePrismaSchema(sampleSchema);
    const post = result.get('Post');

    // authorId appears in @relation(fields: [authorId])
    // tenantId ends with Id and is scalar
    expect(post?.ownerFields).toContain('authorId');
    expect(post?.ownerFields).toContain('tenantId');
    expect(post?.ownerFields).not.toContain('title');
  });

  it('throws ScanConfigError with line number on unclosed model block', () => {
    const badSchema = `
      model User {
        id String @id
    `;

    expect(() => parsePrismaSchema(badSchema, { filePath: 'bad.prisma' })).toThrow(
      ScanConfigError,
    );

    try {
      parsePrismaSchema(badSchema, { filePath: 'bad.prisma' });
    } catch (err) {
      expect(err).toBeInstanceOf(ScanConfigError);
      const e = err as ScanConfigError;
      expect(e.filePath).toBe('bad.prisma');
      expect(e.lineNumber).toBe(2);
      expect(e.message).toContain('Unclosed model');
    }
  });

  it('throws ScanConfigError with line number on invalid field syntax', () => {
    const badSchema = `
      model User {
        id
      }
    `;

    try {
      parsePrismaSchema(badSchema, { filePath: 'syntax.prisma' });
    } catch (err) {
      expect(err).toBeInstanceOf(ScanConfigError);
      const e = err as ScanConfigError;
      expect(e.filePath).toBe('syntax.prisma');
      expect(e.lineNumber).toBe(3);
      expect(e.message).toContain('Invalid field definition');
    }
  });
});

describe('loadPrismaSchema', () => {
  it('throws ScanConfigError when file does not exist', () => {
    expect(() => loadPrismaSchema('/nonexistent/path/schema.prisma')).toThrow(
      ScanConfigError,
    );
  });

  it('loads and parses schema from disk', () => {
    const tmpDir = path.resolve('test/fixtures/clean/prisma');
    if (!fs.existsSync(tmpDir)) {
      fs.mkdirSync(tmpDir, { recursive: true });
    }
    const schemaPath = path.join(tmpDir, 'schema.prisma');
    fs.writeFileSync(
      schemaPath,
      `
      model Student {
        id        String @id
        authorId  String
        name      String
      }
      `,
    );

    const result = loadPrismaSchema(schemaPath);
    expect(result.has('Student')).toBe(true);
    expect(result.get('Student')?.ownerFields).toContain('authorId');
  });

  it('re-throws ScanConfigError when reading malformed schema from disk', () => {
    const tmpDir = path.resolve('test/fixtures/clean/prisma');
    const schemaPath = path.join(tmpDir, 'malformed.prisma');
    fs.writeFileSync(schemaPath, 'model Unclosed { id String @id');
    try {
      expect(() => loadPrismaSchema(schemaPath)).toThrow(ScanConfigError);
    } finally {
      if (fs.existsSync(schemaPath)) fs.unlinkSync(schemaPath);
    }
  });

  it('throws ScanConfigError on unexpected token outside model block', () => {
    const bad = 'someToken { foo String }';
    expect(() => parsePrismaSchema(bad)).toThrow(ScanConfigError);
  });

  it('parses relations without explicit names', () => {
    const schema = `
      model Comment {
        id Int @id
        postId Int
        post Post @relation(fields: [postId], references: [id])
      }
    `;
    const result = parsePrismaSchema(schema);
    const comment = result.get('Comment');
    expect(comment?.relations.get('post')?.name).toBeUndefined();
    expect(comment?.relations.get('post')?.fields).toEqual(['postId']);
  });

  it('parses enums, quoted field attributes, and composite relations', () => {
    expect(stripComments("val String @default('test // single') // comment")).toBe(
      "val String @default('test // single')",
    );

    const schema = `
      datasource db {
        provider = "mysql"
        url = env("DATABASE_URL")
      }

      generator client {
        provider = "prisma-client-js"
      }

      enum Role {
        ADMIN
        USER
      }

      model Item {
        id Int @id @default(autoincrement())
        name String @default("item name with spaces")
        ownerId String
        tenantId String
        user User @relation("ItemUser", fields: [ownerId, tenantId], references: [id, tenantId])

        @@unique([name, ownerId])
        @@index([tenantId])
      }
    `;

    const result = parsePrismaSchema(schema);
    expect(result.has('Item')).toBe(true);
    const item = result.get('Item');
    expect(item?.relations.get('user')?.fields).toEqual(['ownerId', 'tenantId']);
    expect(item?.relations.get('user')?.references).toEqual(['id', 'tenantId']);
    expect(item?.relations.get('user')?.name).toBe('ItemUser');
  });
});
