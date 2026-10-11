/**
 * Unit tests for audit log export (JSON and CSV formats, formula injection safety, streaming).
 *
 * @see context.md §7.10, tasks.md T3.11
 */

import { describe, it, expect, vi } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import express from 'express';
import request from 'supertest';
import {
  escapeCsvCell,
  exportAuditLogs,
  exportAuditLogsToFile,
  serializeRowForJson,
  CSV_COLUMNS,
  type ExportPrismaClient,
} from '../../src/runtime/export.js';
import { auditRouter, type RouterPrismaClient } from '../../src/runtime/router.js';

describe('escapeCsvCell formula injection and RFC 4180 escaping', () => {
  it('prefixes cells starting with =, +, -, @, \\t, \\r with a single quote', () => {
    expect(escapeCsvCell('=HYPERLINK("http://evil.com","Click")')).toBe(
      `"'=HYPERLINK(""http://evil.com"",""Click"")"`,
    );
    expect(escapeCsvCell('=HYPERLINK(...)')).toBe("'=HYPERLINK(...)");
    expect(escapeCsvCell('+cmd|/C')).toBe("'+cmd|/C");
    expect(escapeCsvCell('-25')).toBe("'-25");
    expect(escapeCsvCell('@SUM(A1:A10)')).toBe("'@SUM(A1:A10)");
    expect(escapeCsvCell('\ttabbed')).toBe("'\ttabbed");
    expect(escapeCsvCell('\rreturn')).toBe("\"'\rreturn\"");
  });

  it('escapes commas, quotes, and newlines properly per RFC 4180', () => {
    expect(escapeCsvCell('hello, world')).toBe('"hello, world"');
    expect(escapeCsvCell('He said "hello"')).toBe('"He said ""hello"""');
    expect(escapeCsvCell('Line 1\nLine 2')).toBe('"Line 1\nLine 2"');
    expect(escapeCsvCell('Line 1\r\nLine 2')).toBe(`"Line 1\r\nLine 2"`);
  });

  it('handles null, undefined, bigints, dates, and json objects', () => {
    expect(escapeCsvCell(null)).toBe('');
    expect(escapeCsvCell(undefined)).toBe('');
    expect(escapeCsvCell(123n)).toBe('123');
    const d = new Date('2026-01-01T00:00:00.000Z');
    expect(escapeCsvCell(d)).toBe('2026-01-01T00:00:00.000Z');
    expect(escapeCsvCell({ a: 1, b: 'two' })).toBe(`"{""a"":1,""b"":""two""}"`);
  });

  it('returns normal string untouched when no escaping or prefix is needed', () => {
    expect(escapeCsvCell('regular text')).toBe('regular text');
    expect(escapeCsvCell('Student')).toBe('Student');
    expect(escapeCsvCell('CREATE')).toBe('CREATE');
  });
});

describe('serializeRowForJson', () => {
  it('converts BigInt to string and Date to ISO string', () => {
    const row = {
      seq: 42n,
      model: 'Student',
      createdAt: new Date('2026-01-01T12:00:00.000Z'),
      diff: { name: 'Alice' },
    };
    const serialized = serializeRowForJson(row);
    expect(serialized['seq']).toBe('42');
    expect(serialized['createdAt']).toBe('2026-01-01T12:00:00.000Z');
    expect(serialized['model']).toBe('Student');
    expect(serialized['diff']).toEqual({ name: 'Alice' });
  });
});

describe('exportAuditLogs cursor-batch streaming', () => {
  const mockRows = [
    {
      seq: 1n,
      model: 'Student',
      recordId: 'rec-1',
      action: 'CREATE',
      actorId: 'user-1',
      actorRole: 'ADMIN',
      requestId: 'req-1',
      ipAddress: '127.0.0.1',
      userAgent: 'Mozilla',
      before: null,
      after: { name: 'Alice' },
      diff: { name: 'Alice' },
      prevHash: '0000000000000000000000000000000000000000000000000000000000000000',
      hash: '1111111111111111111111111111111111111111111111111111111111111111',
      keyId: 'k1',
      createdAt: new Date('2026-01-01T00:00:00.000Z'),
    },
    {
      seq: 2n,
      model: 'Student',
      recordId: '=HYPERLINK("http://evil.com","Alice")',
      action: 'UPDATE',
      actorId: 'user-1',
      actorRole: 'ADMIN',
      requestId: 'req-2',
      ipAddress: '127.0.0.1',
      userAgent: 'Mozilla',
      before: { name: 'Alice' },
      after: { name: '=HYPERLINK("http://evil.com","Alice")' },
      diff: { name: '=HYPERLINK("http://evil.com","Alice")' },
      prevHash: '1111111111111111111111111111111111111111111111111111111111111111',
      hash: '2222222222222222222222222222222222222222222222222222222222222222',
      keyId: 'k1',
      createdAt: new Date('2026-01-01T00:01:00.000Z'),
    },
    {
      seq: 3n,
      model: 'User',
      recordId: 'rec-2',
      action: 'DELETE',
      actorId: 'user-2',
      actorRole: 'ADMIN',
      requestId: 'req-3',
      ipAddress: '127.0.0.1',
      userAgent: 'Mozilla',
      before: { username: 'bob' },
      after: null,
      diff: null,
      prevHash: '2222222222222222222222222222222222222222222222222222222222222222',
      hash: '3333333333333333333333333333333333333333333333333333333333333333',
      keyId: 'k1',
      createdAt: new Date('2026-01-01T00:02:00.000Z'),
    },
  ];

  it('batches cursor queries without loading all rows into memory at once', async () => {
    const findManyMock = vi.fn().mockImplementation((args: { take?: number; cursor?: { seq?: bigint }; skip?: number }) => {
      const take = args.take ?? 500;
      const cursor = args.cursor?.seq;
      const skip = args.skip ?? 0;

      let startIdx = 0;
      if (cursor !== undefined) {
        startIdx = mockRows.findIndex((r) => r.seq === cursor) + skip;
      }
      return Promise.resolve(mockRows.slice(startIdx, startIdx + take));
    });

    const mockPrisma: ExportPrismaClient = {
      auditLog: {
        findMany: findManyMock,
      },
    };

    // Use batchSize: 2 to force cursor pagination across 2 pages
    const chunks: string[] = [];
    for await (const chunk of exportAuditLogs(mockPrisma, { format: 'csv', batchSize: 2 })) {
      chunks.push(chunk);
    }

    const fullCsv = chunks.join('');
    // First line must be header
    expect(fullCsv.startsWith(CSV_COLUMNS.join(','))).toBe(true);

    // Verify pagination calls
    expect(findManyMock).toHaveBeenCalledTimes(2);
    expect(findManyMock.mock.calls[0]![0]).toMatchObject({ take: 2, orderBy: { seq: 'asc' } });
    expect(findManyMock.mock.calls[1]![0]).toMatchObject({
      take: 2,
      cursor: { seq: 2n },
      skip: 1,
    });

    // Verify formula injection sanitization in row 2
    expect(fullCsv).toContain(`"'=HYPERLINK(""http://evil.com"",""Alice"")"`);
  });

  it('produces valid parseable JSON array', async () => {
    const mockPrisma: ExportPrismaClient = {
      auditLog: {
        findMany: vi.fn().mockResolvedValue(mockRows),
      },
    };

    const chunks: string[] = [];
    for await (const chunk of exportAuditLogs(mockPrisma, { format: 'json', batchSize: 10 })) {
      chunks.push(chunk);
    }

    const jsonString = chunks.join('');
    const parsed = JSON.parse(jsonString) as Array<Record<string, unknown>>;
    expect(parsed.length).toBe(3);
    expect(parsed[0]!['seq']).toBe('1');
    expect(parsed[1]!['seq']).toBe('2');
    expect(parsed[2]!['seq']).toBe('3');
    expect(parsed[0]!['model']).toBe('Student');
  });

  it('handles empty audit log gracefully', async () => {
    const mockPrisma: ExportPrismaClient = {
      auditLog: {
        findMany: vi.fn().mockResolvedValue([]),
      },
    };

    // JSON
    const jsonChunks: string[] = [];
    for await (const chunk of exportAuditLogs(mockPrisma, { format: 'json' })) {
      jsonChunks.push(chunk);
    }
    expect(JSON.parse(jsonChunks.join(''))).toEqual([]);

    // CSV
    const csvChunks: string[] = [];
    for await (const chunk of exportAuditLogs(mockPrisma, { format: 'csv' })) {
      csvChunks.push(chunk);
    }
    expect(csvChunks.join('')).toBe(CSV_COLUMNS.join(',') + '\n');
  });

  it('exportAuditLogsToFile writes streamed export directly to disk', async () => {
    const mockPrisma: ExportPrismaClient = {
      auditLog: {
        findMany: vi.fn().mockResolvedValue(mockRows),
      },
    };

    const tmpFile = path.join(os.tmpdir(), `trailguard-export-test-${Date.now().toString()}.csv`);
    try {
      await exportAuditLogsToFile(mockPrisma, { format: 'csv' }, tmpFile);
      expect(fs.existsSync(tmpFile)).toBe(true);
      const content = fs.readFileSync(tmpFile, 'utf-8');
      expect(content).toContain(CSV_COLUMNS.join(','));
      expect(content).toContain('rec-1');
      expect(content).toContain('rec-2');
    } finally {
      if (fs.existsSync(tmpFile)) {
        fs.unlinkSync(tmpFile);
      }
    }
  });
});

describe('auditRouter GET /export endpoint', () => {
  const dummyPrisma: RouterPrismaClient = {
    auditLog: {
      findMany: vi.fn().mockResolvedValue([
        {
          seq: 1n,
          model: 'Student',
          recordId: '=DDE("server")',
          action: 'CREATE',
          actorId: 'admin-1',
          actorRole: 'ADMIN',
          requestId: 'req-1',
          ipAddress: '127.0.0.1',
          userAgent: 'curl',
          before: null,
          after: { name: '=DDE("server")' },
          diff: { name: '=DDE("server")' },
          prevHash: '0000000000000000000000000000000000000000000000000000000000000000',
          hash: 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
          keyId: 'k1',
          createdAt: new Date('2026-01-01T00:00:00.000Z'),
        },
      ]),
    },
  };

  const app = express();
  app.use(
    '/audit',
    auditRouter({
      guard: (_req, _res, next) => next(),
      prisma: dummyPrisma,
      keys: { secret: '01234567890123456789012345678901' },
      models: ['Student'],
    }),
  );

  it('streams CSV with formula injection defense and correct headers', async () => {
    const res = await request(app)
      .get('/audit/export?format=csv')
      .expect(200);

    expect(res.headers['content-type']).toContain('text/csv');
    expect(res.headers['content-disposition']).toContain('audit-log.csv');
    expect(res.text).toContain(CSV_COLUMNS.join(','));
    // Sanitized formula injection
    expect(res.text).toContain(`"'=DDE(""server"")"`);
  });

  it('streams JSON with correct headers and valid array body', async () => {
    const res = await request(app)
      .get('/audit/export?format=json')
      .expect(200);

    expect(res.headers['content-type']).toContain('application/json');
    expect(res.headers['content-disposition']).toContain('audit-log.json');
    const parsed = JSON.parse(res.text);
    expect(Array.isArray(parsed)).toBe(true);
    expect(parsed[0].seq).toBe('1');
    expect(parsed[0].model).toBe('Student');
  });

  it('validates model query and rejects unknown model', async () => {
    const res = await request(app)
      .get('/audit/export?format=json&model=UnknownModel')
      .expect(400);

    expect(res.body.error).toContain("Unknown model 'UnknownModel'");
  });
});
