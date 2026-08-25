import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { ConfigSchema, defineConfig } from '../../src/config/schema.js';
import { loadConfig, findConfigFile } from '../../src/config/load.js';
import { ScanConfigError } from '../../src/core/errors.js';

describe('T1.5 — Config schema + loader', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'trailguard-config-test-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  describe('defineConfig', () => {
    it('returns the input config unchanged (identity function)', () => {
      const input = { entry: ['./src/index.ts'] };
      const output = defineConfig(input);
      expect(output).toBe(input);
    });
  });

  describe('ConfigSchema validation and defaults', () => {
    it('parses minimal valid config and populates all defaults', () => {
      const parsed = ConfigSchema.parse({
        entry: ['./src/app.ts'],
      });

      expect(parsed.entry).toEqual(['./src/app.ts']);
      expect(parsed.tsconfig).toBe('./tsconfig.json');
      expect(parsed.prismaSchema).toBe('./prisma/schema.prisma');
      expect(parsed.ignore).toEqual(['**/*.test.ts', '**/node_modules/**']);

      // auth defaults
      expect(parsed.auth.middleware).toEqual([]);

      // roles defaults
      expect(parsed.roles.middleware).toEqual([]);
      expect(parsed.roles.extractor).toBe('firstStringArg');
      expect(parsed.roles.known).toEqual([]);

      // ownership defaults
      expect(parsed.ownership.signals).toEqual([
        'req.user.id',
        'req.user?.id',
        'req.user.userId',
        'user.id',
      ]);
      expect(parsed.ownership.ownerFields).toEqual([
        'authorId',
        'userId',
        'ownerId',
        'tenantId',
        'createdById',
      ]);
      expect(parsed.ownership.middleware).toEqual([]);

      // audit defaults
      expect(parsed.audit.models).toEqual([]);
      expect(parsed.audit.clientNames).toEqual(['auditClient', 'audited', 'db']);
      expect(parsed.audit.routerNames).toEqual(['auditRouter']);

      // drift defaults
      expect(parsed.drift.strict).toBe(false);
      expect(parsed.drift.allowRoles).toEqual(['SYSTEM']);

      // root defaults
      expect(parsed.keyEnv).toBe('TRAILGUARD_KEY');
      expect(parsed.resources).toEqual({});
      expect(parsed.privateResources).toEqual([]);
      expect(parsed.rules).toEqual({});
      expect(parsed.baseline).toBeUndefined();
      expect(parsed.checkpoints.file).toBeUndefined();
    });

    it('rejects config without required entry field', () => {
      const res = ConfigSchema.safeParse({});
      expect(res.success).toBe(false);
      if (!res.success) {
        expect(res.error.issues[0].path).toContain('entry');
      }
    });

    it('rejects unknown top-level keys due to .strict()', () => {
      const res = ConfigSchema.safeParse({
        entry: ['./src/app.ts'],
        unknownField: true,
      });
      expect(res.success).toBe(false);
      if (!res.success) {
        expect(res.error.issues[0].code).toBe('unrecognized_keys');
      }
    });

    it('rejects unknown nested keys due to .strict() on sub-schemas', () => {
      const resAuth = ConfigSchema.safeParse({
        entry: ['./src/app.ts'],
        auth: { unknownAuthField: 'bar' },
      });
      expect(resAuth.success).toBe(false);

      const resAudit = ConfigSchema.safeParse({
        entry: ['./src/app.ts'],
        audit: { clientNames: ['client'], badAuditField: 123 },
      });
      expect(resAudit.success).toBe(false);

      const resDrift = ConfigSchema.safeParse({
        entry: ['./src/app.ts'],
        drift: { extra: true },
      });
      expect(resDrift.success).toBe(false);
    });

    it('validates rule risk overrides', () => {
      const valid = ConfigSchema.safeParse({
        entry: ['./src/app.ts'],
        rules: { RBAC001: 'high', RBAC002: 'medium', RBAC003: 'low', RBAC004: 'off' },
      });
      expect(valid.success).toBe(true);

      const invalid = ConfigSchema.safeParse({
        entry: ['./src/app.ts'],
        rules: { RBAC001: 'critical' },
      });
      expect(invalid.success).toBe(false);
    });
  });

  describe('loadConfig', () => {
    it('loads a valid TypeScript config file with jiti and resolves relative paths', async () => {
      const configPath = path.join(tmpDir, 'trailguard.config.ts');
      fs.writeFileSync(
        configPath,
        `
        export default {
          entry: ['./src/server.ts'],
          tsconfig: './custom-tsconfig.json',
          prismaSchema: './db/schema.prisma',
          baseline: './baseline.json',
          checkpoints: { file: './checkpoints.jsonl' },
          auth: { middleware: ['authenticate'] },
          roles: { middleware: ['requireRole'], extractor: 'allStringArgs', known: ['ADMIN', 'USER'] },
        };
      `,
      );

      const config = await loadConfig(configPath);

      expect(config.entry).toEqual([path.resolve(tmpDir, './src/server.ts')]);
      expect(config.tsconfig).toBe(path.resolve(tmpDir, './custom-tsconfig.json'));
      expect(config.prismaSchema).toBe(path.resolve(tmpDir, './db/schema.prisma'));
      expect(config.baseline).toBe(path.resolve(tmpDir, './baseline.json'));
      expect(config.checkpoints.file).toBe(path.resolve(tmpDir, './checkpoints.jsonl'));
      expect(config.auth.middleware).toEqual(['authenticate']);
      expect(config.roles.extractor).toBe('allStringArgs');
      expect(config.roles.known).toEqual(['ADMIN', 'USER']);

      // Verify unconfigured defaults are still populated
      expect(config.ownership.ownerFields).toEqual([
        'authorId',
        'userId',
        'ownerId',
        'tenantId',
        'createdById',
      ]);
      expect(config.audit.clientNames).toEqual(['auditClient', 'audited', 'db']);
    });

    it('loads a valid JSON config file and resolves paths', async () => {
      const configPath = path.join(tmpDir, 'trailguard.config.json');
      fs.writeFileSync(
        configPath,
        JSON.stringify({
          entry: ['./src/index.ts'],
          keyEnv: 'CUSTOM_KEY_ENV',
        }),
      );

      const config = await loadConfig(configPath);
      expect(config.entry).toEqual([path.resolve(tmpDir, './src/index.ts')]);
      expect(config.keyEnv).toBe('CUSTOM_KEY_ENV');
      expect(config.tsconfig).toBe(path.resolve(tmpDir, './tsconfig.json'));
      expect(config.prismaSchema).toBe(path.resolve(tmpDir, './prisma/schema.prisma'));
    });

    it('throws ScanConfigError naming unknown top-level keys', async () => {
      const configPath = path.join(tmpDir, 'trailguard.config.json');
      fs.writeFileSync(
        configPath,
        JSON.stringify({
          entry: ['./src/app.ts'],
          invalidTopKey: 'not allowed',
        }),
      );

      await expect(loadConfig(configPath)).rejects.toThrow(ScanConfigError);
      try {
        await loadConfig(configPath);
      } catch (err) {
        expect(err).toBeInstanceOf(ScanConfigError);
        const scanErr = err as ScanConfigError;
        expect(scanErr.code).toBe('SCAN_CONFIG_ERROR');
        expect(scanErr.message).toContain('invalidTopKey');
      }
    });

    it('throws ScanConfigError naming unknown nested keys', async () => {
      const configPath = path.join(tmpDir, 'trailguard.config.json');
      fs.writeFileSync(
        configPath,
        JSON.stringify({
          entry: ['./src/app.ts'],
          ownership: {
            typoOwnerProp: 123,
          },
        }),
      );

      await expect(loadConfig(configPath)).rejects.toThrow(ScanConfigError);
      try {
        await loadConfig(configPath);
      } catch (err) {
        expect(err).toBeInstanceOf(ScanConfigError);
        const scanErr = err as ScanConfigError;
        expect(scanErr.message).toContain('ownership.typoOwnerProp');
      }
    });

    it('throws ScanConfigError when explicit file does not exist', async () => {
      const nonExistent = path.join(tmpDir, 'does-not-exist.ts');
      await expect(loadConfig(nonExistent)).rejects.toThrow(ScanConfigError);
      try {
        await loadConfig(nonExistent);
      } catch (err) {
        expect(err).toBeInstanceOf(ScanConfigError);
        const scanErr = err as ScanConfigError;
        expect(scanErr.code).toBe('SCAN_CONFIG_ERROR');
        expect(scanErr.message).toContain('not found');
      }
    });

    it('throws ScanConfigError on malformed JSON', async () => {
      const configPath = path.join(tmpDir, 'trailguard.config.json');
      fs.writeFileSync(configPath, '{ invalid json');
      await expect(loadConfig(configPath)).rejects.toThrow(ScanConfigError);
      try {
        await loadConfig(configPath);
      } catch (err) {
        expect(err).toBeInstanceOf(ScanConfigError);
        expect((err as ScanConfigError).message).toContain('Failed to parse JSON config');
      }
    });

    it('throws ScanConfigError when config does not export an object', async () => {
      const configPath = path.join(tmpDir, 'trailguard.config.json');
      fs.writeFileSync(configPath, 'null');
      await expect(loadConfig(configPath)).rejects.toThrow(ScanConfigError);
    });

    it('auto-discovers config file by searching upward', () => {
      const configPath = path.join(tmpDir, 'trailguard.config.ts');
      fs.writeFileSync(configPath, 'export default { entry: ["./app.ts"] };');

      const deepDir = path.join(tmpDir, 'a', 'b', 'c');
      fs.mkdirSync(deepDir, { recursive: true });

      const found = findConfigFile(deepDir);
      expect(found).toBe(configPath);
    });

    it('returns undefined from findConfigFile when no config file in ancestor chain', () => {
      const emptyDir = path.join(tmpDir, 'isolated');
      fs.mkdirSync(emptyDir);
      // Create a sub directory and check - no config created
      const found = findConfigFile(emptyDir);
      // If there happens to be a config in a higher parent, that is fine,
      // but in tmpDir root if no config is created:
      expect(found).toBeUndefined();
    });
  });
});
