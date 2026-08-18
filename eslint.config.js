// @ts-check
import eslint from '@eslint/js';
import tseslint from 'typescript-eslint';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));

export default tseslint.config(
  eslint.configs.recommended,
  ...tseslint.configs.strictTypeChecked,
  {
    // Source files: use the production tsconfig
    files: ['src/**/*.ts'],
    languageOptions: {
      parserOptions: {
        project: resolve(__dirname, 'tsconfig.json'),
        tsconfigRootDir: __dirname,
      },
    },
    rules: {
      '@typescript-eslint/no-explicit-any': 'error',
      '@typescript-eslint/no-non-null-assertion': 'error',
      '@typescript-eslint/only-throw-error': 'off',
      'no-throw-literal': 'off',
      // Allow underscore-prefixed args to be unused (Commander action stubs)
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_' },
      ],
      // These assertions are intentional in load.ts (raw config cast before safeParse)
      '@typescript-eslint/no-unnecessary-type-assertion': 'off',
    },
  },
  {
    // Test files: use the test tsconfig (includes both src + test)
    files: ['test/**/*.ts'],
    languageOptions: {
      parserOptions: {
        project: resolve(__dirname, 'tsconfig.test.json'),
        tsconfigRootDir: __dirname,
      },
    },
    rules: {
      '@typescript-eslint/no-explicit-any': 'error',
      '@typescript-eslint/no-non-null-assertion': 'off',
      '@typescript-eslint/no-unsafe-assignment': 'off',
      '@typescript-eslint/no-unsafe-member-access': 'off',
      '@typescript-eslint/no-unsafe-call': 'off',
      '@typescript-eslint/no-unsafe-argument': 'off',
      '@typescript-eslint/no-unsafe-return': 'off',
      '@typescript-eslint/only-throw-error': 'off',
      '@typescript-eslint/no-unnecessary-type-assertion': 'off',
    },
  },
  {
    ignores: [
      'dist/**',
      'node_modules/**',
      'test/integration/generated/**',
      '*.js',
      '*.mjs',
    ],
  },
);
