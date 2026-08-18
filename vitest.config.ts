import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/unit/**/*.test.ts', 'test/scan/**/*.test.ts'],
    exclude: ['test/integration/**'],
    environment: 'node',
    coverage: {
      provider: 'v8',
      include: ['src/scan/**', 'src/runtime/**', 'src/core/**'],
      exclude: ['src/scan/report/**'],
      thresholds: {
        lines: 80,
      },
      // Only enforce coverage threshold when running with --coverage flag
      reportOnFailure: false,
    },
  },
});
