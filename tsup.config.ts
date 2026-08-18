import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    'scan/index': 'src/scan/index.ts',
    cli: 'src/cli.ts',
  },
  format: ['esm'],
  dts: true,
  splitting: false,
  sourcemap: true,
  clean: true,
  target: 'node18',
  outDir: 'dist',
  // Externalize all peer deps and node built-ins
  // Also externalize packages with CJS internals that don't bundle cleanly into ESM
  external: ['@prisma/client', 'express', 'commander', 'jiti', 'ts-morph', 'typescript'],
  noExternal: ['zod'],
  // Ensure ESM-compatible output
  esbuildOptions(options) {
    options.platform = 'node';
  },
});
