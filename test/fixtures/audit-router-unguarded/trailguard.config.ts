import { defineConfig } from '../../../src/scan/index.js';

export default defineConfig({
  entry: ['./src/app.ts'],
  tsconfig: './tsconfig.json',
  auth: {
    middleware: ['authenticate'],
  },
  roles: {
    middleware: ['requireRole'],
    known: ['ADMIN', 'USER'],
  },
  audit: {
    routerNames: ['auditRouter'],
  },
});
