import { defineConfig } from '../../../src/scan/index.js';

export default defineConfig({
  entry: ['./src/app.ts'],
  tsconfig: './tsconfig.json',
  prismaSchema: './prisma/schema.prisma',
  auth: {
    middleware: ['authenticate'],
  },
  roles: {
    middleware: ['requireRole'],
    known: ['ADMIN', 'USER'],
  },
  audit: {
    models: ['Student'],
    clientNames: ['auditClient', 'audited', 'db'],
  },
});
