import { defineConfig } from '../../src/scan/index.js';

export default defineConfig({
  entry: ['./src/app.ts'],
  tsconfig: './tsconfig.json',
  prismaSchema: './prisma/schema.prisma',
  ignore: ['**/*.test.ts', '**/node_modules/**', '**/src/runtime/**', '**/src/index.ts'],
  auth: {
    middleware: ['authenticate'],
  },
  roles: {
    middleware: ['requireRole'],
    extractor: 'allStringArgs',
    known: ['ADMIN', 'TEACHER', 'STUDENT', 'AUDITOR'],
  },
  resources: {
    '/api/students': 'Student',
    '/api/users': 'User',
  },
  privateResources: ['User', 'Student'],
  audit: {
    models: ['Student', 'User'],
    clientNames: ['auditClient'],
    routerNames: ['auditRouter'],
  },
  rules: {
    RBAC005: 'medium',
    RBAC007: 'off',
  },
  baseline: './.trailguard-baseline.json',
  keyEnv: 'TRAILGUARD_KEY',
});
