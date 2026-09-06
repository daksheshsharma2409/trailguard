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
    extractor: 'firstStringArg',
    known: ['ADMIN', 'USER'],
  },
  ownership: {
    signals: ['req.user.id'],
    ownerFields: ['authorId'],
  },
});
