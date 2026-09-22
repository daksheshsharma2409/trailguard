/**
 * Database client setup for the demo app.
 *
 * Exports both:
 * - `prisma`: raw PrismaClient
 * - `auditClient`: Trailguard audited client that HMAC-chains writes to Student & User
 */

import { PrismaClient } from '@prisma/client';
import { createAuditClient } from '../../../src/index.js';

const databaseUrl =
  process.env.DATABASE_URL ||
  process.env.TEST_DATABASE_URL ||
  'mysql://root:root@localhost:3307/trailguard_test';

export const prisma = new PrismaClient({
  datasources: {
    db: {
      url: databaseUrl,
    },
  },
});

const secretKey =
  process.env.TRAILGUARD_KEY || 'demo-trailguard-master-key-32chars!!';

export const auditClient = createAuditClient(prisma, {
  models: ['Student', 'User'],
  keys: { secret: secretKey },
  redactFields: ['passwordHash', 'phone'],
});
