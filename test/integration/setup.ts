import { execSync } from 'node:child_process';
import { beforeAll } from 'vitest';

export const TEST_DATABASE_URL =
  process.env.TEST_DATABASE_URL ?? 'postgresql://root:root@localhost:5432/trailguard_test?schema=public';
process.env.TEST_DATABASE_URL = TEST_DATABASE_URL;

beforeAll(() => {
  execSync(
    'npx prisma db push --schema test/integration/prisma/schema.prisma --accept-data-loss --force-reset',
    {
      stdio: 'pipe',
      env: {
        ...process.env,
        TEST_DATABASE_URL,
      },
    },
  );
});
