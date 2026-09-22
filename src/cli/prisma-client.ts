/**
 * Resolution and connection helper for user's Prisma client in CLI commands.
 *
 * Resolves @prisma/client from the caller's working directory using createRequire,
 * with fallbacks for monorepos and test environments.
 *
 * @see context.md §4.4, tasks.md T5.1
 */

import { createRequire } from 'node:module';
import * as path from 'node:path';
import type { VerifyPrismaClient } from '../runtime/verify.js';

export async function resolvePrismaClient(
  cwd: string = process.cwd(),
): Promise<VerifyPrismaClient> {
  let clientConstructor: (new () => Record<string, unknown>) | undefined;

  // 1. Try createRequire from cwd
  try {
    const cwdRequire = createRequire(path.join(cwd, 'package.json'));
    const prismaModule = cwdRequire('@prisma/client') as {
      PrismaClient?: new () => Record<string, unknown>;
    };
    clientConstructor = prismaModule.PrismaClient;
  } catch {
    // 2. Fallback to dynamic import
    try {
      const { PrismaClient } = ((await import('@prisma/client')) as unknown) as {
        PrismaClient: new () => Record<string, unknown>;
      };
      clientConstructor = PrismaClient;
    } catch (err) {
      throw new Error(
        `Failed to resolve @prisma/client from ${cwd}: ${(err as Error).message}`,
      );
    }
  }

  if (!clientConstructor) {
    throw new Error(`@prisma/client found at ${cwd} does not export PrismaClient`);
  }

  const prisma = (new clientConstructor() as unknown) as VerifyPrismaClient & {
    $connect?: () => Promise<void>;
    $disconnect?: () => Promise<void>;
  };

  // Test connectivity
  if (typeof prisma.$connect === 'function') {
    try {
      await prisma.$connect();
    } catch (err) {
      if (typeof prisma.$disconnect === 'function') {
        try {
          await prisma.$disconnect();
        } catch {
          // ignore disconnect error on failed connection
        }
      }
      throw new Error(`Database unreachable: ${(err as Error).message}`);
    }
  }

  return prisma;
}
