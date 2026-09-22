/**
 * Authentication and authorization middleware for demo app.
 */

import type { Request, Response, NextFunction } from 'express';
import { verifyToken, type UserTokenPayload } from './jwt.js';

// Extend Express Request to include user
declare global {
  namespace Express {
    interface Request {
      user?: UserTokenPayload | undefined;
    }
  }
}

/**
 * Verifies JWT token and populates req.user.
 */
export function authenticate(req: Request, res: Response, next: NextFunction): void {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.status(401).json({ error: 'Unauthorized: Missing or invalid token' });
    return;
  }

  const token = authHeader.slice(7).trim();
  try {
    const payload = verifyToken(token);
    req.user = payload;
    next();
  } catch {
    res.status(401).json({ error: 'Unauthorized: Invalid token' });
  }
}

/**
 * Checks that authenticated user has one of the required roles.
 */
export function requireRole(...roles: string[]) {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({ error: 'Unauthorized: User not authenticated' });
      return;
    }

    if (!roles.includes(req.user.role)) {
      res.status(403).json({ error: 'Forbidden: Insufficient permissions' });
      return;
    }

    next();
  };
}
