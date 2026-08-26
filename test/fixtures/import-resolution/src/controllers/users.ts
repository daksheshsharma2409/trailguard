import type express from 'express';

export class UserController {
  static getUser(_req: express.Request, res: express.Response) {
    res.json({ id: '1' });
  }
}

export class AuthService {
  login(_req: express.Request, res: express.Response) {
    res.json({ token: 'abc' });
  }
}

export const authService = new AuthService();
