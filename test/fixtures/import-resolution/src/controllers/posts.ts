import type express from 'express';

export function listPosts(_req: express.Request, res: express.Response) {
  res.json([]);
}

export const postController = {
  createPost(_req: express.Request, res: express.Response) {
    res.json({ created: true });
  },
};
