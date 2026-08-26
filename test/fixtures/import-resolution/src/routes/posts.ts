import express from 'express';

export const postsRouter = express.Router();

postsRouter.get('/', (_req, res) => {
  res.json([]);
});
