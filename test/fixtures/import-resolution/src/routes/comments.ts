import express from 'express';

const commentsRouter = express.Router();

commentsRouter.get('/', (_req, res) => {
  res.json([]);
});

export default commentsRouter;
