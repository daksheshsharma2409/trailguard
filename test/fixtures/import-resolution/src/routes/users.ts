import express from 'express';

export const router = express.Router();

router.get('/:id', (_req, res) => {
  res.json({ user: true });
});
