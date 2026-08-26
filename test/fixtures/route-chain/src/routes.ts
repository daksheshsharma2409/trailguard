import express from 'express';

export const router = express.Router();

function authenticate(_req: express.Request, _res: express.Response, next: express.NextFunction) {
  next();
}

function getItem(_req: express.Request, res: express.Response) {
  res.json({ id: '1' });
}

function updateItem(_req: express.Request, res: express.Response) {
  res.json({ updated: true });
}

router
  .route('/:id')
  .get(getItem)
  .patch(authenticate, updateItem);
