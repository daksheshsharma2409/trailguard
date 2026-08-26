import express from 'express';
import itemsRouter from './routes/items.js';

const app = express();

app.use('/items', itemsRouter);

export default app;
