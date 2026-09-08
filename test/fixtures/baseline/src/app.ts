import express from 'express';
import postsRouter from './routes/posts.js';

const app = express();

app.use('/api/posts', postsRouter);

export default app;
