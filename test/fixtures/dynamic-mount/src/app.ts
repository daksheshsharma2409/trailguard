import express from 'express';
import postsRouter from './routes/posts.js';

const app = express();
const version = 'v1';

app.use(`/api/${version}`, postsRouter);

export default app;
