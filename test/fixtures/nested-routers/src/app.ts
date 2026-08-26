import express from 'express';
import v1Router from './routes/v1.js';

const app = express();

const authenticate = (req: any, res: any, next: any) => next();
const afterAppMw = (req: any, res: any, next: any) => next();

// App-level middleware before mount protects children
app.use(authenticate);

// Level 1 mount
app.use('/api/v1', v1Router);

// App-level middleware after mount does not protect children
app.use(afterAppMw);

export default app;
