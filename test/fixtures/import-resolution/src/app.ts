import express from 'express';

// 1. Named router import
import { postsRouter } from './routes/posts.js';

// 2. Default router import
import commentsRouter from './routes/comments.js';

// 3. Aliased router import
import { router as aliasedRouter } from './routes/users.js';

// 4. Re-exported router import
import { reExportedRouter } from './routes/reexport.js';

// Handlers
import { listPosts, postController } from './controllers/posts.js';
import { UserController, authService } from './controllers/users.js';

// 5. Require router import
// eslint-disable-next-line @typescript-eslint/no-require-imports
const ordersRouter = require('./routes/orders.js') as express.Router;

export const app = express();

app.use(express.json());

// Mounts covering all router import styles
app.use('/posts', postsRouter);
app.use('/comments', commentsRouter);
app.use('/users', aliasedRouter);
app.use('/items', reExportedRouter);
app.use('/orders', ordersRouter);

// Routes covering all handler reference styles:
// (a) Function handler
app.get('/api/posts', listPosts);

// (b) Object method handler
app.post('/api/posts', postController.createPost);

// (c) Class static method handler
app.get('/api/users/:id', UserController.getUser);

// (d) Class instance method handler
app.post('/api/auth/login', authService.login);

// (e) Inline arrow handler
app.get('/api/health', (_req, res) => {
  res.json({ ok: true });
});

// (f) Unresolvable handler (e.g. unknown external reference)
declare const unresolvableExternalHandler: express.RequestHandler;
app.get('/api/external', unresolvableExternalHandler);
