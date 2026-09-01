import express from 'express';

const app = express();
const customTelemetry = (req: any, res: any, next: any) => next();

// Neutral middleware
app.use(express.json());

// Unknown custom middleware
app.use(customTelemetry);

app.get('/data', (req: any, res: any) => res.json({ data: 'ok' }));

export default app;
