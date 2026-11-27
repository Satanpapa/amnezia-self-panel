import express from 'express';
import { healthRouter } from './routes-health.js';

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '32kb' }));
app.use('/api', healthRouter);

const port = Number(process.env.PORT ?? 4000);
app.listen(port, '127.0.0.1', () => {
  console.log(`Amnezia Panel API listening on http://127.0.0.1:${port}`);
});
