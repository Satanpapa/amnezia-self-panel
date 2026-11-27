import { Router } from 'express';

export const healthRouter = Router();
healthRouter.get('/health', (_req, res) => {
  res.json({
    ok: true,
    service: 'amnezia-panel-api',
    version: '0.1.0',
    mode: process.env.RUNTIME_MODE ?? 'preview'
  });
});
