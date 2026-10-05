import { reactRouter } from '@react-router/dev/vite';
import { defineConfig } from 'vite';

export default defineConfig({
  plugins: [reactRouter()],
  publicDir: 'web/public',
  server: { host: '127.0.0.1', proxy: { '/api': 'http://127.0.0.1:3417' } },
  build: { sourcemap: true },
});
