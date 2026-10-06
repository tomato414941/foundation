import { reactRouter } from '@react-router/dev/vite';
import tailwindcss from '@tailwindcss/vite';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vite';

export default defineConfig({
  plugins: [tailwindcss(), reactRouter()],
  resolve: { alias: { '@': fileURLToPath(new URL('./web/app', import.meta.url)) } },
  publicDir: 'web/public',
  server: {
    host: '127.0.0.1',
    proxy: { '/api': 'http://127.0.0.1:' + (process.env.FOUNDATION_PORT || '3417') },
  },
  build: { sourcemap: false },
});
