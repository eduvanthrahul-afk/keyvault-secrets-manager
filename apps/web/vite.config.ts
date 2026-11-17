import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Dev: Vite on :5173 proxies /api to the Spring Boot server on :8080 (same-origin, no CORS).
// Build: output goes into the server's static folder so ONE container serves everything.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: { '/api': { target: 'http://localhost:8080', changeOrigin: false } },
  },
  build: {
    outDir: '../server/src/main/resources/static',
    emptyOutDir: true,
    sourcemap: false,
    target: 'es2022',
  },
  worker: { format: 'es' },
});
