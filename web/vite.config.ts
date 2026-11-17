import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

// The hub serves the built UI from internal/hub/webui (copied there by `task build`).
export default defineConfig({
  plugins: [react()],
  // `npm run dev` talks to a hub running locally on its default HTTP port.
  server: {
    proxy: { '/api': 'http://localhost:7080' },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
  },
});
