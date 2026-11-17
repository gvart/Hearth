import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

// The hub serves the built UI from internal/hub/webui (copied there by `task build`).
export default defineConfig({
  plugins: [react()],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
  },
});
