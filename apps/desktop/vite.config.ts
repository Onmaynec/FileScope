import { readFileSync } from 'node:fs';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

const packageMetadata = JSON.parse(
  readFileSync(new URL('./package.json', import.meta.url), 'utf8'),
) as { version: string };

export default defineConfig({
  plugins: [react()],
  define: {
    __FILESCOPE_APP_VERSION__: JSON.stringify(packageMetadata.version),
  },
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
  },
});
