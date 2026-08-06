import { readFileSync } from 'node:fs';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

const packageMetadata = JSON.parse(
  readFileSync(new URL('./package.json', import.meta.url), 'utf8'),
) as { version: string };
const rawSuffix = process.env.FILESCOPE_VERSION_SUFFIX ?? '';
const versionSuffix = /^[-+][0-9A-Za-z.-]+$/.test(rawSuffix) ? rawSuffix : '';
const buildVersion = `${packageMetadata.version}${versionSuffix}`;

export default defineConfig({
  plugins: [react()],
  define: {
    __FILESCOPE_APP_VERSION__: JSON.stringify(buildVersion),
  },
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
  },
});
