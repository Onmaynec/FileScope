import { readFileSync } from 'node:fs';
import { defineConfig } from 'vitest/config';

const packageMetadata = JSON.parse(
  readFileSync(new URL('./package.json', import.meta.url), 'utf8'),
) as { version: string };

export default defineConfig({
  define: {
    __FILESCOPE_APP_VERSION__: JSON.stringify(packageMetadata.version),
  },
  test: {
    environment: 'node',
    include: ['src/**/*.test.ts', 'src/**/*.test.tsx'],
    passWithNoTests: false,
    reporters: ['default'],
    globals: true,
    setupFiles: ['@testing-library/jest-dom/vitest'],
  },
});