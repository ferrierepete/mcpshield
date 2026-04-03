import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: false,
    environment: 'node',
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov', 'html'],
      exclude: [
        'dist/**',
        'tests/**',
        'eslint.config.js',
        'vitest.config.ts',
        'src/cli.ts',
        'src/index.ts',
        'src/types/**',
      ],
      thresholds: {
        lines: 70,
        functions: 70,
        branches: 60,
      },
    },
  },
});
