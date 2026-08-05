import { describe, expect, it } from 'vitest';
import { sanitizeLimits } from './analysis-storage';
import { defaultAnalysisLimits } from './types';

describe('лимиты анализа', () => {
  it('не позволяет полностью отключить защитные ограничения', () => {
    const result = sanitizeLimits({
      ...defaultAnalysisLimits,
      maximumFileSizeBytes: 0,
      maximumArchiveEntries: -10,
      maximumArchiveDepth: 0,
      maximumCompressionRatio: 0,
      activeUrlTimeoutMs: 1,
      activeUrlRedirectLimit: 100,
    });
    expect(result.maximumFileSizeBytes).toBeGreaterThanOrEqual(1024 * 1024);
    expect(result.maximumArchiveEntries).toBeGreaterThanOrEqual(10);
    expect(result.maximumArchiveDepth).toBeGreaterThanOrEqual(1);
    expect(result.maximumCompressionRatio).toBeGreaterThanOrEqual(2);
    expect(result.activeUrlTimeoutMs).toBeGreaterThanOrEqual(1000);
    expect(result.activeUrlRedirectLimit).toBeLessThanOrEqual(10);
  });
});
