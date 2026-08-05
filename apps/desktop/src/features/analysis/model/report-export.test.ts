import { describe, expect, it } from 'vitest';
import { renderReportHtml } from './report-export';
import type { AnalysisReport } from './types';

const report: AnalysisReport = {
  id: 'test-report',
  objectKind: 'file',
  target: 'C:/test/<script>.exe',
  displayName: '<script>alert(1)</script>.exe',
  startedAt: '2026-08-05T00:00:00.000Z',
  completedAt: '2026-08-05T00:00:00.100Z',
  durationMs: 100,
  riskLevel: 'caution',
  riskScore: 20,
  indicators: [],
  metadata: {},
  isDemo: false,
  limitations: ['Тестовое ограничение'],
};

describe('HTML-экспорт', () => {
  it('экранирует пользовательские значения', () => {
    const html = renderReportHtml(report);
    expect(html).toContain('&lt;script&gt;alert(1)&lt;/script&gt;.exe');
    expect(html).not.toContain('<script>alert(1)</script>');
  });
});
