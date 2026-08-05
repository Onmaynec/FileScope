import { describe, expect, it } from 'vitest';
import { analyzeUrlInBrowser } from './analysis-api';

describe('пассивный URL-анализ', () => {
  it('не выполняет сетевой запрос', () => {
    const report = analyzeUrlInBrowser('https://example.com/path');
    expect(report.metadata.networkAccess).toBe(false);
    expect(report.url?.activeCheckPerformed).toBe(false);
    expect(report.isDemo).toBe(false);
  });

  it('обнаруживает учётные данные и вложенный redirect', () => {
    const report = analyzeUrlInBrowser('https://login@example.com/open?redirect=https%3A%2F%2Fevil.test');
    expect(report.indicators.map((item) => item.id)).toEqual(expect.arrayContaining([
      'url.credentials.embedded',
      'url.query.redirect-target',
    ]));
    expect(report.riskLevel).toBe('highRisk');
  });

  it('отклоняет опасные протоколы', () => {
    expect(() => analyzeUrlInBrowser('file:///C:/Windows/System32/cmd.exe')).toThrow('Поддерживаются только HTTP- и HTTPS-ссылки');
  });
});
