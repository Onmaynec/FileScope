import { describe, expect, it } from 'vitest';
import { analyzeUrlInBrowser, friendlyAnalysisError } from './analysis-api';

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

describe('понятные ошибки анализа', () => {
  it('объясняет отсутствие доступа к файлу', () => {
    expect(friendlyAnalysisError('Access is denied. (os error 5)')).toContain('Windows запретила чтение объекта');
  });

  it('объясняет исчезнувший файл', () => {
    expect(friendlyAnalysisError('The system cannot find the file specified. (os error 2)')).toContain('Файл больше не найден');
  });

  it('сохраняет неизвестную диагностическую ошибку без подмены', () => {
    expect(friendlyAnalysisError('custom parser failure')).toBe('custom parser failure');
  });
});
