import { describe, expect, it } from 'vitest';
import { demoPrograms, demoReports } from './demo-data';

describe('безопасный демонстрационный набор', () => {
  it('помечает каждый отчёт как демонстрационный', () => {
    expect(demoReports.length).toBeGreaterThanOrEqual(4);
    expect(demoReports.every((report) => report.isDemo === true)).toBe(true);
  });

  it('покрывает четыре пользовательских уровня риска', () => {
    expect(new Set(demoReports.map((report) => report.risk))).toEqual(
      new Set(['noThreatsFound', 'caution', 'highRisk', 'dangerous']),
    );
  });

  it('не присваивает фиктивный риск списку программ', () => {
    expect(demoPrograms.every((program) => program.isDemo === true)).toBe(true);
    expect(demoPrograms.some((program) => 'risk' in program)).toBe(false);
  });
});
