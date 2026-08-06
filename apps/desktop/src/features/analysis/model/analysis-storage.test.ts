import { beforeEach, describe, expect, it } from 'vitest';
import { clearReports, migrateReport, sanitizeLimits } from './analysis-storage';
import { currentReportSchemaVersion, defaultAnalysisLimits } from './types';

beforeEach(() => localStorage.clear());

describe('лимиты анализа', () => {
  it('не позволяет полностью отключить защитные ограничения', () => {
    const result = sanitizeLimits({
      ...defaultAnalysisLimits,
      maximumFileSizeBytes: 0,
      maximumReadBytes: 0,
      maximumParserMemoryBytes: 0,
      jobTimeoutMs: 1,
      maximumArchiveEntries: -10,
      maximumArchiveDepth: 0,
      maximumCompressionRatio: 0,
      activeUrlTimeoutMs: 1,
      activeUrlRedirectLimit: 100,
    });
    expect(result.maximumFileSizeBytes).toBeGreaterThanOrEqual(1024 * 1024);
    expect(result.maximumReadBytes).toBeGreaterThanOrEqual(1024 * 1024);
    expect(result.maximumParserMemoryBytes).toBeGreaterThanOrEqual(8 * 1024 * 1024);
    expect(result.jobTimeoutMs).toBeGreaterThanOrEqual(5000);
    expect(result.maximumArchiveEntries).toBeGreaterThanOrEqual(10);
    expect(result.maximumArchiveDepth).toBeGreaterThanOrEqual(1);
    expect(result.maximumCompressionRatio).toBeGreaterThanOrEqual(2);
    expect(result.activeUrlTimeoutMs).toBeGreaterThanOrEqual(1000);
    expect(result.activeUrlRedirectLimit).toBeLessThanOrEqual(10);
  });
});

describe('очистка истории', () => {
  it('удаляет current и legacy отчёты, сохраняя backup и настройки', () => {
    localStorage.setItem('filescope:reports:schema-1', '[{"id":"current"}]');
    localStorage.setItem('filescope:v0.2.0:reports', '[{"id":"legacy"}]');
    localStorage.setItem('filescope:migration-backup:v0.3.3', '{"legacy":"backup"}');
    localStorage.setItem('filescope:limits:v1', '{"jobTimeoutMs":30000}');

    expect(clearReports()).toEqual([]);
    expect(localStorage.getItem('filescope:reports:schema-1')).toBeNull();
    expect(localStorage.getItem('filescope:v0.2.0:reports')).toBeNull();
    expect(localStorage.getItem('filescope:migration-backup:v0.3.3')).toBe('{"legacy":"backup"}');
    expect(localStorage.getItem('filescope:limits:v1')).toBe('{"jobTimeoutMs":30000}');
  });
});

describe('миграция отчётов', () => {
  it('переносит legacy-отчёт без потери индикаторов', () => {
    const migrated = migrateReport({
      id: 'legacy-1',
      objectKind: 'file',
      target: 'C:/sample.exe',
      displayName: 'sample.exe',
      startedAt: '2026-08-01T00:00:00Z',
      completedAt: '2026-08-01T00:00:01Z',
      durationMs: 1000,
      riskLevel: 'caution',
      riskScore: 12,
      indicators: [{
        id: 'legacy.indicator',
        title: 'Legacy',
        description: 'Legacy indicator',
        category: 'legacy',
        severity: 'low',
        score: 12,
        evidence: ['evidence'],
        recommendation: 'review',
      }],
      metadata: {},
      isDemo: false,
      limitations: ['legacy limitation'],
    });
    expect(migrated.schemaVersion).toBe(currentReportSchemaVersion);
    expect(migrated.indicators).toHaveLength(1);
    expect(migrated.metadata.migratedFromSchema).toBe(0);
    expect(migrated.createdBy.runtime).toBe('legacy-storage');
  });

  it('открывает будущую schema только в безопасном read-only режиме', () => {
    const migrated = migrateReport({ schemaVersion: 99, id: 'future', displayName: 'future report' });
    expect(migrated.analysisCompleteness).toBe('failed');
    expect(migrated.metadata.unsupportedSchema).toBe(true);
    expect(migrated.limitations[0]).toContain('новее поддерживаемой');
  });
});
