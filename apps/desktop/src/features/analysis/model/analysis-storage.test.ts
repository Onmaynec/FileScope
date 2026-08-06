import { beforeEach, describe, expect, it } from 'vitest';
import {
  clearReports,
  deleteReport,
  loadReportHistory,
  saveReport,
  sanitizeLimits,
} from './analysis-storage';
import {
  HISTORY_MIGRATION_BACKUP_KEY,
  HISTORY_STORAGE_KEY,
  HISTORY_STORAGE_VERSION,
} from './history-repository';
import { migrateReport } from './report-migration';
import { currentReportSchemaVersion, defaultAnalysisLimits, type AnalysisReport } from './types';

beforeEach(() => installMemoryStorage());

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

describe('versioned history repository', () => {
  it('переносит raw schema-v1 array в storage envelope и сохраняет исходный ключ', async () => {
    localStorage.setItem('filescope:reports:schema-1', JSON.stringify([sampleReport('current')]));
    const snapshot = await loadReportHistory();
    expect(snapshot.status).toBe('ready');
    expect(snapshot.reports).toHaveLength(1);
    expect(localStorage.getItem('filescope:reports:schema-1')).not.toBeNull();
    const envelope = JSON.parse(localStorage.getItem(HISTORY_STORAGE_KEY) ?? '{}') as Record<string, unknown>;
    expect(envelope.storageVersion).toBe(HISTORY_STORAGE_VERSION);
    expect(localStorage.getItem(HISTORY_MIGRATION_BACKUP_KEY)).toContain('filescope:reports:schema-1');
  });

  it('не перезаписывает future storage envelope', async () => {
    const raw = JSON.stringify({ storageVersion: 99, reportSchemaVersion: 99, reports: [] });
    localStorage.setItem(HISTORY_STORAGE_KEY, raw);
    const snapshot = await loadReportHistory();
    expect(snapshot.status).toBe('unsupported');
    expect(localStorage.getItem(HISTORY_STORAGE_KEY)).toBe(raw);
  });

  it('не перезаписывает повреждённую историю', async () => {
    localStorage.setItem(HISTORY_STORAGE_KEY, '{broken');
    const snapshot = await loadReportHistory();
    expect(snapshot.status).toBe('corrupted');
    expect(localStorage.getItem(HISTORY_STORAGE_KEY)).toBe('{broken');
  });

  it('сохраняет уникальные отчёты, удаляет один и очищает report keys', async () => {
    await saveReport(sampleReport('a'));
    await saveReport(sampleReport('a'));
    await saveReport(sampleReport('b'));
    expect((await loadReportHistory()).reports.map((item) => item.id)).toEqual(['b', 'a']);
    expect((await deleteReport('a')).map((item) => item.id)).toEqual(['b']);

    localStorage.setItem('filescope:v0.2.0:reports', '[{"id":"legacy"}]');
    localStorage.setItem('filescope:migration-backup:v0.3.3', '{"legacy":"backup"}');
    localStorage.setItem('filescope:limits:v1', '{"jobTimeoutMs":30000}');
    expect(await clearReports()).toEqual([]);
    expect(localStorage.getItem(HISTORY_STORAGE_KEY)).toBeNull();
    expect(localStorage.getItem('filescope:v0.2.0:reports')).toBeNull();
    expect(localStorage.getItem('filescope:migration-backup:v0.3.3')).toBe('{"legacy":"backup"}');
    expect(localStorage.getItem('filescope:limits:v1')).toBe('{"jobTimeoutMs":30000}');
  });
});

describe('миграция отчётов', () => {
  it('переносит legacy-отчёт без потери индикаторов', () => {
    const migrated = migrateReport({
      ...sampleReport('legacy-1'),
      schemaVersion: undefined,
      appVersion: undefined,
      createdBy: undefined,
      indicators: [{
        id: 'legacy.indicator', title: 'Legacy', description: 'Legacy indicator',
        category: 'legacy', severity: 'low', score: 12, evidence: ['evidence'], recommendation: 'review',
      }],
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

function sampleReport(id: string): AnalysisReport {
  return {
    schemaVersion: currentReportSchemaVersion,
    appVersion: '0.3.4', analyzerVersion: 'test', ruleSetVersion: 'test',
    createdBy: { platform: 'test', architecture: 'test', runtime: 'test' },
    analysisCompleteness: 'complete', id, objectKind: 'file', target: `C:/${id}.exe`,
    displayName: `${id}.exe`, startedAt: '2026-08-01T00:00:00Z',
    completedAt: '2026-08-01T00:00:01Z', durationMs: 1000,
    riskLevel: 'noThreatsFound', riskScore: 0, indicators: [], metadata: {},
    isDemo: false, limitations: [],
  };
}

function installMemoryStorage(): void {
  const values = new Map<string, string>();
  const storage: Storage = {
    get length() { return values.size; },
    clear: () => values.clear(),
    getItem: (key) => values.get(key) ?? null,
    key: (index) => [...values.keys()][index] ?? null,
    removeItem: (key) => { values.delete(key); },
    setItem: (key, value) => { values.set(key, value); },
  };
  Object.defineProperty(globalThis, 'localStorage', { configurable: true, value: storage });
}
