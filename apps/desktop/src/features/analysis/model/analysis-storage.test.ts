import { beforeEach, describe, expect, it } from 'vitest';
import {
  clearReportHistory,
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
  LEGACY_HISTORY_MIGRATION_BACKUP_KEYS,
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
    localStorage.setItem(`filescope:reports:schema-${currentReportSchemaVersion}`, JSON.stringify([sampleReport('current')]));
    const snapshot = await loadReportHistory();
    expect(snapshot.status).toBe('ready');
    expect(snapshot.reports).toHaveLength(1);
    expect(localStorage.getItem(`filescope:reports:schema-${currentReportSchemaVersion}`)).not.toBeNull();
    const envelope = JSON.parse(localStorage.getItem(HISTORY_STORAGE_KEY) ?? '{}') as Record<string, unknown>;
    expect(envelope.storageVersion).toBe(HISTORY_STORAGE_VERSION);
    expect(localStorage.getItem(HISTORY_MIGRATION_BACKUP_KEY)).toContain(`filescope:reports:schema-${currentReportSchemaVersion}`);
  });

  it('не перезаписывает future storage envelope', async () => {
    const raw = JSON.stringify({ storageVersion: 99, reportSchemaVersion: 99, reports: [] });
    localStorage.setItem(HISTORY_STORAGE_KEY, raw);
    const snapshot = await loadReportHistory();
    expect(snapshot.status).toBe('unsupported');
    expect(localStorage.getItem(HISTORY_STORAGE_KEY)).toBe(raw);
  });

  it('не перезаписывает current storage envelope с future report schema', async () => {
    const raw = JSON.stringify({
      storageVersion: HISTORY_STORAGE_VERSION,
      reportSchemaVersion: currentReportSchemaVersion + 1,
      savedAt: '2026-08-07T00:00:00Z',
      reports: [{ schemaVersion: currentReportSchemaVersion + 1, id: 'future' }],
    });
    localStorage.setItem(HISTORY_STORAGE_KEY, raw);
    const snapshot = await loadReportHistory();
    expect(snapshot.status).toBe('unsupported');
    await saveReport(sampleReport('new'));
    expect(localStorage.getItem(HISTORY_STORAGE_KEY)).toBe(raw);
  });

  it('не доверяет envelope, если внутри скрыт future report schema', async () => {
    const raw = JSON.stringify({
      storageVersion: HISTORY_STORAGE_VERSION,
      reportSchemaVersion: currentReportSchemaVersion,
      savedAt: '2026-08-07T00:00:00Z',
      reports: [{ schemaVersion: currentReportSchemaVersion + 5, id: 'future-hidden' }],
    });
    localStorage.setItem(HISTORY_STORAGE_KEY, raw);
    expect((await loadReportHistory()).status).toBe('unsupported');
    expect(localStorage.getItem(HISTORY_STORAGE_KEY)).toBe(raw);
  });

  it('не перезаписывает повреждённую историю', async () => {
    localStorage.setItem(HISTORY_STORAGE_KEY, '{broken');
    const snapshot = await loadReportHistory();
    expect(snapshot.status).toBe('corrupted');
    expect(localStorage.getItem(HISTORY_STORAGE_KEY)).toBe('{broken');
  });

  it('ошибку чтения storage не интерпретирует как пустую историю', async () => {
    installMemoryStorage({ failGetKeys: new Set([HISTORY_STORAGE_KEY]) });
    const snapshot = await loadReportHistory();
    expect(snapshot.status).toBe('unavailable');
    expect(snapshot.persisted).toBe(false);
  });

  it('сохраняет уникальные отчёты, удаляет один и полностью очищает report payload', async () => {
    await saveReport(sampleReport('a'));
    await saveReport(sampleReport('a'));
    await saveReport(sampleReport('b'));
    expect((await loadReportHistory()).reports.map((item) => item.id)).toEqual(['b', 'a']);
    expect((await deleteReport('a')).map((item) => item.id)).toEqual(['b']);

    localStorage.setItem('filescope:v0.2.0:reports', '[{"id":"legacy"}]');
    localStorage.setItem(HISTORY_MIGRATION_BACKUP_KEY, '{"reports":"backup"}');
    for (const key of LEGACY_HISTORY_MIGRATION_BACKUP_KEYS) localStorage.setItem(key, '{"legacy":"backup"}');
    localStorage.setItem('filescope:limits:v1', '{"jobTimeoutMs":30000}');
    expect(await clearReports()).toEqual([]);
    expect(localStorage.getItem(HISTORY_STORAGE_KEY)).toBeNull();
    expect(localStorage.getItem('filescope:v0.2.0:reports')).toBeNull();
    expect(localStorage.getItem(HISTORY_MIGRATION_BACKUP_KEY)).toBeNull();
    for (const key of LEGACY_HISTORY_MIGRATION_BACKUP_KEYS) expect(localStorage.getItem(key)).toBeNull();
    expect(localStorage.getItem('filescope:limits:v1')).toBe('{"jobTimeoutMs":30000}');
  });

  it('не сообщает об успешной очистке, если removeItem не сработал', async () => {
    const values = new Map<string, string>([[HISTORY_STORAGE_KEY, JSON.stringify({
      storageVersion: HISTORY_STORAGE_VERSION,
      reportSchemaVersion: currentReportSchemaVersion,
      savedAt: '2026-08-07T00:00:00Z',
      reports: [sampleReport('blocked')],
    })]]);
    installMemoryStorage({ values, failRemoveKeys: new Set([HISTORY_STORAGE_KEY]) });
    const snapshot = await clearReportHistory();
    expect(snapshot.status).toBe('unavailable');
    expect(snapshot.persisted).toBe(false);
    expect(localStorage.getItem(HISTORY_STORAGE_KEY)).not.toBeNull();
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

interface MemoryStorageOptions {
  values?: Map<string, string>;
  failGetKeys?: Set<string>;
  failRemoveKeys?: Set<string>;
}

function installMemoryStorage(options: MemoryStorageOptions = {}): void {
  const values = options.values ?? new Map<string, string>();
  const storage: Storage = {
    get length() { return values.size; },
    clear: () => values.clear(),
    getItem: (key) => {
      if (options.failGetKeys?.has(key)) throw new Error('getItem blocked');
      return values.get(key) ?? null;
    },
    key: (index) => [...values.keys()][index] ?? null,
    removeItem: (key) => {
      if (options.failRemoveKeys?.has(key)) return;
      values.delete(key);
    },
    setItem: (key, value) => { values.set(key, value); },
  };
  Object.defineProperty(globalThis, 'localStorage', { configurable: true, value: storage });
}
