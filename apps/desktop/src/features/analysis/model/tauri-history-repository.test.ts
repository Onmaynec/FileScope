import { beforeEach, describe, expect, it } from 'vitest';

import type { HistoryPreferences } from '../../../shared/services/settings-service';
import { minimizeReportForFutureStorage } from './history-privacy';
import {
  HISTORY_STORAGE_KEY,
  HISTORY_STORAGE_VERSION,
} from './history-repository';
import {
  TauriReportHistoryRepository,
  type HistoryCommandBridge,
  type HistoryProtectionStatus,
} from './tauri-history-repository';
import type { AnalysisReport } from './types';

beforeEach(() => installMemoryStorage());

describe('Tauri report history repository v0.4.0', () => {
  it('мигрирует legacy envelope в Rust storage без перезаписи source и минимизирует данные', async () => {
    const legacy = sampleUrlReport('legacy');
    const raw = JSON.stringify({
      storageVersion: HISTORY_STORAGE_VERSION,
      reportSchemaVersion: 1,
      savedAt: '2026-08-07T00:00:00Z',
      reports: [legacy],
    });
    localStorage.setItem(HISTORY_STORAGE_KEY, raw);
    const fake = createBridge();
    const repository = new TauriReportHistoryRepository(fake.bridge);

    const migrated = await repository.load();

    expect(migrated.status).toBe('ready');
    expect(fake.calls).toEqual(['history_load', 'history_replace_all']);
    expect(fake.reports()).toHaveLength(1);
    expect(fake.reports()[0].target).toBe('https://example.com/path');
    expect(fake.reports()[0].url?.normalizedUrl).toBe('https://example.com/path');
    expect(fake.reports()[0].url?.responseHeaders).toEqual([['Content-Type', 'text/plain']]);
    expect(fake.reports()[0].metadata.privacyPreparedForV040).toBe(true);
    expect(fake.reports()[0].metadata.privacyRedactions).toMatchObject({
      credentialsRemovedFromUrls: true,
      queryRemovedFromUrls: true,
      fragmentRemovedFromUrls: true,
      sensitiveResponseHeadersRemoved: 1,
    });
    expect(localStorage.getItem(HISTORY_STORAGE_KEY)).toBe(raw);
    expect(localStorage.getItem('filescope:migration-backup:v0.3.4')).toBeNull();
  });

  it('не читает и не мигрирует legacy history когда Rust storage уже authoritative', async () => {
    localStorage.setItem(HISTORY_STORAGE_KEY, '{broken');
    const authoritative = sampleUrlReport('tauri');
    const fake = createBridge([authoritative]);
    const repository = new TauriReportHistoryRepository(fake.bridge);

    const loaded = await repository.load();

    expect(loaded.status).toBe('ready');
    expect(loaded.reports[0].id).toBe('tauri');
    expect(fake.calls).toEqual(['history_load', 'history_rewrite_all']);
    expect(localStorage.getItem(HISTORY_STORAGE_KEY)).toBe('{broken');
  });

  it('не создаёт Rust store из future legacy schema', async () => {
    const future = { ...sampleUrlReport('future'), schemaVersion: 99 };
    localStorage.setItem(HISTORY_STORAGE_KEY, JSON.stringify({
      storageVersion: HISTORY_STORAGE_VERSION,
      reportSchemaVersion: 99,
      savedAt: '2026-08-07T00:00:00Z',
      reports: [future],
    }));
    const fake = createBridge();
    const repository = new TauriReportHistoryRepository(fake.bridge);

    const loaded = await repository.load();

    expect(loaded.status).toBe('unsupported');
    expect(fake.calls).toEqual(['history_load']);
    expect(fake.reports()).toEqual([]);
  });

  it('после миграции сохраняет новые отчёты только в Rust storage', async () => {
    const legacy = sampleUrlReport('legacy');
    const raw = JSON.stringify({
      storageVersion: HISTORY_STORAGE_VERSION,
      reportSchemaVersion: 1,
      savedAt: '2026-08-07T00:00:00Z',
      reports: [legacy],
    });
    localStorage.setItem(HISTORY_STORAGE_KEY, raw);
    const fake = createBridge();
    const repository = new TauriReportHistoryRepository(fake.bridge);

    await repository.save(sampleUrlReport('new'));

    expect(fake.reports().map((report) => report.id)).toEqual(['new', 'legacy']);
    expect(localStorage.getItem(HISTORY_STORAGE_KEY)).toBe(raw);
    expect(fake.calls).toEqual(['history_load', 'history_replace_all', 'history_save_report']);
  });

  it('при отключённом сохранении держит новый отчёт только в памяти сеанса', async () => {
    const fake = createBridge([sampleUrlReport('persisted')]);
    const repository = repositoryWithPolicy(fake.bridge, {
      ...defaultPolicy(),
      enabled: false,
    });

    const saved = await repository.save(sampleUrlReport('session-only'));

    expect(saved.reports.map((report) => report.id)).toEqual(['session-only', 'persisted']);
    expect(saved.persisted).toBe(false);
    expect(fake.reports().map((report) => report.id)).toEqual(['persisted']);
    expect(fake.calls).toEqual(['history_load', 'history_rewrite_all']);
  });

  it('режим текущего сеанса не записывает новые отчёты на диск', async () => {
    const fake = createBridge();
    const repository = repositoryWithPolicy(fake.bridge, {
      ...defaultPolicy(),
      retention: 'session',
    });

    const first = await repository.save(sampleUrlReport('session-one'));
    const loaded = await repository.load();

    expect(first.persisted).toBe(false);
    expect(loaded.reports.map((report) => report.id)).toEqual(['session-one']);
    expect(fake.reports()).toEqual([]);
    expect(fake.calls).toEqual(['history_load', 'history_load']);
  });

  it('retention 1d удаляет устаревшие persistent reports через Rust rewrite', async () => {
    const old = sampleUrlReport('old');
    old.startedAt = '2000-01-01T00:00:00Z';
    old.completedAt = '2000-01-01T00:00:01Z';
    const recent = sampleUrlReport('recent');
    recent.startedAt = new Date(Date.now() - 30_000).toISOString();
    recent.completedAt = new Date(Date.now() - 29_000).toISOString();
    const fake = createBridge([old, recent]);
    const repository = repositoryWithPolicy(fake.bridge, {
      ...defaultPolicy(),
      retention: '1d',
    });

    const loaded = await repository.load();

    expect(loaded.reports.map((report) => report.id)).toEqual(['recent']);
    expect(fake.reports().map((report) => report.id)).toEqual(['recent']);
    expect(fake.calls).toEqual(['history_load', 'history_rewrite_all']);
  });

  it('переписывает уже минимизированную plaintext generation в DPAPI', async () => {
    const prepared = minimizeReportForFutureStorage(sampleUrlReport('plaintext'));
    const fake = createBridge([prepared], 'plaintext');
    const repository = new TauriReportHistoryRepository(fake.bridge);

    const loaded = await repository.load();

    expect(loaded.status).toBe('ready');
    expect(fake.calls).toEqual([
      'history_load',
      'history_protection_status',
      'history_rewrite_all',
    ]);
    expect(fake.protection()).toBe('dpapiCurrentUser');
    expect(loaded.message).toContain('DPAPI');
  });

  it('явное сохранение полного URL оставляет query/fragment, но удаляет credentials и sensitive headers', async () => {
    const fake = createBridge();
    const repository = repositoryWithPolicy(fake.bridge, {
      ...defaultPolicy(),
      preserveFullUrl: true,
    });

    await repository.save(sampleUrlReport('full-url'));

    expect(fake.reports()[0].target).toBe('https://example.com/path?token=secret#fragment');
    expect(fake.reports()[0].url?.normalizedUrl).toBe('https://example.com/path?token=secret#fragment');
    expect(fake.reports()[0].url?.responseHeaders).toEqual([['Content-Type', 'text/plain']]);
  });

  it('полная очистка удаляет Rust, session и legacy report payload', async () => {
    localStorage.setItem(HISTORY_STORAGE_KEY, JSON.stringify({
      storageVersion: HISTORY_STORAGE_VERSION,
      reportSchemaVersion: 1,
      savedAt: '2026-08-07T00:00:00Z',
      reports: [sampleUrlReport('legacy')],
    }));
    const fake = createBridge([sampleUrlReport('tauri')]);
    const repository = repositoryWithPolicy(fake.bridge, {
      ...defaultPolicy(),
      retention: 'session',
    });
    await repository.save(sampleUrlReport('session'));

    const cleared = await repository.clear();

    expect(cleared.status).toBe('empty');
    expect(fake.reports()).toEqual([]);
    expect((await repository.load()).reports).toEqual([]);
    expect(localStorage.getItem(HISTORY_STORAGE_KEY)).toBeNull();
  });
});

function repositoryWithPolicy(bridge: HistoryCommandBridge, policy: HistoryPreferences) {
  return new TauriReportHistoryRepository(bridge, undefined, () => policy);
}

function defaultPolicy(): HistoryPreferences {
  return {
    enabled: true,
    retention: 'forever',
    preserveFullPath: false,
    preserveFullUrl: false,
  };
}

function createBridge(
  initial: AnalysisReport[] = [],
  initialProtection: HistoryProtectionStatus = 'dpapiCurrentUser',
) {
  let reports = [...initial];
  let protection = initialProtection;
  const calls: string[] = [];
  const bridge: HistoryCommandBridge = async <T>(command: string, args?: Record<string, unknown>) => {
    calls.push(command);
    if (command === 'history_protection_status') {
      return {
        status: protection,
        dpapiGenerations: protection === 'dpapiCurrentUser' ? 1 : 0,
        plaintextGenerations: protection === 'plaintext' ? 1 : 0,
      } as T;
    }
    if (command === 'history_replace_all' && reports.length === 0) {
      reports = [...((args?.reports as AnalysisReport[] | undefined) ?? [])];
      protection = 'dpapiCurrentUser';
    } else if (command === 'history_rewrite_all') {
      reports = [...((args?.reports as AnalysisReport[] | undefined) ?? [])];
      protection = 'dpapiCurrentUser';
    } else if (command === 'history_save_report') {
      const report = args?.report as AnalysisReport;
      reports = [report, ...reports.filter((item) => item.id !== report.id)];
      protection = 'dpapiCurrentUser';
    } else if (command === 'history_delete_report') {
      reports = reports.filter((item) => item.id !== args?.id);
      protection = reports.length ? 'dpapiCurrentUser' : 'empty';
    } else if (command === 'history_clear') {
      reports = [];
      protection = 'empty';
    } else if (command !== 'history_load' && command !== 'history_inspect') {
      throw new Error(`unexpected command ${command}`);
    }
    return snapshot(reports) as T;
  };
  return { bridge, calls, reports: () => reports, protection: () => protection };
}

function snapshot(reports: AnalysisReport[]) {
  return {
    reports,
    status: reports.length ? 'ready' : 'empty',
    persisted: true,
    sizeBytes: JSON.stringify(reports).length,
    generation: reports.length ? 'test-generation.bin' : undefined,
  };
}

function sampleUrlReport(id: string): AnalysisReport {
  return {
    schemaVersion: 1,
    appVersion: '0.4.0',
    analyzerVersion: 'test',
    ruleSetVersion: 'test',
    createdBy: { platform: 'test', architecture: 'test', runtime: 'test' },
    analysisCompleteness: 'complete',
    id,
    objectKind: 'url',
    target: 'https://user:secret@example.com/path?token=secret#fragment',
    displayName: 'example.com',
    startedAt: '2026-08-07T00:00:00Z',
    completedAt: '2026-08-07T00:00:01Z',
    durationMs: 1000,
    riskLevel: 'noThreatsFound',
    riskScore: 0,
    indicators: [],
    metadata: {},
    url: {
      normalizedUrl: 'https://user:secret@example.com/path?token=secret#fragment',
      scheme: 'https',
      host: 'example.com',
      asciiHost: 'example.com',
      unicodeHost: 'example.com',
      path: '/path',
      queryParameters: 1,
      containsPunycode: false,
      hostIsIp: false,
      hasCredentials: true,
      subdomainCount: 0,
      redirectParameters: [],
      resolvedAddresses: [],
      finalUrl: 'https://example.com/path?session=secret',
      statusCode: 200,
      responseHeaders: [['Set-Cookie', 'session=secret'], ['Content-Type', 'text/plain']],
      redirectCount: 0,
      activeCheckPerformed: true,
    },
    isDemo: false,
    limitations: [],
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
