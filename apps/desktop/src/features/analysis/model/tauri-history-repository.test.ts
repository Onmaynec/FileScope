import { beforeEach, describe, expect, it } from 'vitest';

import {
  HISTORY_STORAGE_KEY,
  HISTORY_STORAGE_VERSION,
} from './history-repository';
import {
  TauriReportHistoryRepository,
  type HistoryCommandBridge,
} from './tauri-history-repository';
import type { AnalysisReport } from './types';

beforeEach(() => {
  localStorage.clear();
});

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
    expect(fake.calls).toEqual(['history_load']);
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

  it('полная очистка удаляет Rust и legacy report payload', async () => {
    localStorage.setItem(HISTORY_STORAGE_KEY, JSON.stringify({
      storageVersion: HISTORY_STORAGE_VERSION,
      reportSchemaVersion: 1,
      savedAt: '2026-08-07T00:00:00Z',
      reports: [sampleUrlReport('legacy')],
    }));
    const fake = createBridge([sampleUrlReport('tauri')]);
    const repository = new TauriReportHistoryRepository(fake.bridge);

    const cleared = await repository.clear();

    expect(cleared.status).toBe('empty');
    expect(fake.reports()).toEqual([]);
    expect(localStorage.getItem(HISTORY_STORAGE_KEY)).toBeNull();
    expect(fake.calls).toEqual(['history_clear']);
  });
});

function createBridge(initial: AnalysisReport[] = []) {
  let reports = [...initial];
  const calls: string[] = [];
  const bridge: HistoryCommandBridge = async <T>(command: string, args?: Record<string, unknown>) => {
    calls.push(command);
    if (command === 'history_replace_all' && reports.length === 0) {
      reports = [...((args?.reports as AnalysisReport[] | undefined) ?? [])];
    } else if (command === 'history_save_report') {
      const report = args?.report as AnalysisReport;
      reports = [report, ...reports.filter((item) => item.id !== report.id)];
    } else if (command === 'history_delete_report') {
      reports = reports.filter((item) => item.id !== args?.id);
    } else if (command === 'history_clear') {
      reports = [];
    } else if (command !== 'history_load' && command !== 'history_inspect') {
      throw new Error(`unexpected command ${command}`);
    }
    return snapshot(reports) as T;
  };
  return { bridge, calls, reports: () => reports };
}

function snapshot(reports: AnalysisReport[]) {
  return {
    reports,
    status: reports.length ? 'ready' : 'empty',
    persisted: true,
    sizeBytes: JSON.stringify(reports).length,
    generation: reports.length ? 'test-generation.json' : undefined,
  };
}

function sampleUrlReport(id: string): AnalysisReport {
  return {
    schemaVersion: 1,
    appVersion: '0.3.4',
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
