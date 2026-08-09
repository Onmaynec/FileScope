import { beforeEach, describe, expect, it } from 'vitest';

import {
  HISTORY_STORAGE_KEY,
  HISTORY_STORAGE_VERSION,
} from './history-repository';
import { inspectLegacyHistoryForMigration } from './legacy-history-migration';
import {
  TauriReportHistoryRepository,
  type HistoryCommandBridge,
} from './tauri-history-repository';
import type { AnalysisReport } from './types';

beforeEach(() => installMemoryStorage());

describe('v0.3.x -> v0.4.0 migration restart and rollback recovery', () => {
  it('successful migration is idempotent across restart and preserves rollback source', async () => {
    const raw = installLegacyEnvelope('legacy-success');
    const state = createPersistentState();

    const firstBridge = createBridge(state);
    const firstProcess = new TauriReportHistoryRepository(firstBridge.bridge);
    const migrated = await firstProcess.load();

    expect(migrated.status).toBe('ready');
    expect(migrated.persisted).toBe(true);
    expect(state.reports.map((report) => report.id)).toEqual(['legacy-success']);
    expect(firstBridge.calls).toEqual(['history_load', 'history_replace_all']);
    expect(localStorage.getItem(HISTORY_STORAGE_KEY)).toBe(raw);

    const restartedBridge = createBridge(state);
    const restartedProcess = new TauriReportHistoryRepository(restartedBridge.bridge);
    const restarted = await restartedProcess.load();

    expect(restarted.status).toBe('ready');
    expect(restarted.reports.map((report) => report.id)).toEqual(['legacy-success']);
    expect(restartedBridge.calls).toEqual(['history_load', 'history_protection_status']);
    expect(restartedBridge.calls).not.toContain('history_replace_all');
    expect(localStorage.getItem(HISTORY_STORAGE_KEY)).toBe(raw);

    const rollbackSource = inspectLegacyHistoryForMigration();
    expect(rollbackSource.status).toBe('ready');
    expect(rollbackSource.sourceKey).toBe(HISTORY_STORAGE_KEY);
    expect(rollbackSource.reports.map((report) => report.id)).toEqual(['legacy-success']);
  });

  it('failed publication before commit is retryable after restart without changing legacy source', async () => {
    const raw = installLegacyEnvelope('legacy-retry');
    const state = createPersistentState();

    const failingBridge = createBridge(state, 'failBeforeCommit');
    const firstProcess = new TauriReportHistoryRepository(failingBridge.bridge);
    const failed = await firstProcess.load();

    expect(failed.status).toBe('unavailable');
    expect(failed.persisted).toBe(false);
    expect(state.reports).toEqual([]);
    expect(failingBridge.calls).toEqual(['history_load', 'history_replace_all']);
    expect(localStorage.getItem(HISTORY_STORAGE_KEY)).toBe(raw);

    const retryBridge = createBridge(state);
    const restartedProcess = new TauriReportHistoryRepository(retryBridge.bridge);
    const recovered = await restartedProcess.load();

    expect(recovered.status).toBe('ready');
    expect(recovered.persisted).toBe(true);
    expect(recovered.reports.map((report) => report.id)).toEqual(['legacy-retry']);
    expect(state.reports.map((report) => report.id)).toEqual(['legacy-retry']);
    expect(retryBridge.calls).toEqual(['history_load', 'history_replace_all']);
    expect(localStorage.getItem(HISTORY_STORAGE_KEY)).toBe(raw);
  });

  it('lost IPC response after committed migration recovers on restart without second replace', async () => {
    const raw = installLegacyEnvelope('legacy-committed');
    const state = createPersistentState();

    const uncertainBridge = createBridge(state, 'commitThenLoseResponse');
    const firstProcess = new TauriReportHistoryRepository(uncertainBridge.bridge);
    const uncertain = await firstProcess.load();

    expect(uncertain.status).toBe('unavailable');
    expect(uncertain.persisted).toBe(false);
    expect(state.reports.map((report) => report.id)).toEqual(['legacy-committed']);
    expect(uncertainBridge.calls).toEqual(['history_load', 'history_replace_all']);
    expect(localStorage.getItem(HISTORY_STORAGE_KEY)).toBe(raw);

    const restartBridge = createBridge(state);
    const restartedProcess = new TauriReportHistoryRepository(restartBridge.bridge);
    const recovered = await restartedProcess.load();

    expect(recovered.status).toBe('ready');
    expect(recovered.persisted).toBe(true);
    expect(recovered.reports.map((report) => report.id)).toEqual(['legacy-committed']);
    expect(state.reports.map((report) => report.id)).toEqual(['legacy-committed']);
    expect(restartBridge.calls).toEqual(['history_load', 'history_protection_status']);
    expect(restartBridge.calls).not.toContain('history_replace_all');
    expect(localStorage.getItem(HISTORY_STORAGE_KEY)).toBe(raw);
  });
});

type ReplaceFailureMode = 'none' | 'failBeforeCommit' | 'commitThenLoseResponse';

interface PersistentState {
  reports: AnalysisReport[];
}

function createPersistentState(): PersistentState {
  return { reports: [] };
}

function createBridge(
  state: PersistentState,
  failureMode: ReplaceFailureMode = 'none',
): { bridge: HistoryCommandBridge; calls: string[] } {
  const calls: string[] = [];
  const bridge: HistoryCommandBridge = async <T>(command: string, args?: Record<string, unknown>) => {
    calls.push(command);

    if (command === 'history_load' || command === 'history_inspect') {
      return snapshot(state.reports) as T;
    }
    if (command === 'history_protection_status') {
      return {
        status: state.reports.length ? 'dpapiCurrentUser' : 'empty',
        dpapiGenerations: state.reports.length ? 1 : 0,
        plaintextGenerations: 0,
      } as T;
    }
    if (command === 'history_replace_all') {
      const reports = [...((args?.reports as AnalysisReport[] | undefined) ?? [])];
      if (failureMode === 'failBeforeCommit') {
        return unavailableSnapshot('Synthetic publication failure before commit.') as T;
      }
      state.reports = reports;
      if (failureMode === 'commitThenLoseResponse') {
        throw new Error('Synthetic IPC response loss after committed publication.');
      }
      return snapshot(state.reports) as T;
    }
    if (command === 'history_rewrite_all') {
      state.reports = [...((args?.reports as AnalysisReport[] | undefined) ?? [])];
      return snapshot(state.reports) as T;
    }

    throw new Error(`unexpected command ${command}`);
  };
  return { bridge, calls };
}

function snapshot(reports: AnalysisReport[]) {
  return {
    reports: [...reports],
    status: reports.length ? 'ready' : 'empty',
    persisted: true,
    sizeBytes: JSON.stringify(reports).length,
    generation: reports.length ? 'migration-generation.bin' : undefined,
  };
}

function unavailableSnapshot(message: string) {
  return {
    reports: [],
    status: 'unavailable',
    persisted: false,
    sizeBytes: 0,
    message,
  };
}

function installLegacyEnvelope(id: string): string {
  const raw = JSON.stringify({
    storageVersion: HISTORY_STORAGE_VERSION,
    reportSchemaVersion: 1,
    savedAt: '2026-08-09T00:00:00Z',
    reports: [sampleLegacyReport(id)],
  });
  localStorage.setItem(HISTORY_STORAGE_KEY, raw);
  return raw;
}

function sampleLegacyReport(id: string): AnalysisReport {
  return {
    schemaVersion: 1,
    appVersion: '0.3.4',
    analyzerVersion: 'migration-test',
    ruleSetVersion: 'migration-test',
    createdBy: { platform: 'windows', architecture: 'x86_64', runtime: 'tauri-desktop' },
    analysisCompleteness: 'complete',
    id,
    objectKind: 'file',
    target: `C:/Users/Test/Downloads/${id}.exe`,
    displayName: `${id}.exe`,
    startedAt: '2026-08-08T20:00:00Z',
    completedAt: '2026-08-08T20:00:01Z',
    durationMs: 1000,
    riskLevel: 'noThreatsFound',
    riskScore: 0,
    indicators: [],
    metadata: {},
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
