import { invoke } from '@tauri-apps/api/core';

import { minimizeReportForFutureStorage } from './history-privacy';
import { inspectLegacyHistoryForMigration } from './legacy-history-migration';
import {
  LegacyLocalStorageReportHistoryRepository,
  type ReportHistoryRepository,
  type ReportHistorySnapshot,
} from './history-repository';
import type { AnalysisReport } from './types';

export const TAURI_HISTORY_STORAGE_VERSION = 2;

export interface TauriReportHistorySnapshot extends ReportHistorySnapshot {
  sizeBytes: number;
  generation?: string;
  backend: 'tauri';
}

export type HistoryCommandBridge = <T>(
  command: string,
  args?: Record<string, unknown>,
) => Promise<T>;

const defaultBridge: HistoryCommandBridge = (command, args) => invoke(command, args);

export class TauriReportHistoryRepository implements ReportHistoryRepository {
  constructor(
    private readonly bridge: HistoryCommandBridge = defaultBridge,
    private readonly legacyRepository = new LegacyLocalStorageReportHistoryRepository(),
  ) {}

  async load(): Promise<ReportHistorySnapshot> {
    const current = await this.readTauri('history_load');
    if (current.status !== 'empty') return current;

    const legacy = inspectLegacyHistoryForMigration();
    if (legacy.status === 'empty') return current;
    if (legacy.status !== 'ready') {
      return {
        ...legacy,
        message: legacy.message
          ? `${legacy.message} Rust history store оставлен пустым.`
          : 'Legacy history не может быть автоматически перенесена. Rust history store оставлен пустым.',
      };
    }

    const reports = legacy.reports.map((report) => minimizeReportForFutureStorage(report));
    const migrated = await this.readTauri('history_replace_all', { reports });
    if (migrated.persisted && (migrated.status === 'ready' || migrated.status === 'empty')) {
      return {
        ...migrated,
        message: `История перенесена из ${legacy.sourceKey ?? 'legacy WebView storage'} в Rust/Tauri storage. Legacy source сохранён только для rollback; новые отчёты туда не записываются.`,
      };
    }
    return migrated;
  }

  async save(report: AnalysisReport): Promise<ReportHistorySnapshot> {
    const prepared = await this.ensureWritableStore();
    if (prepared.status !== 'ready' && prepared.status !== 'empty') return prepared;
    return this.readTauri('history_save_report', {
      report: minimizeReportForFutureStorage(report),
    });
  }

  async delete(id: string): Promise<ReportHistorySnapshot> {
    const prepared = await this.ensureWritableStore();
    if (prepared.status !== 'ready' && prepared.status !== 'empty') return prepared;
    return this.readTauri('history_delete_report', { id });
  }

  async clear(): Promise<ReportHistorySnapshot> {
    const tauri = await this.readTauri('history_clear');
    if (tauri.status !== 'empty' || !tauri.persisted) return tauri;

    const legacy = await this.legacyRepository.clear();
    if (legacy.status !== 'empty' || !legacy.persisted) {
      return {
        reports: [],
        status: 'unavailable',
        persisted: false,
        message: legacy.message
          ? `Rust history удалена, но legacy report payload удалить полностью не удалось: ${legacy.message}`
          : 'Rust history удалена, но legacy report payload удалить полностью не удалось.',
      };
    }
    return {
      ...tauri,
      message: 'Rust history и известные legacy report payload удалены полностью.',
    };
  }

  async inspect(): Promise<ReportHistorySnapshot> {
    const current = await this.readTauri('history_inspect');
    if (current.status !== 'empty') return current;
    const legacy = inspectLegacyHistoryForMigration();
    if (legacy.status === 'empty') return current;
    return {
      ...legacy,
      message: legacy.message
        ? `${legacy.message} Миграция будет выполнена при обычной загрузке истории.`
        : 'Обнаружена legacy history; миграция будет выполнена при обычной загрузке истории.',
    };
  }

  private async ensureWritableStore(): Promise<ReportHistorySnapshot> {
    return this.load();
  }

  private async readTauri(
    command: string,
    args?: Record<string, unknown>,
  ): Promise<TauriReportHistorySnapshot> {
    try {
      const snapshot = await this.bridge<Omit<TauriReportHistorySnapshot, 'backend'>>(command, args);
      return { ...snapshot, backend: 'tauri' };
    } catch (error) {
      return {
        reports: [],
        status: 'unavailable',
        persisted: false,
        sizeBytes: 0,
        backend: 'tauri',
        message: `Rust history command ${command} недоступна: ${errorMessage(error)}`,
      };
    }
  }
}

export function createProductionReportHistoryRepository(): ReportHistoryRepository {
  return isTauriRuntime()
    ? new TauriReportHistoryRepository()
    : new LegacyLocalStorageReportHistoryRepository();
}

export function isTauriRuntime(): boolean {
  return typeof globalThis !== 'undefined'
    && '__TAURI_INTERNALS__' in (globalThis as unknown as Record<string, unknown>);
}

function errorMessage(value: unknown): string {
  return value instanceof Error ? value.message : String(value);
}
