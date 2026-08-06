
import { currentReportSchemaVersion, type AnalysisReport } from './types';
import { decodeAndMigrateReportArray, migrateReport } from './report-migration';

export const HISTORY_STORAGE_VERSION = 1;
export const HISTORY_STORAGE_KEY = `filescope:history:storage-${HISTORY_STORAGE_VERSION}`;
export const LEGACY_REPORT_KEYS = [
  `filescope:reports:schema-${currentReportSchemaVersion}`,
  'filescope:v0.2.0:reports',
] as const;
export const HISTORY_MIGRATION_BACKUP_KEY = 'filescope:migration-backup:v0.3.4';
export const MAXIMUM_REPORTS = 250;
export const MAXIMUM_HISTORY_PAYLOAD_BYTES = 8 * 1024 * 1024;

export type HistoryStorageStatus =
  | 'ready'
  | 'empty'
  | 'corrupted'
  | 'unsupported'
  | 'tooLarge'
  | 'unavailable';

export interface ReportHistoryEnvelope {
  storageVersion: number;
  reportSchemaVersion: number;
  savedAt: string;
  reports: AnalysisReport[];
}

export interface ReportHistorySnapshot {
  reports: AnalysisReport[];
  status: HistoryStorageStatus;
  persisted: boolean;
  sourceKey?: string;
  message?: string;
}

export interface ReportHistoryRepository {
  load(): Promise<ReportHistorySnapshot>;
  save(report: AnalysisReport): Promise<ReportHistorySnapshot>;
  delete(id: string): Promise<ReportHistorySnapshot>;
  clear(): Promise<ReportHistorySnapshot>;
  inspect(): Promise<ReportHistorySnapshot>;
}

interface BrowserStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

export class LegacyLocalStorageReportHistoryRepository implements ReportHistoryRepository {
  async load(): Promise<ReportHistorySnapshot> {
    const storage = resolveStorage();
    if (!storage) return unavailableSnapshot();

    const current = safeGet(storage, HISTORY_STORAGE_KEY);
    if (current !== null) return readCurrentEnvelope(storage, current);

    for (const key of LEGACY_REPORT_KEYS) {
      const raw = safeGet(storage, key);
      if (raw === null) continue;
      if (utf8Size(raw) > MAXIMUM_HISTORY_PAYLOAD_BYTES) {
        return {
          reports: [], status: 'tooLarge', persisted: false, sourceKey: key,
          message: 'Legacy-история превышает безопасный лимит чтения и сохранена без изменений.',
        };
      }
      const decoded = decodeAndMigrateReportArray(raw, MAXIMUM_REPORTS);
      if (!decoded) {
        backupBeforeMigration(storage, key, raw);
        return {
          reports: [], status: 'corrupted', persisted: false, sourceKey: key,
          message: 'История повреждена. Исходная запись сохранена для диагностики и не перезаписана.',
        };
      }
      backupBeforeMigration(storage, key, raw);
      const persisted = writeEnvelope(storage, decoded.reports);
      return {
        reports: decoded.reports,
        status: persisted ? 'ready' : 'unavailable',
        persisted,
        sourceKey: key,
        message: persisted
          ? 'Legacy-история перенесена в versioned storage envelope. Исходный ключ сохранён для отката.'
          : 'История прочитана, но новое storage envelope записать не удалось.',
      };
    }

    return { reports: [], status: 'empty', persisted: true };
  }

  async save(report: AnalysisReport): Promise<ReportHistorySnapshot> {
    const normalized = migrateReport(report);
    const current = await this.load();
    const base = current.status === 'ready' || current.status === 'empty' ? current.reports : [];
    const reports = [normalized, ...base.filter((item) => item.id !== normalized.id)].slice(0, MAXIMUM_REPORTS);
    const storage = resolveStorage();
    if (!storage || !canOverwrite(current.status)) {
      return {
        ...current,
        reports,
        persisted: false,
        message: current.message ?? 'Отчёт доступен в текущем сеансе, но история не была перезаписана.',
      };
    }
    const persisted = writeEnvelope(storage, reports);
    return {
      reports,
      status: persisted ? 'ready' : 'unavailable',
      persisted,
      message: persisted ? undefined : 'Не удалось сохранить историю в WebView storage.',
    };
  }

  async delete(id: string): Promise<ReportHistorySnapshot> {
    const current = await this.load();
    if (!canOverwrite(current.status)) return current;
    const reports = current.reports.filter((report) => report.id !== id);
    const storage = resolveStorage();
    const persisted = storage ? writeEnvelope(storage, reports) : false;
    return {
      reports,
      status: persisted ? (reports.length ? 'ready' : 'empty') : 'unavailable',
      persisted,
      message: persisted ? undefined : 'Не удалось обновить историю после удаления отчёта.',
    };
  }

  async clear(): Promise<ReportHistorySnapshot> {
    const storage = resolveStorage();
    if (!storage) return unavailableSnapshot();
    safeRemove(storage, HISTORY_STORAGE_KEY);
    for (const key of LEGACY_REPORT_KEYS) safeRemove(storage, key);
    return { reports: [], status: 'empty', persisted: true };
  }

  inspect(): Promise<ReportHistorySnapshot> {
    return this.load();
  }
}

export const reportHistoryRepository: ReportHistoryRepository =
  new LegacyLocalStorageReportHistoryRepository();

function readCurrentEnvelope(storage: BrowserStorage, raw: string): ReportHistorySnapshot {
  if (utf8Size(raw) > MAXIMUM_HISTORY_PAYLOAD_BYTES) {
    return {
      reports: [], status: 'tooLarge', persisted: false, sourceKey: HISTORY_STORAGE_KEY,
      message: 'History storage envelope превышает безопасный лимит и не был перезаписан.',
    };
  }
  let value: unknown;
  try {
    value = JSON.parse(raw) as unknown;
  } catch {
    backupBeforeMigration(storage, HISTORY_STORAGE_KEY, raw);
    return {
      reports: [], status: 'corrupted', persisted: false, sourceKey: HISTORY_STORAGE_KEY,
      message: 'History storage envelope повреждён. Исходные данные сохранены без перезаписи.',
    };
  }
  if (!isObject(value) || typeof value.storageVersion !== 'number') {
    backupBeforeMigration(storage, HISTORY_STORAGE_KEY, raw);
    return {
      reports: [], status: 'corrupted', persisted: false, sourceKey: HISTORY_STORAGE_KEY,
      message: 'History storage envelope не соответствует ожидаемому контракту.',
    };
  }
  if (value.storageVersion > HISTORY_STORAGE_VERSION) {
    return {
      reports: [], status: 'unsupported', persisted: false, sourceKey: HISTORY_STORAGE_KEY,
      message: `Storage version ${value.storageVersion} новее поддерживаемой ${HISTORY_STORAGE_VERSION}. Данные оставлены без изменений.`,
    };
  }
  if (value.storageVersion !== HISTORY_STORAGE_VERSION || !Array.isArray(value.reports)) {
    return {
      reports: [], status: 'corrupted', persisted: false, sourceKey: HISTORY_STORAGE_KEY,
      message: 'History storage envelope содержит неподдерживаемую структуру.',
    };
  }
  const reports = value.reports.slice(0, MAXIMUM_REPORTS).map(migrateReport);
  return { reports, status: reports.length ? 'ready' : 'empty', persisted: true, sourceKey: HISTORY_STORAGE_KEY };
}

function writeEnvelope(storage: BrowserStorage, reports: AnalysisReport[]): boolean {
  const envelope: ReportHistoryEnvelope = {
    storageVersion: HISTORY_STORAGE_VERSION,
    reportSchemaVersion: currentReportSchemaVersion,
    savedAt: new Date().toISOString(),
    reports: reports.slice(0, MAXIMUM_REPORTS),
  };
  const raw = JSON.stringify(envelope);
  if (utf8Size(raw) > MAXIMUM_HISTORY_PAYLOAD_BYTES) return false;
  try {
    storage.setItem(HISTORY_STORAGE_KEY, raw);
    return true;
  } catch {
    return false;
  }
}

function backupBeforeMigration(storage: BrowserStorage, sourceKey: string, raw: string): void {
  try {
    const existing = storage.getItem(HISTORY_MIGRATION_BACKUP_KEY);
    const backups = existing ? JSON.parse(existing) as Record<string, string> : {};
    if (!(sourceKey in backups)) {
      backups[sourceKey] = raw;
      storage.setItem(HISTORY_MIGRATION_BACKUP_KEY, JSON.stringify(backups));
    }
  } catch {
    // Ошибка backup не должна удалять или перезаписывать исходный ключ.
  }
}

function resolveStorage(): BrowserStorage | null {
  if (typeof localStorage === 'undefined') return null;
  return localStorage;
}

function safeGet(storage: BrowserStorage, key: string): string | null {
  try {
    return storage.getItem(key);
  } catch {
    return null;
  }
}

function safeRemove(storage: BrowserStorage, key: string): void {
  try {
    storage.removeItem(key);
  } catch {
    // Очистка best-effort; backup и настройки не затрагиваются.
  }
}

function unavailableSnapshot(): ReportHistorySnapshot {
  return {
    reports: [], status: 'unavailable', persisted: false,
    message: 'WebView storage недоступен. Отчёты сохраняются только в памяти текущего сеанса.',
  };
}

function canOverwrite(status: HistoryStorageStatus): boolean {
  return status === 'ready' || status === 'empty';
}

function utf8Size(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}
