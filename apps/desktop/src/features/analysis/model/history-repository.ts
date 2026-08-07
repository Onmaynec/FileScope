import { currentReportSchemaVersion, type AnalysisReport } from './types';
import { decodeAndMigrateReportArray, migrateReport } from './report-migration';

export const HISTORY_STORAGE_VERSION = 1;
export const HISTORY_STORAGE_KEY = `filescope:history:storage-${HISTORY_STORAGE_VERSION}`;
export const LEGACY_REPORT_KEYS = [
  `filescope:reports:schema-${currentReportSchemaVersion}`,
  'filescope:v0.2.0:reports',
] as const;
export const HISTORY_MIGRATION_BACKUP_KEY = 'filescope:migration-backup:v0.3.4';
export const LEGACY_HISTORY_MIGRATION_BACKUP_KEYS = ['filescope:migration-backup:v0.3.3'] as const;
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

interface StorageReadResult {
  ok: boolean;
  value: string | null;
}

export class LegacyLocalStorageReportHistoryRepository implements ReportHistoryRepository {
  async load(): Promise<ReportHistorySnapshot> {
    const storage = resolveStorage();
    if (!storage) return unavailableSnapshot();

    const current = safeGet(storage, HISTORY_STORAGE_KEY);
    if (!current.ok) return storageReadFailure(HISTORY_STORAGE_KEY);
    if (current.value !== null) return readCurrentEnvelope(storage, current.value);

    for (const key of LEGACY_REPORT_KEYS) {
      const result = safeGet(storage, key);
      if (!result.ok) return storageReadFailure(key);
      const raw = result.value;
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
      if (containsFutureReportSchema(JSON.parse(raw) as unknown[])) {
        return {
          reports: [], status: 'unsupported', persisted: false, sourceKey: key,
          message: `Legacy-история содержит отчёт схемы новее поддерживаемой ${currentReportSchemaVersion}. Данные оставлены без изменений.`,
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
    if (report.schemaVersion > currentReportSchemaVersion) {
      return {
        reports: [], status: 'unsupported', persisted: false,
        message: `Отчёт схемы ${report.schemaVersion} новее поддерживаемой ${currentReportSchemaVersion} и не был сохранён.`,
      };
    }
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
    if (!persisted) {
      return {
        ...current,
        status: 'unavailable',
        persisted: false,
        message: 'Не удалось удалить отчёт из постоянной истории. Локальная запись оставлена без изменений.',
      };
    }
    return {
      reports,
      status: reports.length ? 'ready' : 'empty',
      persisted: true,
    };
  }

  async clear(): Promise<ReportHistorySnapshot> {
    const storage = resolveStorage();
    if (!storage) return unavailableSnapshot();

    const directKeys = [
      HISTORY_STORAGE_KEY,
      ...LEGACY_REPORT_KEYS,
      HISTORY_MIGRATION_BACKUP_KEY,
    ];
    const failed = directKeys.filter((key) => !safeRemove(storage, key));
    for (const key of LEGACY_HISTORY_MIGRATION_BACKUP_KEYS) {
      if (!removeReportPayloadFromLegacyBackup(storage, key)) failed.push(key);
    }
    if (failed.length > 0) {
      return {
        reports: [], status: 'unavailable', persisted: false,
        message: `Не удалось полностью удалить локальную историю. Остались недоступные ключи: ${failed.join(', ')}.`,
      };
    }
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
  if (!isObject(value)
    || typeof value.storageVersion !== 'number'
    || typeof value.reportSchemaVersion !== 'number') {
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
  if (value.reportSchemaVersion > currentReportSchemaVersion) {
    return {
      reports: [], status: 'unsupported', persisted: false, sourceKey: HISTORY_STORAGE_KEY,
      message: `Report schema ${value.reportSchemaVersion} новее поддерживаемой ${currentReportSchemaVersion}. Данные оставлены без изменений.`,
    };
  }
  if (value.storageVersion !== HISTORY_STORAGE_VERSION || !Array.isArray(value.reports)) {
    return {
      reports: [], status: 'corrupted', persisted: false, sourceKey: HISTORY_STORAGE_KEY,
      message: 'History storage envelope содержит неподдерживаемую структуру.',
    };
  }
  if (containsFutureReportSchema(value.reports)) {
    return {
      reports: [], status: 'unsupported', persisted: false, sourceKey: HISTORY_STORAGE_KEY,
      message: `History storage содержит отчёт схемы новее поддерживаемой ${currentReportSchemaVersion}. Данные оставлены без изменений.`,
    };
  }
  const reports = value.reports.slice(0, MAXIMUM_REPORTS).map(migrateReport);
  return { reports, status: reports.length ? 'ready' : 'empty', persisted: true, sourceKey: HISTORY_STORAGE_KEY };
}

function writeEnvelope(storage: BrowserStorage, reports: AnalysisReport[]): boolean {
  if (reports.some((report) => report.schemaVersion > currentReportSchemaVersion)) return false;
  const envelope: ReportHistoryEnvelope = {
    storageVersion: HISTORY_STORAGE_VERSION,
    reportSchemaVersion: currentReportSchemaVersion,
    savedAt: new Date().toISOString(),
    reports: reports.slice(0, MAXIMUM_REPORTS),
  };
  const raw = JSON.stringify(envelope);
  if (utf8Size(raw) > MAXIMUM_HISTORY_PAYLOAD_BYTES) return false;
  return safeSet(storage, HISTORY_STORAGE_KEY, raw);
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

function removeReportPayloadFromLegacyBackup(storage: BrowserStorage, backupKey: string): boolean {
  const result = safeGet(storage, backupKey);
  if (!result.ok) return false;
  if (result.value === null) return true;

  let value: unknown;
  try {
    value = JSON.parse(result.value) as unknown;
  } catch {
    // Неразбираемый общий backup нельзя безопасно разделить: удаляем целиком,
    // чтобы команда полного удаления гарантированно не оставляла report payload.
    return safeRemove(storage, backupKey);
  }
  if (!isObject(value)) return safeRemove(storage, backupKey);

  const retained = { ...value };
  delete retained[HISTORY_STORAGE_KEY];
  for (const reportKey of LEGACY_REPORT_KEYS) delete retained[reportKey];

  if (Object.keys(retained).length === 0) return safeRemove(storage, backupKey);
  return safeSet(storage, backupKey, JSON.stringify(retained));
}

function resolveStorage(): BrowserStorage | null {
  if (typeof localStorage === 'undefined') return null;
  return localStorage;
}

function safeGet(storage: BrowserStorage, key: string): StorageReadResult {
  try {
    return { ok: true, value: storage.getItem(key) };
  } catch {
    return { ok: false, value: null };
  }
}

function safeSet(storage: BrowserStorage, key: string, value: string): boolean {
  try {
    storage.setItem(key, value);
    return storage.getItem(key) === value;
  } catch {
    return false;
  }
}

function safeRemove(storage: BrowserStorage, key: string): boolean {
  try {
    storage.removeItem(key);
    return storage.getItem(key) === null;
  } catch {
    return false;
  }
}

function unavailableSnapshot(): ReportHistorySnapshot {
  return {
    reports: [], status: 'unavailable', persisted: false,
    message: 'WebView storage недоступен. Отчёты сохраняются только в памяти текущего сеанса.',
  };
}

function storageReadFailure(sourceKey: string): ReportHistorySnapshot {
  return {
    reports: [], status: 'unavailable', persisted: false, sourceKey,
    message: 'Не удалось прочитать WebView storage. История не считается пустой и не будет перезаписана.',
  };
}

function canOverwrite(status: HistoryStorageStatus): boolean {
  return status === 'ready' || status === 'empty';
}

function containsFutureReportSchema(reports: unknown[]): boolean {
  return reports.some((report) => isObject(report)
    && typeof report.schemaVersion === 'number'
    && report.schemaVersion > currentReportSchemaVersion);
}

function utf8Size(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}
