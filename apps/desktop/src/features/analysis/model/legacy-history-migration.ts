import { currentReportSchemaVersion } from './types';
import { decodeAndMigrateReportArray, migrateReport } from './report-migration';
import {
  HISTORY_STORAGE_KEY,
  HISTORY_STORAGE_VERSION,
  LEGACY_REPORT_KEYS,
  MAXIMUM_HISTORY_PAYLOAD_BYTES,
  MAXIMUM_REPORTS,
  type ReportHistorySnapshot,
} from './history-repository';

export function inspectLegacyHistoryForMigration(): ReportHistorySnapshot {
  if (typeof localStorage === 'undefined') {
    return {
      reports: [], status: 'empty', persisted: false,
      message: 'Legacy WebView storage отсутствует: миграция не требуется.',
    };
  }

  const current = safeGet(HISTORY_STORAGE_KEY);
  if (!current.ok) return readFailure(HISTORY_STORAGE_KEY);
  if (current.value !== null) return parseCurrentEnvelope(current.value);

  for (const key of LEGACY_REPORT_KEYS) {
    const result = safeGet(key);
    if (!result.ok) return readFailure(key);
    if (result.value === null) continue;
    const raw = result.value;
    if (utf8Size(raw) > MAXIMUM_HISTORY_PAYLOAD_BYTES) {
      return {
        reports: [], status: 'tooLarge', persisted: false, sourceKey: key,
        message: 'Legacy-история превышает безопасный лимит миграции и оставлена без изменений.',
      };
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw) as unknown;
    } catch {
      return {
        reports: [], status: 'corrupted', persisted: false, sourceKey: key,
        message: 'Legacy-история повреждена. v0.4.0 не изменяла исходную запись.',
      };
    }
    if (!Array.isArray(parsed)) {
      return {
        reports: [], status: 'corrupted', persisted: false, sourceKey: key,
        message: 'Legacy-история не является ожидаемым массивом отчётов.',
      };
    }
    if (containsFutureReportSchema(parsed)) {
      return futureSnapshot(key);
    }
    const decoded = decodeAndMigrateReportArray(raw, MAXIMUM_REPORTS);
    if (!decoded) {
      return {
        reports: [], status: 'corrupted', persisted: false, sourceKey: key,
        message: 'Legacy-история не прошла миграционную валидацию и оставлена без изменений.',
      };
    }
    return {
      reports: decoded.reports,
      status: decoded.reports.length ? 'ready' : 'empty',
      persisted: false,
      sourceKey: key,
      message: 'Legacy-история прочитана в read-only режиме и готова к переносу в Rust storage.',
    };
  }

  return { reports: [], status: 'empty', persisted: false };
}

function parseCurrentEnvelope(raw: string): ReportHistorySnapshot {
  if (utf8Size(raw) > MAXIMUM_HISTORY_PAYLOAD_BYTES) {
    return {
      reports: [], status: 'tooLarge', persisted: false, sourceKey: HISTORY_STORAGE_KEY,
      message: 'Legacy history envelope превышает безопасный лимит миграции.',
    };
  }
  let value: unknown;
  try {
    value = JSON.parse(raw) as unknown;
  } catch {
    return {
      reports: [], status: 'corrupted', persisted: false, sourceKey: HISTORY_STORAGE_KEY,
      message: 'Legacy history envelope повреждён и оставлен без изменений.',
    };
  }
  if (!isObject(value)
    || typeof value.storageVersion !== 'number'
    || typeof value.reportSchemaVersion !== 'number'
    || !Array.isArray(value.reports)) {
    return {
      reports: [], status: 'corrupted', persisted: false, sourceKey: HISTORY_STORAGE_KEY,
      message: 'Legacy history envelope не соответствует ожидаемому контракту.',
    };
  }
  if (value.storageVersion > HISTORY_STORAGE_VERSION
    || value.reportSchemaVersion > currentReportSchemaVersion
    || containsFutureReportSchema(value.reports)) {
    return futureSnapshot(HISTORY_STORAGE_KEY);
  }
  if (value.storageVersion !== HISTORY_STORAGE_VERSION) {
    return {
      reports: [], status: 'corrupted', persisted: false, sourceKey: HISTORY_STORAGE_KEY,
      message: `Legacy storageVersion=${value.storageVersion} не поддерживается миграцией v0.4.0.`,
    };
  }
  const reports = value.reports.slice(0, MAXIMUM_REPORTS).map(migrateReport);
  return {
    reports,
    status: reports.length ? 'ready' : 'empty',
    persisted: false,
    sourceKey: HISTORY_STORAGE_KEY,
    message: 'Legacy history envelope прочитан в read-only режиме и готов к переносу в Rust storage.',
  };
}

function futureSnapshot(sourceKey: string): ReportHistorySnapshot {
  return {
    reports: [], status: 'unsupported', persisted: false, sourceKey,
    message: 'Legacy-история создана более новой схемой. v0.4.0 не будет изменять или переносить эти данные автоматически.',
  };
}

function readFailure(sourceKey: string): ReportHistorySnapshot {
  return {
    reports: [], status: 'unavailable', persisted: false, sourceKey,
    message: 'Не удалось прочитать legacy WebView storage. Миграция остановлена без изменения данных.',
  };
}

function safeGet(key: string): { ok: boolean; value: string | null } {
  try {
    return { ok: true, value: localStorage.getItem(key) };
  } catch {
    return { ok: false, value: null };
  }
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
