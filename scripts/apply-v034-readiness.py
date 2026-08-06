from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def write(path: str, content: str) -> None:
    target = ROOT / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content.rstrip() + "\n", encoding="utf-8")


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def replace(path: str, old: str, new: str) -> None:
    source = read(path)
    if old not in source:
        raise RuntimeError(f"Expected fragment not found in {path}: {old[:80]!r}")
    write(path, source.replace(old, new))


def update_json(path: str, mutate) -> None:
    value = json.loads(read(path))
    mutate(value)
    write(path, json.dumps(value, ensure_ascii=False, indent=2))


# ---------------------------------------------------------------------------
# Version metadata
# ---------------------------------------------------------------------------
for manifest in [
    "package.json",
    "apps/desktop/package.json",
    "packages/contracts/package.json",
    "apps/desktop/src-tauri/tauri.conf.json",
]:
    update_json(manifest, lambda value: value.__setitem__("version", "0.3.4"))

replace("apps/desktop/src-tauri/Cargo.toml", 'version = "0.3.3"', 'version = "0.3.4"')
replace("apps/desktop/src-tauri/tauri.conf.json", "FileScope 0.3.3", "FileScope 0.3.4")

# ---------------------------------------------------------------------------
# Pure report migration
# ---------------------------------------------------------------------------
write(
    "apps/desktop/src/features/analysis/model/report-migration.ts",
    r'''
import { APP_VERSION } from '../../../shared/config/app-version';
import {
  currentReportSchemaVersion,
  type AnalysisReport,
  type ObjectKind,
  type RiskLevel,
} from './types';

export interface DecodedReportArray {
  reports: AnalysisReport[];
  changed: boolean;
}

export function decodeAndMigrateReportArray(raw: string, maximumReports = 250): DecodedReportArray | null {
  try {
    const value = JSON.parse(raw) as unknown;
    if (!Array.isArray(value)) return null;
    const reports = value.slice(0, maximumReports).map(migrateReport);
    return { reports, changed: JSON.stringify(value) !== JSON.stringify(reports) };
  } catch {
    return null;
  }
}

export function migrateReport(value: unknown): AnalysisReport {
  const raw = isObject(value) ? value : {};
  const schemaVersion = numberValue(raw.schemaVersion, 0);
  if (schemaVersion > currentReportSchemaVersion) return unsupportedFutureReport(raw, schemaVersion);

  const detectedType = stringOrUndefined(raw.detectedType);
  const indicators = Array.isArray(raw.indicators) ? raw.indicators.filter(isIndicator) : [];
  const metadata = isObject(raw.metadata) ? { ...raw.metadata } : {};
  const completeness = raw.analysisCompleteness === 'complete'
    || raw.analysisCompleteness === 'partial'
    || raw.analysisCompleteness === 'stoppedByLimit'
    || raw.analysisCompleteness === 'failed'
    ? raw.analysisCompleteness
    : inferCompleteness(detectedType, indicators, metadata);

  return {
    schemaVersion: currentReportSchemaVersion,
    appVersion: stringValue(raw.appVersion, schemaVersion === 0 ? '0.2.0-legacy' : APP_VERSION),
    analyzerVersion: stringValue(raw.analyzerVersion, 'legacy'),
    ruleSetVersion: stringValue(raw.ruleSetVersion, 'legacy'),
    createdBy: isObject(raw.createdBy)
      ? {
          platform: stringValue(raw.createdBy.platform, 'unknown'),
          architecture: stringValue(raw.createdBy.architecture, 'unknown'),
          runtime: stringValue(raw.createdBy.runtime, 'legacy-storage'),
        }
      : { platform: 'unknown', architecture: 'unknown', runtime: 'legacy-storage' },
    analysisCompleteness: completeness,
    id: stringValue(raw.id, migrationId()),
    objectKind: objectKind(raw.objectKind),
    target: stringValue(raw.target, ''),
    displayName: stringValue(raw.displayName, 'Старый отчёт'),
    startedAt: stringValue(raw.startedAt, new Date(0).toISOString()),
    completedAt: stringValue(raw.completedAt, new Date(0).toISOString()),
    durationMs: numberValue(raw.durationMs, 0),
    sha256: stringOrUndefined(raw.sha256),
    detectedType,
    sizeBytes: optionalNumber(raw.sizeBytes),
    riskLevel: riskLevel(raw.riskLevel),
    riskScore: numberValue(raw.riskScore, 0),
    indicators,
    metadata: { ...metadata, migratedFromSchema: schemaVersion },
    pe: isObject(raw.pe) ? raw.pe as unknown as AnalysisReport['pe'] : undefined,
    url: isObject(raw.url) ? raw.url as unknown as AnalysisReport['url'] : undefined,
    archive: isObject(raw.archive) ? raw.archive as unknown as AnalysisReport['archive'] : undefined,
    isDemo: raw.isDemo === true,
    limitations: Array.isArray(raw.limitations)
      ? raw.limitations.filter((item): item is string => typeof item === 'string')
      : [],
  };
}

function unsupportedFutureReport(raw: Record<string, unknown>, schemaVersion: number): AnalysisReport {
  return {
    schemaVersion,
    appVersion: stringValue(raw.appVersion, 'future'),
    analyzerVersion: stringValue(raw.analyzerVersion, 'future'),
    ruleSetVersion: stringValue(raw.ruleSetVersion, 'future'),
    createdBy: { platform: 'unknown', architecture: 'unknown', runtime: 'unsupported-read-only' },
    analysisCompleteness: 'failed',
    id: stringValue(raw.id, migrationId()),
    objectKind: objectKind(raw.objectKind),
    target: '',
    displayName: stringValue(raw.displayName, 'Отчёт новой версии'),
    startedAt: stringValue(raw.startedAt, new Date(0).toISOString()),
    completedAt: stringValue(raw.completedAt, new Date(0).toISOString()),
    durationMs: 0,
    riskLevel: 'caution',
    riskScore: 0,
    indicators: [],
    metadata: { unsupportedSchema: true, originalSchemaVersion: schemaVersion },
    isDemo: false,
    limitations: [`Схема ${schemaVersion} новее поддерживаемой схемы ${currentReportSchemaVersion}. Отчёт открыт только в безопасном read-only режиме.`],
  };
}

function inferCompleteness(
  detectedType: string | undefined,
  indicators: AnalysisReport['indicators'],
  metadata: Record<string, unknown>,
): AnalysisReport['analysisCompleteness'] {
  if (metadata.analysisStopped) return 'stoppedByLimit';
  if (detectedType === 'RAR archive' || detectedType === '7-Zip archive') return 'partial';
  if (indicators.some((item) => item.id === 'pe.parse.failed')) return 'partial';
  return 'complete';
}

function isIndicator(value: unknown): value is AnalysisReport['indicators'][number] {
  return isObject(value)
    && typeof value.id === 'string'
    && typeof value.title === 'string'
    && Array.isArray(value.evidence);
}

function isObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}

function stringValue(value: unknown, fallback: string): string {
  return typeof value === 'string' ? value : fallback;
}

function stringOrUndefined(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined;
}

function numberValue(value: unknown, fallback: number): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : fallback;
}

function optionalNumber(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined;
}

function objectKind(value: unknown): ObjectKind {
  return value === 'url' || value === 'archive' ? value : 'file';
}

function riskLevel(value: unknown): RiskLevel {
  return value === 'caution' || value === 'highRisk' || value === 'dangerous' ? value : 'noThreatsFound';
}

function migrationId(): string {
  if (typeof crypto !== 'undefined' && 'randomUUID' in crypto) return crypto.randomUUID();
  return `migrated-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}
''',
)

# ---------------------------------------------------------------------------
# Repository boundary around legacy WebView storage
# ---------------------------------------------------------------------------
write(
    "apps/desktop/src/features/analysis/model/history-repository.ts",
    r'''
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
''',
)

# ---------------------------------------------------------------------------
# Stable async facade; limits remain in legacy storage until v0.4.0
# ---------------------------------------------------------------------------
write(
    "apps/desktop/src/features/analysis/model/analysis-storage.ts",
    r'''
import {
  defaultAnalysisLimits,
  type AnalysisLimits,
  type AnalysisReport,
} from './types';
import {
  reportHistoryRepository,
  type ReportHistorySnapshot,
} from './history-repository';

const LIMITS_KEY = 'filescope:limits:v1';
const LEGACY_LIMIT_KEYS = ['filescope:v0.2.0:limits'];
const LIMITS_MIGRATION_BACKUP_KEY = 'filescope:migration-backup:v0.3.3';

export { migrateReport } from './report-migration';

export function loadReportHistory(): Promise<ReportHistorySnapshot> {
  return reportHistoryRepository.load();
}

export async function loadReports(): Promise<AnalysisReport[]> {
  return (await reportHistoryRepository.load()).reports;
}

export async function saveReport(report: AnalysisReport): Promise<AnalysisReport[]> {
  return (await reportHistoryRepository.save(report)).reports;
}

export async function deleteReport(id: string): Promise<AnalysisReport[]> {
  return (await reportHistoryRepository.delete(id)).reports;
}

export async function clearReports(): Promise<AnalysisReport[]> {
  return (await reportHistoryRepository.clear()).reports;
}

export function inspectHistoryStorage(): Promise<ReportHistorySnapshot> {
  return reportHistoryRepository.inspect();
}

export function loadAnalysisLimits(): AnalysisLimits {
  if (typeof localStorage === 'undefined') return defaultAnalysisLimits;
  const current = localStorage.getItem(LIMITS_KEY);
  if (current) return parseLimits(current);
  for (const key of LEGACY_LIMIT_KEYS) {
    const raw = localStorage.getItem(key);
    if (!raw) continue;
    backupLimitsBeforeMigration(key, raw);
    const migrated = parseLimits(raw);
    localStorage.setItem(LIMITS_KEY, JSON.stringify(migrated));
    return migrated;
  }
  return defaultAnalysisLimits;
}

export function saveAnalysisLimits(limits: AnalysisLimits): AnalysisLimits {
  const next = sanitizeLimits(limits);
  if (typeof localStorage !== 'undefined') localStorage.setItem(LIMITS_KEY, JSON.stringify(next));
  return next;
}

export function sanitizeLimits(limits: AnalysisLimits): AnalysisLimits {
  return {
    maximumFileSizeBytes: clampNumber(limits.maximumFileSizeBytes, 1 * 1024 * 1024, 4 * 1024 * 1024 * 1024),
    maximumReadBytes: clampNumber(limits.maximumReadBytes, 1 * 1024 * 1024, 4 * 1024 * 1024 * 1024),
    maximumParserMemoryBytes: clampNumber(limits.maximumParserMemoryBytes, 8 * 1024 * 1024, 512 * 1024 * 1024),
    jobTimeoutMs: Math.round(clampNumber(limits.jobTimeoutMs, 5_000, 30 * 60 * 1_000)),
    maximumArchiveEntries: Math.round(clampNumber(limits.maximumArchiveEntries, 10, 100_000)),
    maximumArchiveUncompressedBytes: clampNumber(limits.maximumArchiveUncompressedBytes, 10 * 1024 * 1024, 20 * 1024 * 1024 * 1024),
    maximumArchiveDepth: Math.round(clampNumber(limits.maximumArchiveDepth, 1, 64)),
    maximumCompressionRatio: clampNumber(limits.maximumCompressionRatio, 2, 10_000),
    activeUrlTimeoutMs: Math.round(clampNumber(limits.activeUrlTimeoutMs, 1_000, 30_000)),
    activeUrlRedirectLimit: Math.round(clampNumber(limits.activeUrlRedirectLimit, 0, 10)),
  };
}

function parseLimits(raw: string): AnalysisLimits {
  try {
    const value = JSON.parse(raw) as Partial<AnalysisLimits>;
    return sanitizeLimits({ ...defaultAnalysisLimits, ...value });
  } catch {
    return defaultAnalysisLimits;
  }
}

function backupLimitsBeforeMigration(sourceKey: string, raw: string): void {
  if (typeof localStorage === 'undefined') return;
  try {
    const existing = localStorage.getItem(LIMITS_MIGRATION_BACKUP_KEY);
    const backups = existing ? JSON.parse(existing) as Record<string, string> : {};
    if (!(sourceKey in backups)) {
      backups[sourceKey] = raw;
      localStorage.setItem(LIMITS_MIGRATION_BACKUP_KEY, JSON.stringify(backups));
    }
  } catch {
    // Исходный limits key остаётся нетронутым.
  }
}

function clampNumber(value: number, minimum: number, maximum: number): number {
  if (!Number.isFinite(value)) return minimum;
  return Math.min(maximum, Math.max(minimum, value));
}
''',
)

# ---------------------------------------------------------------------------
# Future v0.4 privacy policy helpers (not wired into production persistence)
# ---------------------------------------------------------------------------
write(
    "apps/desktop/src/features/analysis/model/history-privacy.ts",
    r'''
import type { AnalysisReport } from './types';

export interface HistoryPrivacyPolicy {
  preserveFullPath: boolean;
  preserveUrlQuery: boolean;
  preserveUrlFragment: boolean;
}

export const proposedV040PrivacyPolicy: HistoryPrivacyPolicy = {
  preserveFullPath: false,
  preserveUrlQuery: false,
  preserveUrlFragment: false,
};

const SENSITIVE_HEADER_NAMES = new Set([
  'authorization', 'proxy-authorization', 'cookie', 'set-cookie', 'x-api-key',
  'x-auth-token', 'proxy-authenticate', 'www-authenticate',
]);

export function redactUrlForHistory(value: string, policy: HistoryPrivacyPolicy): string {
  try {
    const parsed = new URL(value);
    parsed.username = '';
    parsed.password = '';
    if (!policy.preserveUrlQuery) parsed.search = '';
    if (!policy.preserveUrlFragment) parsed.hash = '';
    return parsed.toString();
  } catch {
    return value.replace(/\/\/[^/@\s]+@/g, '//[credentials-redacted]@');
  }
}

export function minimizePathForHistory(value: string, preserveFullPath: boolean): string {
  if (preserveFullPath) return value;
  const normalized = value.replaceAll('\\', '/');
  return normalized.split('/').filter(Boolean).at(-1) ?? value;
}

export function filterHeadersForHistory(headers: [string, string][]): [string, string][] {
  return headers.filter(([name]) => !SENSITIVE_HEADER_NAMES.has(name.trim().toLocaleLowerCase('en-US')));
}

export function minimizeReportForFutureStorage(
  report: AnalysisReport,
  policy: HistoryPrivacyPolicy = proposedV040PrivacyPolicy,
): AnalysisReport {
  const isUrl = report.objectKind === 'url';
  const target = isUrl
    ? redactUrlForHistory(report.target, policy)
    : minimizePathForHistory(report.target, policy.preserveFullPath);
  const url = report.url
    ? {
        ...report.url,
        normalizedUrl: redactUrlForHistory(report.url.normalizedUrl, policy),
        finalUrl: report.url.finalUrl ? redactUrlForHistory(report.url.finalUrl, policy) : undefined,
        responseHeaders: filterHeadersForHistory(report.url.responseHeaders),
      }
    : undefined;
  return {
    ...report,
    target,
    url,
    metadata: {
      ...report.metadata,
      privacyPreparedForV040: true,
      fullPathPreserved: policy.preserveFullPath,
      urlQueryPreserved: policy.preserveUrlQuery,
      urlFragmentPreserved: policy.preserveUrlFragment,
    },
  };
}
''',
)

# ---------------------------------------------------------------------------
# Tests and fixtures
# ---------------------------------------------------------------------------
write(
    "apps/desktop/src/features/analysis/model/analysis-storage.test.ts",
    r'''
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
''',
)

write(
    "apps/desktop/src/features/analysis/model/history-privacy.test.ts",
    r'''
import { describe, expect, it } from 'vitest';
import {
  filterHeadersForHistory,
  minimizePathForHistory,
  redactUrlForHistory,
} from './history-privacy';

const privatePolicy = {
  preserveFullPath: false,
  preserveUrlQuery: false,
  preserveUrlFragment: false,
};

describe('v0.4 privacy preparation properties', () => {
  it('никогда не возвращает username/password из корректного HTTP URL', () => {
    for (let index = 0; index < 256; index += 1) {
      const password = `secret-${index}-value`;
      const value = `https://user:${password}@example.com/path?q=${index}#fragment`;
      const redacted = redactUrlForHistory(value, privatePolicy);
      expect(redacted).not.toContain(password);
      expect(redacted).not.toContain('user:');
      expect(redacted).not.toContain('?');
      expect(redacted).not.toContain('#');
    }
  });

  it('фильтрует чувствительные headers независимо от регистра', () => {
    const safe = filterHeadersForHistory([
      ['Set-Cookie', 'session=secret'],
      ['AUTHORIZATION', 'Bearer secret'],
      ['Content-Type', 'text/plain'],
    ]);
    expect(safe).toEqual([['Content-Type', 'text/plain']]);
  });

  it('сохраняет только basename при выключенном полном пути', () => {
    expect(minimizePathForHistory('C:\\Users\\Example\\sample.exe', false)).toBe('sample.exe');
    expect(minimizePathForHistory('/home/example/sample.bin', false)).toBe('sample.bin');
  });
});
''',
)

fixtures = {
    "legacy-v020.json": [{"id": "legacy", "objectKind": "file", "target": "C:/legacy.exe", "displayName": "legacy.exe", "riskLevel": "caution", "riskScore": 12, "indicators": [], "metadata": {}, "limitations": []}],
    "schema-v1-array.json": [{"schemaVersion": 1, "id": "schema-v1", "objectKind": "file", "target": "C:/schema-v1.exe", "displayName": "schema-v1.exe", "riskLevel": "noThreatsFound", "riskScore": 0, "indicators": [], "metadata": {}, "limitations": []}],
    "storage-v1.json": {"storageVersion": 1, "reportSchemaVersion": 1, "savedAt": "2026-08-06T00:00:00Z", "reports": []},
    "future-storage.json": {"storageVersion": 99, "reportSchemaVersion": 99, "savedAt": "2026-08-06T00:00:00Z", "reports": []},
}
for name, value in fixtures.items():
    write(f"apps/desktop/src/features/analysis/model/fixtures/history/{name}", json.dumps(value, ensure_ascii=False, indent=2))
write("apps/desktop/src/features/analysis/model/fixtures/history/corrupted.json", "{ intentionally-invalid-json")

# ---------------------------------------------------------------------------
# Async UI integration
# ---------------------------------------------------------------------------
replace(
    "apps/desktop/src/features/analysis/ui/AnalysisWorkspace.tsx",
    "        saveReport(result);",
    "        await saveReport(result);",
)

write(
    "apps/desktop/src/features/analysis/ui/ReportHistory.tsx",
    r'''
import { useEffect, useMemo, useRef, useState } from 'react';
import { AlertTriangle, FileJson2, LoaderCircle, Search, ShieldCheck, Trash2 } from 'lucide-react';
import { clearReports, deleteReport, loadReportHistory } from '../model/analysis-storage';
import type { HistoryStorageStatus } from '../model/history-repository';
import { riskLabels, type AnalysisReport, type ObjectKind, type RiskLevel } from '../model/types';
import { ReportView } from './ReportView';

export function ReportHistory() {
  const [reports, setReports] = useState<AnalysisReport[]>([]);
  const [storageStatus, setStorageStatus] = useState<HistoryStorageStatus>('ready');
  const [storageMessage, setStorageMessage] = useState('');
  const [loading, setLoading] = useState(true);
  const [query, setQuery] = useState('');
  const [kind, setKind] = useState<'all' | ObjectKind>('all');
  const [risk, setRisk] = useState<'all' | RiskLevel>('all');
  const [selected, setSelected] = useState<AnalysisReport | null>(null);
  const [clearConfirmationOpen, setClearConfirmationOpen] = useState(false);
  const cancelClearRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    let active = true;
    void loadReportHistory().then((snapshot) => {
      if (!active) return;
      setReports(snapshot.reports);
      setStorageStatus(snapshot.status);
      setStorageMessage(snapshot.message ?? '');
      setLoading(false);
    });
    return () => { active = false; };
  }, []);

  useEffect(() => {
    if (clearConfirmationOpen) cancelClearRef.current?.focus();
  }, [clearConfirmationOpen]);

  const filtered = useMemo(
    () => reports.filter((report) => {
      const matchesQuery = `${report.displayName} ${report.target} ${report.sha256 ?? ''}`
        .toLocaleLowerCase('ru-RU').includes(query.toLocaleLowerCase('ru-RU'));
      return matchesQuery
        && (kind === 'all' || report.objectKind === kind)
        && (risk === 'all' || report.riskLevel === risk);
    }),
    [reports, query, kind, risk],
  );

  const remove = async (id: string) => {
    const next = await deleteReport(id);
    setReports(next);
    if (selected?.id === id) setSelected(null);
  };

  const clearHistory = async () => {
    setReports(await clearReports());
    setSelected(null);
    setStorageStatus('empty');
    setStorageMessage('');
    setClearConfirmationOpen(false);
  };

  if (selected) {
    return <div className="analysis-history">
      <button type="button" className="text-button" onClick={() => setSelected(null)}>← Вернуться к истории</button>
      <ReportView report={selected} />
    </div>;
  }

  return <div className="analysis-history">
    <section className="analysis-history__toolbar card">
      <label className="analysis-search">
        <Search />
        <input className="input" value={query} onChange={(event) => setQuery(event.target.value)}
          placeholder="Поиск по имени, пути или SHA-256" aria-label="Поиск по истории отчётов" />
      </label>
      <select className="input compact" value={kind}
        onChange={(event) => setKind(event.target.value as 'all' | ObjectKind)} aria-label="Фильтр истории по типу объекта">
        <option value="all">Все объекты</option><option value="file">Файлы</option>
        <option value="url">URL</option><option value="archive">Архивы</option>
      </select>
      <select className="input compact" value={risk}
        onChange={(event) => setRisk(event.target.value as 'all' | RiskLevel)} aria-label="Фильтр истории по уровню риска">
        <option value="all">Все уровни риска</option>
        <option value="noThreatsFound">Без обнаруженных признаков</option>
        <option value="caution">Требует внимания</option><option value="highRisk">Высокий риск</option>
        <option value="dangerous">Опасный объект</option>
      </select>
      {reports.length > 0 && <button type="button" className="button button-secondary analysis-history__clear"
        onClick={() => setClearConfirmationOpen(true)}><Trash2 />Очистить историю</button>}
    </section>

    {storageStatus !== 'ready' && storageStatus !== 'empty' && <section className="card warning-banner" role="status">
      <AlertTriangle />
      <div><strong>История открыта в защитном режиме</strong><p>{storageMessage || historyStatusMessage(storageStatus)}</p></div>
    </section>}

    {clearConfirmationOpen && <section className="analysis-history__confirmation card" role="alertdialog"
      aria-modal="true" aria-labelledby="clear-history-title" aria-describedby="clear-history-description"
      onKeyDown={(event) => { if (event.key === 'Escape') setClearConfirmationOpen(false); }}>
      <div className="analysis-history__confirmation-content">
        <strong id="clear-history-title">Очистить всю историю?</strong>
        <p id="clear-history-description">Все локально сохранённые отчёты будут удалены без возможности восстановления. Резервные копии миграции и настройки анализа останутся нетронутыми.</p>
      </div>
      <div className="analysis-history__confirmation-actions">
        <button ref={cancelClearRef} type="button" className="button button-secondary" onClick={() => setClearConfirmationOpen(false)}>Отмена</button>
        <button type="button" className="button button-danger" onClick={() => void clearHistory()}><Trash2 />Удалить все отчёты</button>
      </div>
    </section>}

    {loading ? <section className="card empty analysis-history__empty" role="status">
      <LoaderCircle className="spin" size={42} /><h2>Загрузка истории</h2><p>Проверяется версия локального storage envelope.</p>
    </section> : filtered.length === 0 ? <section className="card empty analysis-history__empty">
      <FileJson2 size={42} /><h2>{reports.length === 0 ? 'Отчётов пока нет' : 'Ничего не найдено'}</h2>
      <p>{reports.length === 0
        ? 'Выполните локальную проверку файла, URL или ZIP-архива. В v0.3.4 история проходит через совместимый repository adapter перед переносом в защищённое хранилище v0.4.0.'
        : 'Измените поисковый запрос или выбранные фильтры.'}</p>
    </section> : <section className="analysis-report-grid">
      {filtered.map((report) => <article className={`analysis-report-card risk-${report.riskLevel}`} key={report.id}>
        <button type="button" className="analysis-report-card__body" onClick={() => setSelected(report)}>
          <div className="analysis-report-card__icon"><ShieldCheck /></div>
          <div><strong>{report.displayName}</strong><span>{report.detectedType ?? report.objectKind} · {new Date(report.completedAt).toLocaleString('ru-RU')}</span>
            <b>{riskLabels[report.riskLevel]} · {report.riskScore}/100</b></div>
        </button>
        <button type="button" className="icon-button danger" onClick={() => void remove(report.id)}
          aria-label={`Удалить отчёт «${report.displayName}»`}><Trash2 /></button>
      </article>)}
    </section>}
  </div>;
}

function historyStatusMessage(status: HistoryStorageStatus): string {
  if (status === 'tooLarge') return 'История превышает безопасный лимит чтения.';
  if (status === 'unsupported') return 'История создана более новой версией FileScope и не перезаписывается.';
  if (status === 'corrupted') return 'История повреждена и сохранена без перезаписи для диагностики.';
  return 'WebView storage недоступен; текущий сеанс продолжает работать без постоянного сохранения.';
}
''',
)

# ---------------------------------------------------------------------------
# Shared storage contract
# ---------------------------------------------------------------------------
contracts = read("packages/contracts/src/analysis.ts")
needle = "export const FILESCOPE_REPORT_SCHEMA_VERSION = 1;\n"
addition = needle + "export const FILESCOPE_HISTORY_STORAGE_VERSION = 1;\n\nexport type HistoryStorageStatus = 'ready' | 'empty' | 'corrupted' | 'unsupported' | 'tooLarge' | 'unavailable';\n\nexport interface ReportHistoryEnvelope<TReport> {\n  storageVersion: number;\n  reportSchemaVersion: number;\n  savedAt: string;\n  reports: TReport[];\n}\n"
if needle not in contracts:
    raise RuntimeError("shared contract insertion point missing")
write("packages/contracts/src/analysis.ts", contracts.replace(needle, addition))

# ---------------------------------------------------------------------------
# Rust property and fuzz preparation
# ---------------------------------------------------------------------------
replace(
    "apps/desktop/src-tauri/src/analysis/rules.rs",
    "    let score = unique\n        .iter()\n        .map(|indicator| indicator.score)\n        .sum::<u16>()\n        .min(100);",
    "    let score = unique\n        .iter()\n        .fold(0_u16, |total, indicator| total.saturating_add(indicator.score))\n        .min(100);",
)
replace(
    "apps/desktop/src-tauri/src/analysis/mod.rs",
    "mod url;\n",
    "mod url;\n#[cfg(feature = \"fuzzing\")]\npub mod fuzzing;\n#[cfg(test)]\nmod properties;\n",
)
replace(
    "apps/desktop/src-tauri/src/lib.rs",
    "mod window_lifecycle;\n",
    "mod window_lifecycle;\n\n#[cfg(feature = \"fuzzing\")]\npub use analysis::fuzzing;\n",
)
replace(
    "apps/desktop/src-tauri/Cargo.toml",
    "[lib]\n",
    "[features]\ndefault = []\nfuzzing = []\n\n[lib]\n",
)

write(
    "apps/desktop/src-tauri/src/analysis/properties.rs",
    r'''
use super::{
    jobs::JobRegistry,
    rules::{calculate_risk, indicator},
    types::{IndicatorSeverity, RiskLevel},
    url,
};

#[test]
fn risk_score_is_bounded_for_large_synthetic_sets() {
    let values = (0..10_000)
        .map(|index| indicator(
            &format!("property.{index}"), "Synthetic", "Synthetic", "property",
            IndicatorSeverity::Low, u16::MAX, vec![format!("evidence-{index}")], "review",
        ))
        .collect::<Vec<_>>();
    let (score, level) = calculate_risk(&values);
    assert_eq!(score, 100);
    assert_eq!(level, RiskLevel::Dangerous);
}

#[test]
fn independent_indicator_order_does_not_change_result() {
    let mut values = (0..128)
        .map(|index| indicator(
            &format!("property.{index}"), "Synthetic", "Synthetic", "property",
            IndicatorSeverity::Info, (index % 5) as u16, vec![format!("evidence-{index}")], "review",
        ))
        .collect::<Vec<_>>();
    let first = calculate_risk(&values);
    values.reverse();
    assert_eq!(calculate_risk(&values), first);
}

#[test]
fn duplicate_normalized_indicators_do_not_raise_score() {
    let value = indicator(
        "property.duplicate", "Synthetic", "Synthetic", "property",
        IndicatorSeverity::Medium, 20,
        vec!["kernel32.dll!ExampleApi".to_string(), "ExampleApi".to_string()], "review",
    );
    assert_eq!(calculate_risk(&[value.clone(), value.clone()]), calculate_risk(&[value]));
}

#[test]
fn passive_url_never_returns_plaintext_password() {
    for index in 0..128 {
        let password = format!("secret-{index}-value");
        let input = format!("https://user:{password}@example.com/path?q={index}#fragment");
        let registry = JobRegistry::default();
        let token = registry.start(&format!("url-property-{index}"), 10_000).unwrap();
        let report = url::analyze_url_passive(input, &token).unwrap();
        let serialized = serde_json::to_string(&report).unwrap();
        assert!(!serialized.contains(&password));
    }
}
''',
)

write(
    "apps/desktop/src-tauri/src/analysis/fuzzing.rs",
    r'''
//! Safe, bounded entry points used only by cargo-fuzz targets.

use super::{
    jobs::JobRegistry,
    rules::{calculate_risk, indicator},
    types::{AnalysisReport, IndicatorSeverity},
    url,
};

pub fn report_deserialization(data: &[u8]) {
    let result = serde_json::from_slice::<AnalysisReport>(data);
    if let Ok(report) = result {
        let _ = serde_json::to_vec(&report);
    }
}

pub fn passive_url(data: &[u8]) {
    let Ok(input) = std::str::from_utf8(data) else { return };
    if input.len() > 4_096 { return; }
    let registry = JobRegistry::default();
    let Ok(token) = registry.start("fuzz-passive-url", 2_000) else { return };
    let _ = url::analyze_url_passive(input.to_string(), &token);
}

pub fn rule_engine(data: &[u8]) {
    let indicators = data.chunks(4).take(1_024).enumerate().map(|(index, chunk)| {
        let score = chunk.first().copied().unwrap_or_default() as u16;
        indicator(
            &format!("fuzz.{}", index % 64), "Fuzz", "Fuzz", "fuzz",
            IndicatorSeverity::Info, score,
            vec![format!("evidence-{}", chunk.get(1).copied().unwrap_or_default())], "review",
        )
    }).collect::<Vec<_>>();
    let _ = calculate_risk(&indicators);
}
''',
)

write(
    "apps/desktop/src-tauri/fuzz/Cargo.toml",
    r'''
[package]
name = "filescope-fuzz"
version = "0.0.0"
publish = false
edition = "2021"

[package.metadata]
cargo-fuzz = true

[dependencies]
libfuzzer-sys = "0.4"
filescope_lib = { package = "filescope", path = "..", features = ["fuzzing"] }

[[bin]]
name = "report_deserialization"
path = "fuzz_targets/report_deserialization.rs"
test = false
doc = false
bench = false

[[bin]]
name = "passive_url"
path = "fuzz_targets/passive_url.rs"
test = false
doc = false
bench = false

[[bin]]
name = "rule_engine"
path = "fuzz_targets/rule_engine.rs"
test = false
doc = false
bench = false
''',
)
for target, function in [
    ("report_deserialization", "report_deserialization"),
    ("passive_url", "passive_url"),
    ("rule_engine", "rule_engine"),
]:
    write(
        f"apps/desktop/src-tauri/fuzz/fuzz_targets/{target}.rs",
        f"#![no_main]\nuse libfuzzer_sys::fuzz_target;\n\nfuzz_target!(|data: &[u8]| filescope_lib::fuzzing::{function}(data));\n",
    )
write("apps/desktop/src-tauri/fuzz/corpus/.gitkeep", "")

# ---------------------------------------------------------------------------
# Readiness scripts
# ---------------------------------------------------------------------------
write(
    "scripts/check-v040-readiness.mjs",
    r'''
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

const root = process.cwd();
const required = [
  'apps/desktop/src/features/analysis/model/history-repository.ts',
  'apps/desktop/src/features/analysis/model/report-migration.ts',
  'apps/desktop/src/features/analysis/model/history-privacy.ts',
  'apps/desktop/src-tauri/src/analysis/properties.rs',
  'apps/desktop/src-tauri/src/analysis/fuzzing.rs',
  'apps/desktop/src-tauri/fuzz/Cargo.toml',
  '.github/workflows/security-fuzz.yml',
  'docs/architecture/history-storage-migration-v040.md',
  'docs/security/fuzzing-policy.md',
  'docs/product/v0.4.0-readiness-checklist.md',
];
const errors = [];
for (const path of required) if (!existsSync(join(root, path))) errors.push(`missing ${path}`);

const historyLiterals = ['filescope:history:storage-', 'filescope:reports:schema-', 'filescope:v0.2.0:reports'];
const allowedHistoryFiles = new Set([
  'apps/desktop/src/features/analysis/model/history-repository.ts',
  'apps/desktop/src/features/analysis/model/analysis-storage.test.ts',
]);
for (const path of walk(join(root, 'apps/desktop/src'))) {
  const rel = relative(root, path).replaceAll('\\', '/');
  if (allowedHistoryFiles.has(rel)) continue;
  const text = readFileSync(path, 'utf8');
  for (const literal of historyLiterals) if (text.includes(literal)) errors.push(`${rel}: direct history key ${literal}`);
}

const fixtureDirectory = join(root, 'apps/desktop/src/features/analysis/model/fixtures/history');
if (existsSync(fixtureDirectory)) {
  for (const name of readdirSync(fixtureDirectory)) {
    const text = readFileSync(join(fixtureDirectory, name), 'utf8');
    if (name === 'corrupted.json') {
      try { JSON.parse(text); errors.push('corrupted.json must stay intentionally invalid'); } catch { /* expected */ }
    } else {
      try { JSON.parse(text); } catch { errors.push(`${name}: invalid migration fixture`); }
    }
  }
}

for (const target of ['report_deserialization', 'passive_url', 'rule_engine']) {
  const path = join(root, `apps/desktop/src-tauri/fuzz/fuzz_targets/${target}.rs`);
  if (!existsSync(path)) continue;
  const text = readFileSync(path, 'utf8');
  for (const forbidden of ['std::process::Command', 'reqwest::', 'std::fs::write', 'File::create']) {
    if (text.includes(forbidden)) errors.push(`${target}: forbidden fuzz side effect ${forbidden}`);
  }
}

const fuzzWorkflowPath = join(root, '.github/workflows/security-fuzz.yml');
if (existsSync(fuzzWorkflowPath)) {
  const workflow = readFileSync(fuzzWorkflowPath, 'utf8');
  if (!/permissions:\s*\n\s*contents:\s*read/m.test(workflow)) errors.push('security-fuzz workflow must be contents: read');
  if (/contents:\s*write|environment:\s*production|secrets\./.test(workflow)) errors.push('security-fuzz workflow has forbidden privilege/secrets');
  const retention = [...workflow.matchAll(/retention-days:\s*(\d+)/g)].map((match) => Number(match[1]));
  if (retention.some((days) => days > 3)) errors.push('fuzz crash retention must be <= 3 days');
}

for (const workflow of walk(join(root, '.github/workflows'))) {
  const text = readFileSync(workflow, 'utf8');
  for (const oldAction of ['actions/checkout@v4', 'actions/setup-node@v4', 'actions/upload-artifact@v4', 'actions/download-artifact@v4']) {
    if (text.includes(oldAction)) errors.push(`${relative(root, workflow)}: deprecated ${oldAction}`);
  }
}

if (errors.length) {
  console.error('FileScope v0.4.0 readiness check failed:');
  for (const error of errors) console.error(`- ${error}`);
  process.exit(1);
}
console.log('FileScope v0.4.0 readiness boundary OK.');

function* walk(directory) {
  if (!existsSync(directory)) return;
  for (const entry of readdirSync(directory)) {
    const path = join(directory, entry);
    const stats = statSync(path);
    if (stats.isDirectory()) yield* walk(path);
    else yield path;
  }
}
''',
)

write(
    "scripts/release-preflight.mjs",
    r'''
import { existsSync, readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';

const development = process.argv.includes('--development');
const packageJson = JSON.parse(readFileSync('package.json', 'utf8'));
const version = packageJson.version;
if (!/^\d+\.\d+\.\d+(?:[-.][0-9A-Za-z.-]+)?$/.test(version)) throw new Error(`Invalid version: ${version}`);
for (const file of ['pnpm-lock.yaml', 'apps/desktop/src-tauri/Cargo.lock', `docs/releases/v${version}.md`]) {
  if (!existsSync(file)) throw new Error(`Required release file missing: ${file}`);
}
const changelog = readFileSync('CHANGELOG.md', 'utf8');
if (!changelog.includes(`## [${version}]`)) throw new Error(`CHANGELOG section ${version} missing`);
execFileSync(process.execPath, ['scripts/check-version-consistency.mjs'], { stdio: 'inherit' });
execFileSync(process.execPath, ['scripts/check-v040-readiness.mjs'], { stdio: 'inherit' });
console.log(`Release preflight OK for FileScope ${version}${development ? ' (development mode)' : ''}.`);
''',
)

# Update package scripts.
def root_scripts(value):
    scripts = value.setdefault("scripts", {})
    scripts["check:v040-readiness"] = "node scripts/check-v040-readiness.mjs"
    scripts["release:preflight"] = "node scripts/release-preflight.mjs"
    scripts["test:properties"] = "pnpm --filter @filescope/desktop test:properties && cargo test --manifest-path apps/desktop/src-tauri/Cargo.toml --locked properties"
    scripts["check:readiness"] = "pnpm check:version && pnpm check:v040-readiness && pnpm test:properties"

update_json("package.json", root_scripts)

def desktop_scripts(value):
    value.setdefault("scripts", {})["test:properties"] = "vitest run --config vitest.config.ts src/features/analysis/model/history-privacy.test.ts"

update_json("apps/desktop/package.json", desktop_scripts)

# ---------------------------------------------------------------------------
# Documentation
# ---------------------------------------------------------------------------
write(
    "docs/product/v0.3.4-readiness.md",
    r'''
# FileScope v0.3.4 — readiness release

v0.3.4 не переносит production-историю в Tauri storage и не закрывает Issues #42/#49. Версия создаёт совместимый фундамент для v0.4.0:

- async `ReportHistoryRepository` отделяет UI от WebView storage;
- legacy localStorage помещается за отдельный adapter;
- report schema отделена от storage envelope version;
- повреждённые, чрезмерно большие и future envelopes не перезаписываются;
- migration fixtures фиксируют форматы v0.2.0, schema v1 и storage v1;
- privacy helpers определяют будущую минимизацию путей, URL и headers;
- property и bounded fuzz targets проверяют основные инварианты без malware samples;
- CI выполняет readiness preflight перед будущим v0.4.0.

## Граница релиза

В v0.3.4 production persistence всё ещё использует WebView localStorage через `LegacyLocalStorageReportHistoryRepository`. Это намеренное совместимое состояние. Переключение на Rust/Tauri storage, retention settings и DPAPI относится к v0.4.0.
''',
)
(ROOT / "docs/product/v0.3.4-scope.md").unlink(missing_ok=True)

write(
    "docs/architecture/history-storage-migration-v040.md",
    r'''
# ADR: миграция истории FileScope к v0.4.0

## Решение

UI работает только с асинхронным `ReportHistoryRepository`. В v0.3.4 используется legacy adapter; в v0.4.0 он будет заменён Tauri/Rust adapter без изменения компонентов истории и анализа.

## Версии

`schemaVersion` описывает структуру одного отчёта. `storageVersion` описывает контейнер, транзакции и способ хранения набора отчётов. Эти версии изменяются независимо.

## Миграция

1. Прочитать versioned Tauri storage.
2. При отсутствии прочитать storage-v1 WebView envelope.
3. При отсутствии прочитать schema-v1 raw array и v0.2.0 keys.
4. Проверить размер до JSON parse.
5. Создать неизменяемую backup-копию исходной записи.
6. Валидировать и мигрировать каждый отчёт.
7. Атомарно записать новый Rust storage.
8. Не удалять legacy keys до подтверждённого успешного запуска и отдельного периода отката.

## Ошибки

Future, corrupted и oversized storage никогда не перезаписывается автоматически. Пользователь получает read-only/diagnostic status. Ошибка одной записи не должна ломать запуск приложения.

## Rollback

v0.4.0 должен уметь вернуться к backup или экспортировать диагностическую копию. Двойная запись чувствительных данных запрещена: после переключения активен только один authoritative repository.
''',
)

write(
    "docs/security/fuzzing-policy.md",
    r'''
# Политика fuzzing FileScope

Разрешены только synthetic/random bytes, минимальные conformance fixtures с проверенной лицензией и минимизированные невредоносные crash inputs.

Запрещены malware samples, активные вредоносные URL, credentials, tokens, пользовательские файлы и большие бинарные corpus без review.

Fuzz targets не выполняют сеть, процессы, извлечение архивов или запись в пользовательские каталоги. Workflow работает с `contents: read`, без secrets и production Environment, с жёстким timeout. Crash artifacts хранятся не более трёх дней.

Потенциально security-sensitive crash не публикуется публичным Issue с exploit details. Он проходит private triage: минимизация, проверка отсутствия секретов, классификация panic/OOM/hang/invariant, безопасный regression fixture и исправление root cause.
''',
)

write(
    "docs/product/v0.4.0-readiness-checklist.md",
    r'''
# FileScope v0.4.0 readiness checklist

- [x] UI отделён от конкретного history backend асинхронным repository contract.
- [x] Report schema и storage envelope version разделены.
- [x] Legacy migration fixtures и backup policy зафиксированы.
- [x] Future/corrupted/oversized storage не перезаписывается.
- [x] Privacy minimization helpers подготовлены и протестированы.
- [x] Быстрые property tests входят в PR CI.
- [x] Bounded fuzz targets и read-only workflow подготовлены.
- [ ] Реализован Rust/Tauri atomic storage.
- [ ] Выполнена миграция localStorage → Tauri storage.
- [ ] Добавлены retention и privacy settings UI.
- [ ] Исследован и реализован DPAPI policy для installed mode.
- [ ] Описано поведение portable mode.
- [ ] Issue #42 закрыт полным ручным тестированием.
- [ ] Issue #49 закрыт длительными scheduled fuzz runs.
''',
)

write(
    "docs/releases/v0.3.4.md",
    r'''
# FileScope v0.3.4 — подготовка к v0.4.0

Статус: разработка и ручное тестирование. Релиз не опубликован.

## Основные изменения

- история переведена на асинхронный `ReportHistoryRepository`;
- legacy localStorage изолирован отдельным adapter;
- добавлен storage envelope v1, независимый от report schema v1;
- future, corrupted и oversized history не перезаписываются;
- подготовлены migration fixtures и rollback plan;
- добавлены privacy helpers для будущей минимизации путей, URL и headers;
- Rule Engine использует saturating accumulation и проверяется property tests;
- добавлены bounded cargo-fuzz targets для report JSON, passive URL и Rule Engine;
- добавлен read-only security fuzz workflow с коротким retention;
- CI получает readiness/release preflight;
- GitHub Actions переводятся на Node 24 runtime majors.

## Ограничение

Production-история v0.3.4 всё ещё физически хранится в WebView localStorage через совместимый legacy adapter. Переключение на Tauri storage, DPAPI, retention и пользовательские privacy settings выполняется в v0.4.0.

Связано с #63. Issues #42 и #49 получают подготовительный прогресс, но остаются открытыми.
''',
)

changelog = read("CHANGELOG.md")
marker = "## [Не выпущено]\n"
section = """## [Не выпущено]\n\n## [0.3.4] — в разработке\n\n### Добавлено\n\n- асинхронная граница `ReportHistoryRepository` и versioned storage envelope v1;\n- migration fixtures, privacy helpers и readiness preflight для v0.4.0;\n- быстрые property tests и bounded fuzz targets без malware samples;\n- read-only scheduled/manual fuzz workflow с коротким retention.\n\n### Изменено\n\n- UI истории больше не зависит от синхронного прямого доступа к report keys;\n- накопление risk score защищено от переполнения на больших synthetic inputs;\n- GitHub Actions подготовлены к Node.js 24 runtime.\n\n### Важно\n\n- v0.3.4 остаётся совместимым readiness-релизом: Tauri/DPAPI storage и privacy settings входят в v0.4.0.\n"
if marker not in changelog:
    raise RuntimeError("CHANGELOG marker missing")
write("CHANGELOG.md", changelog.replace(marker, section, 1))

readme = read("README.md")
readme = readme.replace(
    "> **Последний опубликованный релиз:** `v0.3.3`  ",
    "> **Последний опубликованный релиз:** `v0.3.3`  \n> **Текущая версия разработки:** `v0.3.4`  ",
)
readme = readme.replace(
    "## BugFix v0.3.3\n",
    "## Подготовка v0.3.4 к v0.4.0\n\n- storage boundary отделяет UI истории от WebView localStorage;\n- versioned envelope и migration fixtures готовят безопасный переход на Tauri storage;\n- privacy helpers и property/fuzz infrastructure закрепляют требования #42 и #49;\n- пользовательские retention/privacy settings и DPAPI остаются задачами v0.4.0.\n\nПодробности: [readiness scope v0.3.4](docs/product/v0.3.4-readiness.md).\n\n## BugFix v0.3.3\n",
)
write("README.md", readme)

contributing = read("CONTRIBUTING.md")
if "## Fuzzing и private triage" not in contributing:
    contributing += r'''

## Fuzzing и private triage

Fuzz corpus не должен содержать malware, active malicious URLs, secrets или пользовательские файлы. Быстрые property tests обязательны для security-sensitive изменений. Потенциальный security crash оформляется через Private Vulnerability Reporting; публичный Issue допускается только после устранения чувствительных деталей и оценки affected versions.
'''
write("CONTRIBUTING.md", contributing)

# Extend version consistency with history storage contract checks.
version_check = read("scripts/check-version-consistency.mjs")
version_check = version_check.replace(
    "const sharedSchema = Number(sharedContracts.match(/FILESCOPE_REPORT_SCHEMA_VERSION\\s*=\\s*(\\d+)/)?.[1]);",
    "const sharedSchema = Number(sharedContracts.match(/FILESCOPE_REPORT_SCHEMA_VERSION\\s*=\\s*(\\d+)/)?.[1]);\nconst frontendStorage = read('apps/desktop/src/features/analysis/model/history-repository.ts');\nconst frontendStorageVersion = Number(frontendStorage.match(/HISTORY_STORAGE_VERSION\\s*=\\s*(\\d+)/)?.[1]);\nconst sharedStorageVersion = Number(sharedContracts.match(/FILESCOPE_HISTORY_STORAGE_VERSION\\s*=\\s*(\\d+)/)?.[1]);",
)
version_check = version_check.replace(
    "if (contractErrors.length) {",
    "if (!frontendStorageVersion || frontendStorageVersion !== sharedStorageVersion) {\n  contractErrors.push(`History storage mismatch: frontend=${frontendStorageVersion}, contracts=${sharedStorageVersion}`);\n}\nif (contractErrors.length) {",
)
write("scripts/check-version-consistency.mjs", version_check)

print("FileScope v0.3.4 readiness files applied.")
