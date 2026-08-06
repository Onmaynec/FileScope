import { APP_VERSION } from '../../../shared/config/app-version';
import {
  currentReportSchemaVersion,
  defaultAnalysisLimits,
  type AnalysisLimits,
  type AnalysisReport,
  type ObjectKind,
  type RiskLevel,
} from './types';

const REPORTS_KEY = `filescope:reports:schema-${currentReportSchemaVersion}`;
const LIMITS_KEY = 'filescope:limits:v1';
const LEGACY_REPORT_KEYS = ['filescope:v0.2.0:reports'];
const LEGACY_LIMIT_KEYS = ['filescope:v0.2.0:limits'];
const MIGRATION_BACKUP_KEY = 'filescope:migration-backup:v0.3.3';
const MAX_REPORTS = 250;

export function loadReports(): AnalysisReport[] {
  if (typeof localStorage === 'undefined') return [];
  const source = localStorage.getItem(REPORTS_KEY);
  if (source) return parseAndMigrateReports(source, REPORTS_KEY);

  for (const key of LEGACY_REPORT_KEYS) {
    const raw = localStorage.getItem(key);
    if (!raw) continue;
    backupBeforeMigration(key, raw);
    const migrated = parseAndMigrateReports(raw, key);
    localStorage.setItem(REPORTS_KEY, JSON.stringify(migrated));
    return migrated;
  }
  return [];
}

export function saveReport(report: AnalysisReport): AnalysisReport[] {
  const normalized = migrateReport(report);
  const next = [normalized, ...loadReports().filter((item) => item.id !== normalized.id)].slice(0, MAX_REPORTS);
  if (typeof localStorage !== 'undefined') localStorage.setItem(REPORTS_KEY, JSON.stringify(next));
  return next;
}

export function deleteReport(id: string): AnalysisReport[] {
  const next = loadReports().filter((report) => report.id !== id);
  if (typeof localStorage !== 'undefined') localStorage.setItem(REPORTS_KEY, JSON.stringify(next));
  return next;
}

export function clearReports(): AnalysisReport[] {
  if (typeof localStorage !== 'undefined') {
    localStorage.removeItem(REPORTS_KEY);
    for (const key of LEGACY_REPORT_KEYS) localStorage.removeItem(key);
  }
  return [];
}

export function loadAnalysisLimits(): AnalysisLimits {
  if (typeof localStorage === 'undefined') return defaultAnalysisLimits;
  const current = localStorage.getItem(LIMITS_KEY);
  if (current) return parseLimits(current);
  for (const key of LEGACY_LIMIT_KEYS) {
    const raw = localStorage.getItem(key);
    if (!raw) continue;
    backupBeforeMigration(key, raw);
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
    limitations: Array.isArray(raw.limitations) ? raw.limitations.filter((item): item is string => typeof item === 'string') : [],
  };
}

function parseAndMigrateReports(raw: string, sourceKey: string): AnalysisReport[] {
  try {
    const value = JSON.parse(raw) as unknown;
    if (!Array.isArray(value)) {
      backupBeforeMigration(sourceKey, raw);
      return [];
    }
    const migrated = value.slice(0, MAX_REPORTS).map(migrateReport);
    if (sourceKey === REPORTS_KEY && JSON.stringify(value) !== JSON.stringify(migrated)) {
      backupBeforeMigration(sourceKey, raw);
      localStorage.setItem(REPORTS_KEY, JSON.stringify(migrated));
    }
    return migrated;
  } catch {
    backupBeforeMigration(sourceKey, raw);
    return [];
  }
}

function parseLimits(raw: string): AnalysisLimits {
  try {
    const value = JSON.parse(raw) as Partial<AnalysisLimits>;
    return sanitizeLimits({ ...defaultAnalysisLimits, ...value });
  } catch {
    return defaultAnalysisLimits;
  }
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

function backupBeforeMigration(sourceKey: string, raw: string): void {
  if (typeof localStorage === 'undefined') return;
  try {
    const existing = localStorage.getItem(MIGRATION_BACKUP_KEY);
    const backups = existing ? JSON.parse(existing) as Record<string, string> : {};
    if (!(sourceKey in backups)) {
      backups[sourceKey] = raw;
      localStorage.setItem(MIGRATION_BACKUP_KEY, JSON.stringify(backups));
    }
  } catch {
    // Ошибка резервной записи не должна удалять исходный ключ.
  }
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

function clampNumber(value: number, minimum: number, maximum: number): number {
  if (!Number.isFinite(value)) return minimum;
  return Math.min(maximum, Math.max(minimum, value));
}

function migrationId(): string {
  if (typeof crypto !== 'undefined' && 'randomUUID' in crypto) return crypto.randomUUID();
  return `migrated-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}
