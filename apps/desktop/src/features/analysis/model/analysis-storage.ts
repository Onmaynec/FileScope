import {
  defaultAnalysisLimits,
  type AnalysisLimits,
  type AnalysisReport,
} from './types';
import type { ReportHistorySnapshot } from './history-repository';
import { createProductionReportHistoryRepository } from './tauri-history-repository';

const LIMITS_KEY = 'filescope:limits:v1';
const LEGACY_LIMIT_KEYS = ['filescope:v0.2.0:limits'];
const LIMITS_MIGRATION_BACKUP_KEY = 'filescope:migration-backup:v0.3.3';
const reportHistoryRepository = createProductionReportHistoryRepository();

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

export function deleteReportHistory(id: string): Promise<ReportHistorySnapshot> {
  return reportHistoryRepository.delete(id);
}

export async function deleteReport(id: string): Promise<AnalysisReport[]> {
  return (await deleteReportHistory(id)).reports;
}

export function clearReportHistory(): Promise<ReportHistorySnapshot> {
  return reportHistoryRepository.clear();
}

export async function clearReports(): Promise<AnalysisReport[]> {
  return (await clearReportHistory()).reports;
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
