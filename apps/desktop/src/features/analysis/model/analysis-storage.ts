import { defaultAnalysisLimits, type AnalysisLimits, type AnalysisReport } from './types';

const REPORTS_KEY = 'filescope:v0.2.0:reports';
const LIMITS_KEY = 'filescope:v0.2.0:limits';
const MAX_REPORTS = 250;

export function loadReports(): AnalysisReport[] {
  if (typeof localStorage === 'undefined') return [];
  try {
    const raw = localStorage.getItem(REPORTS_KEY);
    if (!raw) return [];
    const value = JSON.parse(raw) as AnalysisReport[];
    return Array.isArray(value) ? value.filter(isReport).slice(0, MAX_REPORTS) : [];
  } catch {
    return [];
  }
}

export function saveReport(report: AnalysisReport): AnalysisReport[] {
  const next = [report, ...loadReports().filter((item) => item.id !== report.id)].slice(0, MAX_REPORTS);
  if (typeof localStorage !== 'undefined') localStorage.setItem(REPORTS_KEY, JSON.stringify(next));
  return next;
}

export function deleteReport(id: string): AnalysisReport[] {
  const next = loadReports().filter((report) => report.id !== id);
  if (typeof localStorage !== 'undefined') localStorage.setItem(REPORTS_KEY, JSON.stringify(next));
  return next;
}

export function clearReports(): void {
  if (typeof localStorage !== 'undefined') localStorage.removeItem(REPORTS_KEY);
}

export function loadAnalysisLimits(): AnalysisLimits {
  if (typeof localStorage === 'undefined') return defaultAnalysisLimits;
  try {
    const raw = localStorage.getItem(LIMITS_KEY);
    if (!raw) return defaultAnalysisLimits;
    const value = JSON.parse(raw) as Partial<AnalysisLimits>;
    return sanitizeLimits({ ...defaultAnalysisLimits, ...value });
  } catch {
    return defaultAnalysisLimits;
  }
}

export function saveAnalysisLimits(limits: AnalysisLimits): AnalysisLimits {
  const next = sanitizeLimits(limits);
  if (typeof localStorage !== 'undefined') localStorage.setItem(LIMITS_KEY, JSON.stringify(next));
  return next;
}

export function sanitizeLimits(limits: AnalysisLimits): AnalysisLimits {
  return {
    maximumFileSizeBytes: clampNumber(limits.maximumFileSizeBytes, 1 * 1024 * 1024, 4 * 1024 * 1024 * 1024),
    maximumArchiveEntries: Math.round(clampNumber(limits.maximumArchiveEntries, 10, 100_000)),
    maximumArchiveUncompressedBytes: clampNumber(limits.maximumArchiveUncompressedBytes, 10 * 1024 * 1024, 20 * 1024 * 1024 * 1024),
    maximumArchiveDepth: Math.round(clampNumber(limits.maximumArchiveDepth, 1, 64)),
    maximumCompressionRatio: clampNumber(limits.maximumCompressionRatio, 2, 10_000),
    activeUrlTimeoutMs: Math.round(clampNumber(limits.activeUrlTimeoutMs, 1_000, 30_000)),
    activeUrlRedirectLimit: Math.round(clampNumber(limits.activeUrlRedirectLimit, 0, 10)),
  };
}

function isReport(value: AnalysisReport): boolean {
  return Boolean(value && typeof value.id === 'string' && typeof value.completedAt === 'string' && Array.isArray(value.indicators));
}

function clampNumber(value: number, minimum: number, maximum: number): number {
  if (!Number.isFinite(value)) return minimum;
  return Math.min(maximum, Math.max(minimum, value));
}
