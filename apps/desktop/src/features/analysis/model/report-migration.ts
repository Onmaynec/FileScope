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
    archive: migrateArchive(raw.archive),
    isDemo: raw.isDemo === true,
    limitations: Array.isArray(raw.limitations)
      ? raw.limitations.filter((item): item is string => typeof item === 'string')
      : [],
  };
}

function migrateArchive(value: unknown): AnalysisReport['archive'] {
  if (!isObject(value)) return undefined;
  const ratio = optionalNumber(value.compressionRatio);
  return {
    ...value,
    compressionRatio: ratio ?? 0,
    compressionRatioInfinite: value.compressionRatioInfinite === true || value.compressionRatio === null,
  } as unknown as AnalysisReport['archive'];
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
