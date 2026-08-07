export type ObjectKind = 'file' | 'url' | 'archive';
export type RiskLevel = 'noThreatsFound' | 'caution' | 'highRisk' | 'dangerous';
export type IndicatorSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export type AnalysisCompleteness = 'complete' | 'partial' | 'stoppedByLimit' | 'failed';
export type AnalysisFailureCode =
  | 'cancelled'
  | 'timeout'
  | 'readLimit'
  | 'memoryLimit'
  | 'entryLimit'
  | 'fileChanged'
  | 'unsupportedObject'
  | 'securityBlocked'
  | 'invalidInput'
  | 'io'
  | 'parse'
  | 'network'
  | 'internal';

export interface AnalysisCommandError {
  code: AnalysisFailureCode;
  message: string;
}

export interface CreatedBy {
  platform: string;
  architecture: string;
  runtime: string;
}

export interface ThreatIndicator {
  id: string;
  title: string;
  description: string;
  category: string;
  severity: IndicatorSeverity;
  score: number;
  evidence: string[];
  recommendation: string;
}

export interface PeSection {
  name: string;
  virtualSize: number;
  rawSize: number;
  entropy: number;
}

export interface PeAnalysis {
  architecture: string;
  entryPoint: number;
  sections: PeSection[];
  imports: string[];
  suspiciousImports: string[];
  signaturePresent: boolean;
}

export interface UrlAnalysis {
  normalizedUrl: string;
  scheme: string;
  host: string;
  asciiHost: string;
  unicodeHost: string;
  registrableDomain?: string;
  port?: number;
  path: string;
  queryParameters: number;
  containsPunycode: boolean;
  hostIsIp: boolean;
  hasCredentials: boolean;
  subdomainCount: number;
  redirectParameters: string[];
  resolvedAddresses: string[];
  finalUrl?: string;
  statusCode?: number;
  responseHeaders: [string, string][];
  redirectCount?: number;
  activeCheckPerformed: boolean;
}

export interface ArchiveEntry {
  path: string;
  compressedSize: number;
  uncompressedSize: number;
  depth: number;
  isDirectory: boolean;
  isExecutable: boolean;
  isArchive: boolean;
  suspiciousPath: boolean;
}

export interface ArchiveAnalysis {
  format: string;
  entries: ArchiveEntry[];
  totalEntries: number;
  totalCompressedSize: number;
  totalUncompressedSize: number;
  maximumDepth: number;
  compressionRatio: number;
  compressionRatioInfinite?: boolean;
  nestedArchives: number;
  executableEntries: number;
  suspiciousPaths: number;
}

export interface AnalysisReport {
  schemaVersion: number;
  appVersion: string;
  analyzerVersion: string;
  ruleSetVersion: string;
  createdBy: CreatedBy;
  analysisCompleteness: AnalysisCompleteness;
  id: string;
  objectKind: ObjectKind;
  target: string;
  displayName: string;
  startedAt: string;
  completedAt: string;
  durationMs: number;
  sha256?: string;
  detectedType?: string;
  sizeBytes?: number;
  riskLevel: RiskLevel;
  riskScore: number;
  indicators: ThreatIndicator[];
  metadata: Record<string, unknown>;
  pe?: PeAnalysis;
  url?: UrlAnalysis;
  archive?: ArchiveAnalysis;
  isDemo: boolean;
  limitations: string[];
}

export interface AnalysisLimits {
  maximumFileSizeBytes: number;
  maximumReadBytes: number;
  maximumParserMemoryBytes: number;
  jobTimeoutMs: number;
  maximumArchiveEntries: number;
  maximumArchiveUncompressedBytes: number;
  maximumArchiveDepth: number;
  maximumCompressionRatio: number;
  activeUrlTimeoutMs: number;
  activeUrlRedirectLimit: number;
}

export const currentReportSchemaVersion = 1;

export const defaultAnalysisLimits: AnalysisLimits = {
  maximumFileSizeBytes: 512 * 1024 * 1024,
  maximumReadBytes: 512 * 1024 * 1024,
  maximumParserMemoryBytes: 128 * 1024 * 1024,
  jobTimeoutMs: 120_000,
  maximumArchiveEntries: 10_000,
  maximumArchiveUncompressedBytes: 2 * 1024 * 1024 * 1024,
  maximumArchiveDepth: 12,
  maximumCompressionRatio: 150,
  activeUrlTimeoutMs: 8_000,
  activeUrlRedirectLimit: 5,
};

export const riskLabels: Record<RiskLevel, string> = {
  noThreatsFound: 'Признаков угроз не найдено',
  caution: 'Требует внимания',
  highRisk: 'Высокий риск',
  dangerous: 'Опасный объект',
};

export const severityLabels: Record<IndicatorSeverity, string> = {
  info: 'Информация',
  low: 'Низкая',
  medium: 'Средняя',
  high: 'Высокая',
  critical: 'Критическая',
};
