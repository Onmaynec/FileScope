export type ScanObjectKind = 'file' | 'url' | 'archive' | 'program' | 'browserExtension';
export type RiskLevel = 'noThreatsFound' | 'caution' | 'highRisk' | 'dangerous';
export type AnalysisCompleteness = 'complete' | 'partial' | 'stoppedByLimit' | 'failed';

export const FILESCOPE_REPORT_SCHEMA_VERSION = 1;
export const FILESCOPE_HISTORY_STORAGE_VERSION = 2;

export type HistoryStorageStatus = 'ready' | 'empty' | 'corrupted' | 'unsupported' | 'tooLarge' | 'unavailable';

export interface ReportHistoryEnvelope<TReport> {
  storageVersion: number;
  reportSchemaVersion: number;
  savedAt: string;
  reports: TReport[];
}

export interface ReportVersionMetadata {
  schemaVersion: number;
  appVersion: string;
  analyzerVersion: string;
  ruleSetVersion: string;
  createdBy: {
    platform: string;
    architecture: string;
    runtime: string;
  };
  analysisCompleteness: AnalysisCompleteness;
}

export interface ScanObject {
  id: string;
  kind: ScanObjectKind;
  displayName: string;
  path?: string;
  url?: string;
  size?: number;
  extension?: string;
  createdAt?: string;
  modifiedAt?: string;
  isDemo: boolean;
}

export interface ThreatIndicator {
  id: string;
  category: string;
  severity: RiskLevel;
  title: string;
  description: string;
  evidence?: string;
  ruleId?: string;
  confidenceType: 'heuristic' | 'signature' | 'reputation' | 'behavior';
  isHeuristic: boolean;
}

export interface ScanResult extends ReportVersionMetadata {
  id: string;
  objectId: string;
  status: 'ready' | 'unavailable' | 'failed';
  riskLevel: RiskLevel;
  riskScore: number;
  summary: string;
  recommendation: string;
  createdAt: string;
  indicators: ThreatIndicator[];
  metadata: Record<string, unknown>;
  networkEvents: unknown[];
  behaviors: unknown[];
  technicalDetails: Record<string, unknown>;
  isDemo: boolean;
  limitations: string[];
}

export interface IFileAnalysisService {
  requestAnalysis(object: ScanObject, jobId: string): Promise<ScanResult>;
  cancel(jobId: string): Promise<boolean>;
}

export interface IUrlAnalysisService {
  requestPassiveAnalysis(url: string, jobId: string): Promise<ScanResult>;
  requestActiveAnalysis(url: string, jobId: string): Promise<ScanResult>;
  cancel(jobId: string): Promise<boolean>;
}
