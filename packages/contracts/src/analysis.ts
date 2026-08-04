export type ScanObjectKind = 'file' | 'url' | 'archive' | 'program' | 'browserExtension';
export type RiskLevel = 'noThreatsFound' | 'caution' | 'highRisk' | 'dangerous';

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

export interface ScanResult {
  id: string;
  objectId: string;
  status: 'ready' | 'unavailable' | 'failed';
  riskLevel: RiskLevel;
  summary: string;
  recommendation: string;
  createdAt: string;
  indicators: ThreatIndicator[];
  metadata: Record<string, string>;
  networkEvents: unknown[];
  behaviors: unknown[];
  technicalDetails: Record<string, unknown>;
  isDemo: boolean;
}

export interface IFileAnalysisService {
  requestAnalysis(object: ScanObject): Promise<ScanResult>;
}

export interface IUrlAnalysisService {
  requestPassiveAnalysis(url: string): Promise<ScanResult>;
}
