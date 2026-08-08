import { describe, expect, it } from 'vitest';
import { renderReportHtml } from './report-export';
import { currentReportSchemaVersion, type AnalysisReport } from './types';

const dangerousPayloads = [
  'FS-XSS-<script>alert("filescope")</script>',
  'FS-IMG-<img src=x onerror="alert(1)">',
  'FS-SVG-</title><svg onload="alert(2)">',
  'FS-ENTITIES-<&>"\'',
  'FS-CLOSE-</style></head><body onload="alert(3)">',
];

describe('HTML-экспорт', () => {
  it.each(dangerousPayloads)('экранирует пользовательский payload %#', (payload) => {
    const html = renderReportHtml(sampleReport(payload), payload);

    expect(html).not.toContain(payload);
    expect(html).not.toMatch(/<script\b/i);
    expect(html).not.toMatch(/<img\b/i);
    expect(html).not.toMatch(/<svg\b/i);
    expect(html).not.toMatch(/<body\s+onload=/i);
    expect(html).toContain('&lt;');
    expect(html).toContain('&gt;');
    expect(html).toContain('не подписан цифровой подписью');
  });
});

function sampleReport(payload: string): AnalysisReport {
  return {
    schemaVersion: currentReportSchemaVersion,
    appVersion: payload,
    analyzerVersion: payload,
    ruleSetVersion: payload,
    createdBy: { platform: payload, architecture: payload, runtime: payload },
    analysisCompleteness: 'complete',
    id: 'export-hardening',
    objectKind: 'file',
    target: payload,
    displayName: payload,
    startedAt: '2026-08-08T00:00:00Z',
    completedAt: '2026-08-08T00:00:01Z',
    durationMs: 1000,
    sha256: payload,
    detectedType: payload,
    sizeBytes: 123,
    riskLevel: 'caution',
    riskScore: 7,
    indicators: [{
      id: 'export.escape',
      title: payload,
      description: payload,
      category: payload,
      severity: 'low',
      score: 7,
      evidence: [payload],
      recommendation: payload,
    }],
    metadata: { payload },
    isDemo: false,
    limitations: [payload],
  };
}
