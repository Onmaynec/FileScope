import { riskLabels, severityLabels, type AnalysisReport } from './types';

interface ReportExportEnvelope {
  export: {
    formatVersion: 1;
    generatedAt: string;
    reportPayloadSha256: string;
    signed: false;
    signatureNote: string;
  };
  report: AnalysisReport;
}

export async function downloadReport(report: AnalysisReport, format: 'json' | 'html'): Promise<void> {
  const payload = JSON.stringify(report, null, 2);
  const checksum = await sha256Text(payload);
  const envelope: ReportExportEnvelope = {
    export: {
      formatVersion: 1,
      generatedAt: new Date().toISOString(),
      reportPayloadSha256: checksum,
      signed: false,
      signatureNote: 'Экспорт содержит SHA-256 payload, но не подписан цифровой подписью FileScope.',
    },
    report,
  };
  const content = format === 'json'
    ? JSON.stringify(envelope, null, 2)
    : renderReportHtml(report, checksum);
  const mime = format === 'json' ? 'application/json;charset=utf-8' : 'text/html;charset=utf-8';
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = `FileScope-${safeFileName(report.displayName)}-${report.id.slice(0, 8)}.${format}`;
  anchor.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 1_000);
}

export function renderReportHtml(report: AnalysisReport, payloadChecksum = 'не рассчитан'): string {
  const indicatorRows = report.indicators.length
    ? report.indicators.map((item) => `<article class="indicator"><h3>${escapeHtml(item.title)}</h3><p><strong>${escapeHtml(severityLabels[item.severity])}</strong> · ${escapeHtml(item.category)} · +${item.score}</p><p>${escapeHtml(item.description)}</p>${item.evidence.length ? `<ul>${item.evidence.map((value) => `<li>${escapeHtml(value)}</li>`).join('')}</ul>` : ''}<p><strong>Рекомендация:</strong> ${escapeHtml(item.recommendation)}</p></article>`).join('')
    : '<p>Признаки, повышающие риск, не обнаружены.</p>';
  return `<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>FileScope — ${escapeHtml(report.displayName)}</title><style>body{font-family:Segoe UI,Arial,sans-serif;max-width:920px;margin:40px auto;padding:0 24px;color:#111827;line-height:1.55}header{padding:24px;border:1px solid #dbe2ea;border-radius:16px;background:#f8fafc}dl{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}dl div,.indicator{padding:16px;border:1px solid #e5e7eb;border-radius:12px}dt{color:#64748b;font-size:13px}dd{margin:4px 0 0;overflow-wrap:anywhere}.indicator{margin:12px 0}.mono{font-family:Consolas,monospace;overflow-wrap:anywhere}.warning{padding:16px;background:#fff7ed;border-radius:12px}.integrity{padding:16px;background:#eff6ff;border:1px solid #bfdbfe;border-radius:12px}@media(max-width:640px){dl{grid-template-columns:1fr}}</style></head><body><header><h1>FileScope v${escapeHtml(report.appVersion)}</h1><h2>${escapeHtml(report.displayName)}</h2><p><strong>${escapeHtml(riskLabels[report.riskLevel])}</strong> · ${report.riskScore}/100</p></header><h2>Версии и целостность</h2><div class="integrity"><p><strong>Schema:</strong> ${report.schemaVersion} · <strong>Analyzer:</strong> ${escapeHtml(report.analyzerVersion)} · <strong>Rules:</strong> ${escapeHtml(report.ruleSetVersion)}</p><p><strong>SHA-256 JSON payload:</strong> <span class="mono">${escapeHtml(payloadChecksum)}</span></p><p>Этот HTML-экспорт не подписан цифровой подписью. Checksum позволяет проверить неизменность JSON payload отчёта.</p></div><h2>Сводка</h2><dl><div><dt>Тип объекта</dt><dd>${escapeHtml(report.objectKind)}</dd></div><div><dt>Формат</dt><dd>${escapeHtml(report.detectedType ?? 'Не определён')}</dd></div><div><dt>Полнота</dt><dd>${escapeHtml(report.analysisCompleteness)}</dd></div><div><dt>Дата</dt><dd>${escapeHtml(new Date(report.completedAt).toLocaleString('ru-RU'))}</dd></div><div><dt>Длительность</dt><dd>${report.durationMs} мс</dd></div><div><dt>Размер</dt><dd>${report.sizeBytes ?? '—'}</dd></div><div><dt>SHA-256 объекта</dt><dd class="mono">${escapeHtml(report.sha256 ?? '—')}</dd></div><div><dt>Создано</dt><dd>${escapeHtml(report.createdBy.platform)} · ${escapeHtml(report.createdBy.architecture)}</dd></div></dl><h2>Обнаруженные признаки</h2>${indicatorRows}<h2>Ограничения</h2><div class="warning"><ul>${report.limitations.map((item) => `<li>${escapeHtml(item)}</li>`).join('')}</ul></div><h2>Технические данные</h2><pre>${escapeHtml(JSON.stringify(report, null, 2))}</pre></body></html>`;
}

async function sha256Text(value: string): Promise<string> {
  if (typeof crypto === 'undefined' || !crypto.subtle) return 'недоступен в текущем runtime';
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function safeFileName(value: string): string {
  return value.replace(/[\\/:*?"<>|]/g, '_').slice(0, 80) || 'report';
}

function escapeHtml(value: string): string {
  const entities: Record<string, string> = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    "'": '&#39;',
    '"': '&quot;',
  };
  return value.replace(/[&<>'"]/g, (character) => entities[character] ?? character);
}
