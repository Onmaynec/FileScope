import { AlertTriangle, Archive, CheckCircle2, Copy, Download, FileCode2, Globe2, ShieldAlert } from 'lucide-react';
import { downloadReport } from '../model/report-export';
import { riskLabels, severityLabels, type AnalysisReport } from '../model/types';

interface ReportViewProps {
  report: AnalysisReport;
  compact?: boolean;
}

export function ReportView({ report, compact = false }: ReportViewProps) {
  const incompleteWithoutThreats = report.analysisCompleteness !== 'complete' && report.riskLevel === 'noThreatsFound';
  const RiskIcon = incompleteWithoutThreats
    ? AlertTriangle
    : report.riskLevel === 'noThreatsFound'
      ? CheckCircle2
      : report.riskLevel === 'caution'
        ? AlertTriangle
        : ShieldAlert;
  const partialReason = getPartialReason(report);
  const copySummary = () => navigator.clipboard?.writeText(buildShortSummary(report));

  return (
    <section className={`analysis-report risk-${report.riskLevel} ${compact ? 'analysis-report--compact' : ''}`} aria-label="Результат анализа">
      <header className="analysis-report__header">
        <span className="analysis-report__risk-icon"><RiskIcon /></span>
        <div>
          <span className="analysis-kicker">FileScope {report.appVersion} · schema {report.schemaVersion}</span>
          <h2>{displayVerdictLabel(report)}</h2>
          <p>{report.displayName} · оценка {report.riskScore}/100 · {report.durationMs} мс</p>
        </div>
        <div className="analysis-report__actions">
          <button className="button button-secondary" onClick={() => void copySummary()}><Copy />Кратко</button>
          <button className="button button-secondary" onClick={() => void downloadReport(report, 'json')}><Download />JSON</button>
          <button className="button button-secondary" onClick={() => void downloadReport(report, 'html')}><Download />HTML</button>
        </div>
      </header>

      <dl className="metadata-grid analysis-report__metadata">
        <div><dt>Тип объекта</dt><dd>{objectKindLabel(report.objectKind)}</dd></div>
        <div><dt>Фактический формат</dt><dd>{report.detectedType ?? 'Не определён'}</dd></div>
        <div><dt>Размер</dt><dd>{report.sizeBytes === undefined ? '—' : formatBytes(report.sizeBytes)}</dd></div>
        <div><dt>Полнота</dt><dd>{completenessLabel(report.analysisCompleteness)}</dd></div>
        <div><dt>Analyzer</dt><dd>{report.analyzerVersion}</dd></div>
        <div><dt>Rule set</dt><dd>{report.ruleSetVersion}</dd></div>
        <div><dt>Среда</dt><dd>{report.createdBy.platform} · {report.createdBy.architecture}</dd></div>
        <div><dt>Завершено</dt><dd>{new Date(report.completedAt).toLocaleString('ru-RU')}</dd></div>
      </dl>

      {partialReason && <div className="status-banner warning" role="status"><AlertTriangle /><div><strong>Анализ выполнен частично</strong><span>{partialReason}</span></div></div>}

      {report.sha256 && <div className="analysis-hash"><span><strong>SHA-256 объекта</strong><code>{report.sha256}</code></span><button className="icon-button" title="Копировать SHA-256" onClick={() => void navigator.clipboard?.writeText(report.sha256 ?? '')}><Copy /></button></div>}

      <section className="analysis-section">
        <div className="card-title-row"><div><h3>Обнаруженные признаки</h3><p>{report.indicators.length ? `Найдено: ${report.indicators.length}` : 'Признаки, повышающие риск, не обнаружены.'}</p></div></div>
        <div className="analysis-indicators">
          {report.indicators.map((indicator) => (
            <article className={`analysis-indicator severity-${indicator.severity}`} key={`${indicator.id}-${indicator.evidence.join('|')}`}>
              <div className="analysis-indicator__top"><span className="analysis-indicator__icon"><AlertTriangle /></span><div><strong>{indicator.title}</strong><span>{severityLabels[indicator.severity]} · {indicator.category}{indicator.score > 0 ? ` · +${indicator.score}` : ' · без изменения Risk Score'}</span></div></div>
              <p>{indicator.description}</p>
              {indicator.evidence.length > 0 && <ul>{indicator.evidence.map((value) => <li key={value}>{value}</li>)}</ul>}
              <div className="analysis-recommendation"><strong>Рекомендация</strong><span>{indicator.recommendation}</span></div>
            </article>
          ))}
        </div>
      </section>

      {report.url && <section className="analysis-section"><h3><Globe2 />URL</h3><dl className="metadata-grid"><div><dt>Нормализованный адрес</dt><dd>{report.url.normalizedUrl}</dd></div><div><dt>ASCII-домен</dt><dd>{report.url.asciiHost}</dd></div><div><dt>Unicode-домен</dt><dd>{report.url.unicodeHost}</dd></div><div><dt>Registrable domain (приближённо)</dt><dd>{report.url.registrableDomain ?? 'Не определён'}</dd></div><div><dt>Схема и порт</dt><dd>{report.url.scheme.toUpperCase()} · {report.url.port ?? 'по умолчанию'}</dd></div><div><dt>Сетевой запрос</dt><dd>{report.url.activeCheckPerformed ? 'Выполнен вручную с SSRF-защитой' : 'Не выполнялся'}</dd></div>{report.url.finalUrl && <div><dt>Итоговый URL</dt><dd>{report.url.finalUrl}</dd></div>}{report.url.statusCode !== undefined && <div><dt>HTTP-статус</dt><dd>{report.url.statusCode}</dd></div>}{report.url.resolvedAddresses.length > 0 && <div><dt>Разрешённые IP</dt><dd>{report.url.resolvedAddresses.join(', ')}</dd></div>}</dl></section>}

      {report.pe && <section className="analysis-section"><h3><FileCode2 />Windows PE</h3><dl className="metadata-grid"><div><dt>Архитектура</dt><dd>{report.pe.architecture}</dd></div><div><dt>Точка входа</dt><dd>0x{report.pe.entryPoint.toString(16)}</dd></div><div><dt>Authenticode</dt><dd>{report.pe.signaturePresent ? 'Таблица сертификатов присутствует; доверие издателя не проверялось' : 'Таблица сертификатов не обнаружена'}</dd></div><div><dt>Импорты</dt><dd>{report.pe.imports.length}</dd></div></dl><div className="analysis-table"><div className="analysis-table__head"><span>Секция</span><span>Virtual</span><span>Raw</span><span>Энтропия</span></div>{report.pe.sections.map((section) => <div className="analysis-table__row" key={section.name}><span>{section.name}</span><span>{formatBytes(section.virtualSize)}</span><span>{formatBytes(section.rawSize)}</span><span>{section.entropy.toFixed(2)}</span></div>)}</div></section>}

      {report.archive && <section className="analysis-section"><h3><Archive />ZIP-архив</h3><dl className="metadata-grid"><div><dt>Элементов</dt><dd>{archiveEntriesLabel(report)}</dd></div><div><dt>Структурная сводка</dt><dd>{archiveSummaryLabel(report)}</dd></div><div><dt>После распаковки</dt><dd>{formatBytes(report.archive.totalUncompressedSize)}</dd></div><div><dt>Коэффициент сжатия</dt><dd>{formatCompressionRatio(report)}</dd></div><div><dt>Максимальная глубина</dt><dd>{report.archive.maximumDepth}</dd></div><div><dt>Исполняемых файлов</dt><dd>{report.archive.executableEntries}</dd></div><div><dt>Вложенных архивов</dt><dd>{report.archive.nestedArchives}</dd></div><div><dt>Зашифрованных</dt><dd>{report.archive.encryptedEntries ?? 0}</dd></div><div><dt>Непрочитанных записей</dt><dd>{report.archive.unreadableEntries ?? 0}</dd></div><div><dt>Symlink</dt><dd>{report.archive.symlinkEntries ?? 0}</dd></div><div><dt>ADS semantics</dt><dd>{report.archive.adsEntries ?? 0}</dd></div><div><dt>Нормализовано имён</dt><dd>{report.archive.normalizationChangedEntries ?? 0}</dd></div><div><dt>Записей в Windows-коллизиях</dt><dd>{report.archive.pathCollisions ?? 0}</dd></div><div><dt>Записей в файл/каталог коллизиях</dt><dd>{report.archive.fileDirectoryCollisions ?? 0}</dd></div></dl><div className="archive-entry-list">{report.archive.entries.slice(0, compact ? 20 : 200).map((entry, index) => { const labels = archiveEntryLabels(entry); const warning = entry.suspiciousPath || entry.isExecutable || labels.length > 0; const sourcePath = entry.displayPath || entry.path; const normalizedSuffix = entry.pathNormalizationChanged && sourcePath !== entry.path ? ` · нормализовано: ${entry.path}` : ''; return <div className={`archive-entry ${warning ? 'archive-entry--warning' : ''}`} key={`${index}-${entry.path}-${entry.uncompressedSize}`}><span>{sourcePath}</span><small>{entry.isDirectory ? 'Папка' : formatBytes(entry.uncompressedSize)}{labels.length > 0 ? ` · ${labels.join(' · ')}` : ''}{normalizedSuffix}</small></div>; })}</div>{report.archive.entries.length > (compact ? 20 : 200) && <p className="helper-text">Показана только часть дерева. Полный список просмотренных записей, исходные bytes имени (`rawNameHex`) и нормализованные пути доступны в JSON-экспорте.</p>}{report.archive.summaryComplete === false && <p className="helper-text">Сводные размеры и счётчики относятся только к успешно просмотренной части архива; непрочитанные или не просмотренные записи не включены.</p>}</section>}

      <section className="analysis-section analysis-limitations"><h3>Ограничения результата</h3><ul>{report.limitations.map((limitation) => <li key={limitation}>{limitation}</li>)}</ul></section>
    </section>
  );
}

function displayVerdictLabel(report: AnalysisReport): string {
  if (report.analysisCompleteness !== 'complete' && report.riskLevel === 'noThreatsFound') {
    return 'Недостаточно данных для полного вердикта';
  }
  return riskLabels[report.riskLevel];
}

function formatCompressionRatio(report: AnalysisReport): string {
  const archive = report.archive;
  if (!archive) return '—';
  if (archive.compressionRatioInfinite === true) return '∞';
  return Number.isFinite(archive.compressionRatio) ? `${archive.compressionRatio.toFixed(1)}x` : 'Не определён';
}

function archiveEntriesLabel(report: AnalysisReport): string {
  const archive = report.archive;
  if (!archive) return '—';
  if (archive.entriesScanned === undefined || archive.entriesScanned === archive.totalEntries) return `${archive.totalEntries}`;
  return `${archive.totalEntries} · просмотрено ${archive.entriesScanned}`;
}

function archiveSummaryLabel(report: AnalysisReport): string {
  const archive = report.archive;
  if (!archive) return '—';
  if (archive.summaryComplete === true) return 'Полная central-directory сводка';
  if ((archive.unreadableEntries ?? 0) > 0) return 'Частичная — metadata части записей повреждена';
  if (archive.summaryComplete === false) return 'Частичная — достигнут защитный лимит';
  return 'Legacy-отчёт · статус неизвестен';
}

function archiveEntryLabels(entry: NonNullable<AnalysisReport['archive']>['entries'][number]): string[] {
  const labels: string[] = [];
  if (entry.isExecutable) labels.push('исполняемый');
  if (entry.isArchive) labels.push('архив');
  if (entry.isEncrypted) labels.push('зашифрован');
  if (entry.isSymlink) labels.push('symlink');
  if (entry.isSpecial) labels.push('special entry');
  if (entry.hasAds) labels.push('ADS');
  if (entry.hasReservedName) labels.push('reserved name');
  if (entry.hasTrailingDotOrSpace) labels.push('trailing dot/space');
  if (entry.hasControlOrBidi) labels.push('control/bidi');
  if (entry.pathNormalizationChanged) labels.push('нормализован');
  if (entry.pathCollision) labels.push('Windows-коллизия');
  if (entry.fileDirectoryCollision) labels.push('файл/каталог');
  return labels;
}

function buildShortSummary(report: AnalysisReport): string {
  const lines = [
    `FileScope ${report.appVersion}: ${displayVerdictLabel(report)}`,
    `Schema: ${report.schemaVersion}; Analyzer: ${report.analyzerVersion}; Rules: ${report.ruleSetVersion}`,
    `Объект: ${report.displayName}`,
    `Оценка: ${report.riskScore}/100`,
    `Формат: ${report.detectedType ?? 'не определён'}`,
    `Полнота: ${completenessLabel(report.analysisCompleteness)}`,
  ];
  if (report.sha256) lines.push(`SHA-256: ${report.sha256}`);
  if (report.archive) lines.push(`ZIP: ${archiveEntriesLabel(report)}; сводка: ${archiveSummaryLabel(report)}`);
  lines.push(`Признаков: ${report.indicators.length}`);
  const partialReason = getPartialReason(report);
  if (partialReason) lines.push(`Ограничение: ${partialReason}`);
  return lines.join('\n');
}

function getPartialReason(report: AnalysisReport): string {
  if (report.analysisCompleteness === 'complete') return '';
  if (report.analysisCompleteness === 'stoppedByLimit') return 'Проверка остановлена защитным лимитом; объект разобран не полностью. Техническая остановка сама по себе не повышает оценку угрозы.';
  if ((report.archive?.unreadableEntries ?? 0) > 0) return 'Не удалось структурно прочитать metadata части ZIP-записей; отчёт сохранён для доступной части архива. Техническая неполнота сама по себе не повышает оценку угрозы.';
  if (report.detectedType === 'RAR archive') return 'RAR распознан по сигнатуре, но содержимое архива структурно не разбирается.';
  if (report.detectedType === '7-Zip archive') return '7Z распознан по сигнатуре, но содержимое архива структурно не разбирается.';
  if (report.indicators.some((indicator) => indicator.id === 'pe.parse.failed')) return 'PE-структура повреждена или нестандартна и разобрана не полностью.';
  if (report.analysisCompleteness === 'failed') return 'Отчёт открыт в безопасном режиме совместимости и не является новым verdict.';
  return 'Часть анализаторов или данных была недоступна; учитывайте ограничения отчёта.';
}

function completenessLabel(value: AnalysisReport['analysisCompleteness']): string {
  if (value === 'complete') return 'Полный';
  if (value === 'partial') return 'Частичный';
  if (value === 'stoppedByLimit') return 'Остановлен лимитом';
  return 'Ошибка/совместимость';
}

function objectKindLabel(kind: AnalysisReport['objectKind']): string {
  return kind === 'file' ? 'Файл' : kind === 'archive' ? 'Архив' : 'URL';
}

export function formatBytes(value: number): string {
  if (!Number.isFinite(value)) return '—';
  if (value < 1024) return `${value} Б`;
  const units = ['КБ', 'МБ', 'ГБ', 'ТБ'];
  let size = value;
  let index = -1;
  do { size /= 1024; index += 1; } while (size >= 1024 && index < units.length - 1);
  return `${size.toLocaleString('ru-RU', { maximumFractionDigits: 2 })} ${units[index]}`;
}
