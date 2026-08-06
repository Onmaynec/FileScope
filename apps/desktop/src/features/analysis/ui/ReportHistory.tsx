import { useMemo, useState } from 'react';
import { FileJson2, Search, ShieldCheck, Trash2 } from 'lucide-react';
import {
  clearReports,
  deleteReport,
  loadReports,
} from '../model/analysis-storage';
import {
  riskLabels,
  type AnalysisReport,
  type ObjectKind,
  type RiskLevel,
} from '../model/types';
import { ReportView } from './ReportView';

export function ReportHistory() {
  const [reports, setReports] = useState<AnalysisReport[]>(() => loadReports());
  const [query, setQuery] = useState('');
  const [kind, setKind] = useState<'all' | ObjectKind>('all');
  const [risk, setRisk] = useState<'all' | RiskLevel>('all');
  const [selected, setSelected] = useState<AnalysisReport | null>(null);
  const [clearConfirmationOpen, setClearConfirmationOpen] = useState(false);

  const filtered = useMemo(
    () =>
      reports.filter((report) => {
        const matchesQuery =
          `${report.displayName} ${report.target} ${report.sha256 ?? ''}`
            .toLowerCase()
            .includes(query.toLowerCase());

        const matchesKind =
          kind === 'all' || report.objectKind === kind;

        const matchesRisk =
          risk === 'all' || report.riskLevel === risk;

        return matchesQuery && matchesKind && matchesRisk;
      }),
    [reports, query, kind, risk],
  );

  const remove = (id: string) => {
    const nextReports = deleteReport(id);

    setReports(nextReports);

    if (selected?.id === id) {
      setSelected(null);
    }
  };

  const clearHistory = () => {
    clearReports();
    setReports([]);
    setSelected(null);
    setClearConfirmationOpen(false);
  };

  if (selected) {
    return (
      <div className="analysis-history">
        <button
          type="button"
          className="text-button"
          onClick={() => setSelected(null)}
        >
          ← Вернуться к истории
        </button>

        <ReportView report={selected} />
      </div>
    );
  }

  return (
    <div className="analysis-history">
      <section className="analysis-history__toolbar card">
        <div className="analysis-search">
          <Search />

          <input
            className="input"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Поиск по имени, пути или SHA-256"
            aria-label="Поиск по истории отчётов"
          />
        </div>

        <select
          className="input compact"
          value={kind}
          onChange={(event) =>
            setKind(event.target.value as 'all' | ObjectKind)
          }
          aria-label="Фильтр по типу объекта"
        >
          <option value="all">Все объекты</option>
          <option value="file">Файлы</option>
          <option value="url">URL</option>
          <option value="archive">Архивы</option>
        </select>

        <select
          className="input compact"
          value={risk}
          onChange={(event) =>
            setRisk(event.target.value as 'all' | RiskLevel)
          }
          aria-label="Фильтр по уровню риска"
        >
          <option value="all">Все уровни риска</option>
          <option value="noThreatsFound">
            Без обнаруженных признаков
          </option>
          <option value="caution">Требует внимания</option>
          <option value="highRisk">Высокий риск</option>
          <option value="dangerous">Опасный объект</option>
        </select>

        {reports.length > 0 && (
          <button
            type="button"
            className="button button-secondary analysis-history__clear"
            onClick={() => setClearConfirmationOpen(true)}
          >
            <Trash2 />
            Очистить историю
          </button>
        )}
      </section>

      {clearConfirmationOpen && (
        <section
          className="analysis-history__confirmation card"
          aria-labelledby="clear-history-title"
          aria-describedby="clear-history-description"
        >
          <div className="analysis-history__confirmation-content">
            <strong id="clear-history-title">
              Очистить всю историю?
            </strong>

            <p id="clear-history-description">
              Будут безвозвратно удалены все локально сохранённые отчёты.
              Это действие нельзя отменить.
            </p>
          </div>

          <div className="analysis-history__confirmation-actions">
            <button
              type="button"
              className="button button-secondary"
              onClick={() => setClearConfirmationOpen(false)}
            >
              Отмена
            </button>

            <button
              type="button"
              className="button button-secondary danger"
              onClick={clearHistory}
            >
              <Trash2 />
              Очистить историю
            </button>
          </div>
        </section>
      )}

      {filtered.length === 0 ? (
        <section className="card empty analysis-history__empty">
          <FileJson2 size={42} />

          <h2>
            {reports.length === 0
              ? 'Отчётов пока нет'
              : 'Ничего не найдено'}
          </h2>

          <p>
            {reports.length === 0
              ? 'Выполните локальную проверку файла, URL или ZIP-архива. Результаты сохраняются только на этом устройстве.'
              : 'Попробуйте изменить поисковый запрос или выбранные фильтры.'}
          </p>
        </section>
      ) : (
        <section className="analysis-report-grid">
          {filtered.map((report) => (
            <article
              className={`analysis-report-card risk-${report.riskLevel}`}
              key={report.id}
            >
              <button
                type="button"
                className="analysis-report-card__body"
                onClick={() => setSelected(report)}
              >
                <div className="analysis-report-card__icon">
                  <ShieldCheck />
                </div>

                <div>
                  <strong>{report.displayName}</strong>

                  <span>
                    {report.detectedType ?? report.objectKind} ·{' '}
                    {new Date(report.completedAt).toLocaleString('ru-RU')}
                  </span>

                  <b>
                    {riskLabels[report.riskLevel]} · {report.riskScore}/100
                  </b>
                </div>
              </button>

              <button
                type="button"
                className="icon-button danger"
                onClick={() => remove(report.id)}
                aria-label={`Удалить отчёт «${report.displayName}»`}
              >
                <Trash2 />
              </button>
            </article>
          ))}
        </section>
      )}
    </div>
  );
}