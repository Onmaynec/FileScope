import { useEffect, useState } from 'react';
import { Database, ShieldAlert, Trash2 } from 'lucide-react';

import type { HistoryRetention } from '../../../shared/services/settings-service';
import { useAppPreferences } from '../../../shared/hooks/use-app-preferences';
import { Select } from '../../../shared/ui/Select';
import {
  clearReportHistory,
  inspectHistoryStorage,
  loadReportHistory,
} from '../model/analysis-storage';
import type { ReportHistorySnapshot } from '../model/history-repository';

const retentionOptions = [
  { value: 'session', label: 'Только текущий сеанс' },
  { value: '1d', label: '1 день' },
  { value: '7d', label: '7 дней' },
  { value: '30d', label: '30 дней' },
  { value: 'forever', label: 'Без автоудаления' },
] as const;

export function HistoryPrivacySettings() {
  const { preferences, patchPreferences } = useAppPreferences();
  const policy = preferences.history;
  const [snapshot, setSnapshot] = useState<ReportHistorySnapshot | null>(null);
  const [confirmClear, setConfirmClear] = useState(false);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let active = true;
    void loadReportHistory().then((value) => {
      if (active) setSnapshot(value);
    });
    return () => { active = false; };
  }, [policy.enabled, policy.retention, policy.preserveFullPath, policy.preserveFullUrl]);

  const patchHistory = (patch: Partial<typeof policy>) => {
    patchPreferences({ history: { ...policy, ...patch } });
  };

  const refresh = async () => {
    const value = await inspectHistoryStorage();
    setSnapshot(value);
  };

  const clear = async () => {
    setBusy(true);
    const value = await clearReportHistory();
    setSnapshot(value);
    setBusy(false);
    if (value.persisted && value.status === 'empty') setConfirmClear(false);
  };

  const storage = snapshotDetails(snapshot);

  return <section className="card settings-v020">
    <h2>История и приватность</h2>
    <div className="setting-row">
      <div><strong>Сохранять новые отчёты</strong><span>Если отключено, новые результаты остаются только до закрытия FileScope. Ранее сохранённые данные не удаляются автоматически.</span></div>
      <button type="button" className={`button ${policy.enabled ? 'button-primary' : 'button-secondary'}`}
        aria-pressed={policy.enabled} onClick={() => patchHistory({ enabled: !policy.enabled })}>
        {policy.enabled ? 'Включено' : 'Отключено'}
      </button>
    </div>
    <div className="setting-row">
      <div><strong>Срок хранения</strong><span>1/7/30 дней автоматически удаляют устаревшие записи из authoritative Rust storage. «Текущий сеанс» не пишет новые отчёты на диск.</span></div>
      <Select<HistoryRetention> label="Срок хранения истории" value={policy.retention}
        options={retentionOptions} onChange={(retention) => patchHistory({ retention })} />
    </div>
    <div className="setting-row">
      <div><strong>Хранить полный путь</strong><span>По умолчанию в истории остаётся только имя файла. Включайте полный путь только если он действительно нужен для диагностики.</span></div>
      <button type="button" className={`button ${policy.preserveFullPath ? 'button-secondary' : 'button-primary'}`}
        aria-pressed={policy.preserveFullPath} onClick={() => patchHistory({ preserveFullPath: !policy.preserveFullPath })}>
        {policy.preserveFullPath ? 'Полный путь' : 'Только имя'}
      </button>
    </div>
    <div className="setting-row">
      <div><strong>Хранить полный URL</strong><span>Credentials всегда удаляются. По умолчанию query и fragment также вырезаются перед записью истории.</span></div>
      <button type="button" className={`button ${policy.preserveFullUrl ? 'button-secondary' : 'button-primary'}`}
        aria-pressed={policy.preserveFullUrl} onClick={() => patchHistory({ preserveFullUrl: !policy.preserveFullUrl })}>
        {policy.preserveFullUrl ? 'Query + fragment сохраняются' : 'URL минимизирован'}
      </button>
    </div>

    <div className="setting-row">
      <div><strong>Хранилище истории</strong><span>{storage.description}</span></div>
      <span className={`badge ${storage.tone}`}>{storage.label}</span>
    </div>
    <div className="setting-row">
      <div><strong>Занимаемое место</strong><span>{storage.reportCount} отчётов в persistent storage. Session-only результаты в размер файла не входят.</span></div>
      <span className="badge neutral">{storage.size}</span>
    </div>
    <div className="setting-row">
      <div><strong>Защита Windows</strong><span>Сейчас используется контролируемый Rust/Tauri app-data storage с атомарными generations. DPAPI ещё не включён и будет отдельным этапом v0.4.0.</span></div>
      <span className="badge warning">Без DPAPI</span>
    </div>

    <div className="button-row">
      <button type="button" className="button button-secondary" onClick={() => void refresh()}><Database />Обновить состояние</button>
      <button type="button" className="button button-danger" onClick={() => setConfirmClear(true)}><Trash2 />Удалить всю историю</button>
    </div>

    {confirmClear && <div className="status-banner warning" role="alertdialog" aria-modal="true">
      <ShieldAlert />
      <div><strong>Удалить всю локальную историю?</strong><span>Будут удалены Rust generations, session history и известные legacy report payload/backup. Настройки приложения и лимиты анализа останутся.</span></div>
      <div className="button-row">
        <button type="button" className="button button-secondary" disabled={busy} onClick={() => setConfirmClear(false)}>Отмена</button>
        <button type="button" className="button button-danger" disabled={busy} onClick={() => void clear()}><Trash2 />{busy ? 'Удаление…' : 'Удалить безвозвратно'}</button>
      </div>
    </div>}
  </section>;
}

function snapshotDetails(snapshot: ReportHistorySnapshot | null) {
  if (!snapshot) {
    return { label: 'Проверка…', tone: 'neutral', description: 'Читается состояние локального storage.', size: '—', reportCount: 0 };
  }
  const extended = snapshot as ReportHistorySnapshot & {
    backend?: 'tauri' | 'webview';
    sizeBytes?: number;
  };
  const backend = extended.backend === 'tauri' ? 'Rust/Tauri app-data' : 'Legacy WebView storage';
  const size = formatBytes(extended.sizeBytes ?? 0);
  if (snapshot.status === 'ready' || snapshot.status === 'empty') {
    return {
      label: extended.backend === 'tauri' ? 'Rust/Tauri' : 'Legacy',
      tone: extended.backend === 'tauri' ? 'success' : 'warning',
      description: `${backend}. Статус: ${snapshot.status === 'ready' ? 'готово' : 'пусто'}.`,
      size,
      reportCount: snapshot.reports.length,
    };
  }
  return {
    label: 'Защитный режим',
    tone: 'warning',
    description: snapshot.message ?? `Storage status: ${snapshot.status}.`,
    size,
    reportCount: snapshot.reports.length,
  };
}

function formatBytes(value: number): string {
  if (!Number.isFinite(value) || value <= 0) return '0 Б';
  if (value < 1024) return `${Math.round(value)} Б`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} КБ`;
  return `${(value / (1024 * 1024)).toFixed(2)} МБ`;
}
