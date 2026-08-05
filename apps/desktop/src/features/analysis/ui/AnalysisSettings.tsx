import { useState } from 'react';
import { RotateCcw, Save, ShieldCheck } from 'lucide-react';
import { defaultAnalysisLimits, type AnalysisLimits } from '../model/types';
import { saveAnalysisLimits } from '../model/analysis-storage';

interface AnalysisSettingsProps {
  value: AnalysisLimits;
  onChange: (limits: AnalysisLimits) => void;
}

export function AnalysisSettings({ value, onChange }: AnalysisSettingsProps) {
  const [draft, setDraft] = useState(value);
  const update = (field: keyof AnalysisLimits, next: number) => setDraft((current) => ({ ...current, [field]: next }));
  const save = () => onChange(saveAnalysisLimits(draft));
  const reset = () => { setDraft(defaultAnalysisLimits); onChange(saveAnalysisLimits(defaultAnalysisLimits)); };

  return <div className="analysis-settings">
    <section className="card"><div className="card-title-row"><div><h2>Лимиты локального анализа</h2><p>Ограничения защищают устройство от чрезмерного потребления памяти, времени и дискового пространства.</p></div><ShieldCheck /></div>
      <div className="analysis-settings-grid">
        <NumberSetting label="Максимальный размер файла" suffix="МБ" value={Math.round(draft.maximumFileSizeBytes / 1024 / 1024)} minimum={1} maximum={4096} onChange={(next) => update('maximumFileSizeBytes', next * 1024 * 1024)} />
        <NumberSetting label="Максимум записей ZIP" suffix="шт." value={draft.maximumArchiveEntries} minimum={10} maximum={100000} onChange={(next) => update('maximumArchiveEntries', next)} />
        <NumberSetting label="Максимальный объём после распаковки" suffix="МБ" value={Math.round(draft.maximumArchiveUncompressedBytes / 1024 / 1024)} minimum={10} maximum={20480} onChange={(next) => update('maximumArchiveUncompressedBytes', next * 1024 * 1024)} />
        <NumberSetting label="Максимальная глубина ZIP" suffix="уровней" value={draft.maximumArchiveDepth} minimum={1} maximum={64} onChange={(next) => update('maximumArchiveDepth', next)} />
        <NumberSetting label="Порог степени сжатия" suffix="x" value={draft.maximumCompressionRatio} minimum={2} maximum={10000} onChange={(next) => update('maximumCompressionRatio', next)} />
        <NumberSetting label="Таймаут активного URL" suffix="мс" value={draft.activeUrlTimeoutMs} minimum={1000} maximum={30000} step={500} onChange={(next) => update('activeUrlTimeoutMs', next)} />
        <NumberSetting label="Лимит перенаправлений" suffix="шт." value={draft.activeUrlRedirectLimit} minimum={0} maximum={10} onChange={(next) => update('activeUrlRedirectLimit', next)} />
      </div>
      <div className="button-row"><button className="button button-primary" onClick={save}><Save />Сохранить настройки</button><button className="button button-secondary" onClick={reset}><RotateCcw />Вернуть безопасные значения</button></div>
    </section>
    <section className="info-banner warning"><ShieldCheck /><div><strong>Ограничения нельзя отключить полностью</strong><span>FileScope не распаковывает ZIP на диск и не запускает исследуемые файлы. Повышайте лимиты только для объектов из проверенного источника.</span></div></section>
  </div>;
}

function NumberSetting({ label, suffix, value, minimum, maximum, step = 1, onChange }: { label: string; suffix: string; value: number; minimum: number; maximum: number; step?: number; onChange: (value: number) => void }) {
  return <label className="analysis-setting"><span><strong>{label}</strong><small>{minimum.toLocaleString('ru-RU')}–{maximum.toLocaleString('ru-RU')} {suffix}</small></span><span className="analysis-setting__input"><input className="input compact" type="number" min={minimum} max={maximum} step={step} value={value} onChange={(event) => onChange(Number(event.target.value))} /><b>{suffix}</b></span></label>;
}
