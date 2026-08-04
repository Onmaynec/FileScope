import { useState } from 'react';
import { Archive, ChevronLeft, ChevronRight, FileSearch, Link2, LockKeyhole, MonitorCog, ShieldCheck } from 'lucide-react';
import type { CloseBehavior } from '../../shared/services/settings-service';

interface OnboardingProps {
  closeBehavior: CloseBehavior;
  onComplete: (closeBehavior: CloseBehavior) => void;
}

const LAST_STEP = 4;

export function Onboarding({ closeBehavior: initialCloseBehavior, onComplete }: OnboardingProps) {
  const [step, setStep] = useState(0);
  const [accepted, setAccepted] = useState(false);
  const [closeBehavior, setCloseBehavior] = useState<CloseBehavior>(initialCloseBehavior);

  return (
    <div className="onboarding" role="dialog" aria-modal="true" aria-label="Первый запуск FileScope">
      <section className="onboarding-card">
        <div className="onboarding-progress" aria-label={`Шаг ${step + 1} из ${LAST_STEP + 1}`}>
          {Array.from({ length: LAST_STEP + 1 }, (_, index) => (
            <span key={index} className={index <= step ? 'active' : ''} />
          ))}
        </div>

        {step === 0 && (
          <div className="onboarding-content onboarding-hero">
            <span className="onboarding-logo"><ShieldCheck /></span>
            <h1>FileScope</h1>
            <p>Проверка ссылок, файлов и архивов до запуска</p>
          </div>
        )}

        {step === 1 && (
          <div className="onboarding-content">
            <span className="onboarding-icon"><FileSearch /></span>
            <h1>Проверяйте до запуска</h1>
            <p>Единый интерфейс для ссылок, файлов, архивов, программ и браузерных расширений.</p>
            <div className="onboarding-object-grid">
              <span><FileSearch />Файлы</span><span><Link2 />Ссылки</span>
              <span><Archive />Архивы</span><span><MonitorCog />Программы</span>
            </div>
          </div>
        )}

        {step === 2 && (
          <div className="onboarding-content">
            <span className="onboarding-icon"><LockKeyhole /></span>
            <h1>Ваши данные остаются на устройстве</h1>
            <p>Первая версия работает без интернета, не загружает выбранные объекты и не читает буфер обмена без действия пользователя.</p>
            <div className="status-banner success"><ShieldCheck /><span>Телеметрия выключена по умолчанию</span></div>
          </div>
        )}

        {step === 3 && (
          <div className="onboarding-content">
            <span className="onboarding-icon warning"><ShieldCheck /></span>
            <h1>Важное предупреждение</h1>
            <p>FileScope снижает риск, но не может гарантировать абсолютную безопасность. Отсутствие обнаруженных признаков не означает, что объект полностью безопасен.</p>
            <label className="consent-row">
              <input type="checkbox" checked={accepted} onChange={(event) => setAccepted(event.target.checked)} />
              <span>Я понимаю</span>
            </label>
          </div>
        )}

        {step === 4 && (
          <div className="onboarding-content">
            <span className="onboarding-icon"><MonitorCog /></span>
            <h1>Поведение кнопки закрытия</h1>
            <p>Выбор можно изменить позже в настройках.</p>
            <label className={`choice-card ${closeBehavior === 'tray' ? 'selected' : ''}`}>
              <input type="radio" name="close-behavior" checked={closeBehavior === 'tray'} onChange={() => setCloseBehavior('tray')} />
              <span><strong>Сворачивать в трей</strong><small>FileScope останется доступен в системной области.</small></span>
            </label>
            <label className={`choice-card ${closeBehavior === 'quit' ? 'selected' : ''}`}>
              <input type="radio" name="close-behavior" checked={closeBehavior === 'quit'} onChange={() => setCloseBehavior('quit')} />
              <span><strong>Закрывать полностью</strong><small>Процесс приложения будет завершён.</small></span>
            </label>
          </div>
        )}

        <footer className="onboarding-actions">
          <button className="button button-secondary" disabled={step === 0} onClick={() => setStep((current) => Math.max(0, current - 1))}>
            <ChevronLeft /> Назад
          </button>
          {step < LAST_STEP ? (
            <button className="button button-primary" disabled={step === 3 && !accepted} onClick={() => setStep((current) => Math.min(LAST_STEP, current + 1))}>
              {step === 0 ? 'Начать' : 'Продолжить'} <ChevronRight />
            </button>
          ) : (
            <button className="button button-primary" onClick={() => onComplete(closeBehavior)}>Открыть FileScope</button>
          )}
        </footer>
      </section>
    </div>
  );
}
