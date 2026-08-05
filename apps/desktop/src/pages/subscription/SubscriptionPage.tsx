import { Check, Crown, ShieldCheck } from 'lucide-react';

interface SubscriptionPageProps {
  onUnavailable: () => void;
}

const freeFeatures = ['Базовый локальный анализ', 'Проверка ссылок', 'Базовая проверка файлов', 'Просмотр архивов', 'Понятный уровень риска'];
const proFeatures = ['Глубокий анализ', 'Рекурсивные архивы', 'Проверка расширений', 'Проверка программ', 'Технический отчёт', 'Hyper-V Sandbox'];

export function SubscriptionPage({ onUnavailable }: SubscriptionPageProps) {
  return (
    <>
      <header className="page-header"><h1>Подписка</h1><p>FileScope Free работает без аккаунта. Платёжная система в версии 0.1.0 не подключена.</p></header>
      <div className="subscription-status card"><ShieldCheck /><div><strong>Текущий тариф: FileScope Free</strong><span>Базовые возможности приложения доступны без регистрации.</span></div><span className="badge">Активен</span></div>
      <section className="pricing-grid">
        <article className="card pricing-card">
          <h2>Free</h2><p className="price">0 ₽ <span>навсегда</span></p>
          <ul>{freeFeatures.map((feature) => <li key={feature}><Check />{feature}</li>)}</ul>
          <button className="button button-secondary" disabled>Текущий тариф</button>
        </article>
        <article className="card pricing-card pricing-card-pro">
          <span className="recommended"><Crown />Расширенные возможности</span>
          <h2>FileScope Pro</h2><p className="price">Скоро</p>
          <ul>{proFeatures.map((feature) => <li key={feature}><Check />{feature}</li>)}</ul>
          <button className="button button-primary" onClick={onUnavailable}>Перейти на Pro</button>
          <button className="text-button" onClick={onUnavailable}>Восстановить лицензию</button>
        </article>
      </section>
    </>
  );
}
