import { Github, Scale, ShieldCheck } from 'lucide-react';

interface AboutPageProps {
  onShowTerms: () => void;
}

export function AboutPage({ onShowTerms }: AboutPageProps) {
  return (
    <>
      <header className="page-header"><h1>О программе</h1><p>Сведения о FileScope и принципах первой UI-версии.</p></header>
      <section className="about-hero card">
        <span className="about-logo"><ShieldCheck /></span>
        <div><h2>FileScope 0.1.0</h2><p>Проверка ссылок, файлов и архивов до запуска.</p></div>
        <span className="badge">UI Preview</span>
      </section>
      <section className="two-column">
        <article className="card"><h2>Принципы приватности</h2><p>Регистрация не требуется. Телеметрия выключена. Файлы и ссылки не отправляются во внешние сервисы, а пароли архивов не сохраняются.</p></article>
        <article className="card"><h2>Ограничение ответственности</h2><p>FileScope снижает риск, но не гарантирует абсолютную безопасность. В этой версии аналитическое ядро отсутствует.</p></article>
      </section>
      <section className="card about-actions">
        <button className="button button-secondary" onClick={onShowTerms}><Scale />Условия использования</button>
        <span className="button button-secondary button-static"><Github />Приватный репозиторий проекта</span>
      </section>
    </>
  );
}
