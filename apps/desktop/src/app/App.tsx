import { FileSearch, FolderArchive, Link2, ShieldCheck } from 'lucide-react';

const actions = [
  { icon: Link2, title: 'Проверить ссылку', text: 'Разберите адрес до открытия страницы.' },
  { icon: FileSearch, title: 'Проверить файл', text: 'Выберите объект на устройстве.' },
  { icon: FolderArchive, title: 'Проверить архив', text: 'Просмотрите содержимое архива.' },
];

export function App() {
  const showUnavailable = () => {
    window.alert('Модуль анализа находится в разработке и будет доступен в следующей версии');
  };

  return (
    <main className="app-shell">
      <aside className="sidebar" aria-label="Основная навигация">
        <div className="brand"><ShieldCheck aria-hidden="true" /><strong>FileScope</strong></div>
        <nav>
          <button className="nav-item nav-item--active">Главная</button>
          <button className="nav-item">Проверка</button>
          <button className="nav-item">Ссылки</button>
          <button className="nav-item">Файлы</button>
          <button className="nav-item">Архивы</button>
          <button className="nav-item">Программы</button>
        </nav>
        <div className="sidebar-footer">Версия 0.1.0 · Foundation</div>
      </aside>

      <section className="content">
        <header>
          <p className="eyebrow">ПРОВЕРЬТЕ ДО ЗАПУСКА</p>
          <h1>Проверка ссылок, файлов и архивов до запуска</h1>
          <p className="subtitle">Выберите объект или перетащите его в окно FileScope.</p>
        </header>

        <button className="dropzone" onClick={showUnavailable}>
          <FileSearch size={48} aria-hidden="true" />
          <strong>Перетащите файл, архив или папку</strong>
          <span>Функциональные модули анализа появятся в следующих версиях.</span>
          <span className="primary-button">Выбрать файл</span>
        </button>

        <section className="actions" aria-label="Быстрые действия">
          {actions.map(({ icon: Icon, title, text }) => (
            <button className="action-card" key={title} onClick={showUnavailable}>
              <Icon aria-hidden="true" />
              <strong>{title}</strong>
              <span>{text}</span>
            </button>
          ))}
        </section>

        <div className="privacy-note">
          <ShieldCheck aria-hidden="true" />
          <span>FileScope не загружает файлы во внешние сервисы без разрешения пользователя.</span>
        </div>
      </section>
    </main>
  );
}
