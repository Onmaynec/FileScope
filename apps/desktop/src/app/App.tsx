import {
  Archive,
  FileSearch,
  FolderArchive,
  Home,
  Link2,
  Menu,
  PackageSearch,
  ScanSearch,
  Settings,
  ShieldCheck,
} from 'lucide-react';
import { locale } from '../shared/localization';
import { useUiStore } from './store/ui-store';

const navigation = [
  { icon: Home, label: locale.navigation.home, active: true },
  { icon: ScanSearch, label: locale.navigation.scan },
  { icon: Link2, label: locale.navigation.links },
  { icon: FileSearch, label: locale.navigation.files },
  { icon: Archive, label: locale.navigation.archives },
  { icon: PackageSearch, label: locale.navigation.programs },
  { icon: Settings, label: locale.navigation.settings },
];

const actions = [
  { icon: Link2, ...locale.actions.link },
  { icon: FileSearch, ...locale.actions.file },
  { icon: FolderArchive, ...locale.actions.archive },
  { icon: PackageSearch, ...locale.actions.program },
];

export function App() {
  const {
    sidebarCollapsed,
    unavailableDialogOpen,
    toggleSidebar,
    showUnavailableDialog,
    hideUnavailableDialog,
  } = useUiStore();

  return (
    <main className={`app-shell${sidebarCollapsed ? ' app-shell--collapsed' : ''}`}>
      <aside className="sidebar" aria-label={locale.navigation.ariaLabel}>
        <div className="brand">
          <ShieldCheck aria-hidden="true" />
          <strong>{locale.app.name}</strong>
          <button className="icon-button sidebar-toggle" onClick={toggleSidebar} aria-label="Свернуть боковую панель">
            <Menu aria-hidden="true" />
          </button>
        </div>
        <nav>
          {navigation.map(({ icon: Icon, label, active }) => (
            <button
              className={`nav-item${active ? ' nav-item--active' : ''}`}
              key={label}
              title={sidebarCollapsed ? label : undefined}
              onClick={active ? undefined : showUnavailableDialog}
              aria-current={active ? 'page' : undefined}
            >
              <Icon aria-hidden="true" />
              <span>{label}</span>
            </button>
          ))}
        </nav>
        <div className="sidebar-footer">{locale.app.version}</div>
      </aside>

      <section className="content">
        <header>
          <p className="eyebrow">{locale.home.eyebrow}</p>
          <h1>{locale.home.title}</h1>
          <p className="subtitle">{locale.home.subtitle}</p>
        </header>

        <button className="dropzone" onClick={showUnavailableDialog}>
          <FileSearch size={48} aria-hidden="true" />
          <strong>{locale.home.dropzoneTitle}</strong>
          <span>{locale.home.comingSoon}</span>
          <span className="primary-button">{locale.home.chooseFile}</span>
        </button>

        <section className="actions" aria-label={locale.home.quickActions}>
          {actions.map(({ icon: Icon, title, description }) => (
            <button className="action-card" key={title} onClick={showUnavailableDialog}>
              <Icon aria-hidden="true" />
              <strong>{title}</strong>
              <span>{description}</span>
            </button>
          ))}
        </section>

        <div className="privacy-note">
          <ShieldCheck aria-hidden="true" />
          <span>{locale.home.privacy}</span>
        </div>
      </section>

      {unavailableDialogOpen && (
        <div className="dialog-backdrop" role="presentation" onMouseDown={hideUnavailableDialog}>
          <section
            className="dialog"
            role="dialog"
            aria-modal="true"
            aria-labelledby="unavailable-title"
            onMouseDown={(event) => event.stopPropagation()}
          >
            <div className="dialog-icon"><ShieldCheck aria-hidden="true" /></div>
            <h2 id="unavailable-title">{locale.dialogs.unavailableTitle}</h2>
            <p>{locale.dialogs.unavailableText}</p>
            <button className="button button--primary" autoFocus onClick={hideUnavailableDialog}>
              {locale.dialogs.close}
            </button>
          </section>
        </div>
      )}
    </main>
  );
}
