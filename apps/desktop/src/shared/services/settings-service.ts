export type ThemePreference = 'system' | 'dark' | 'light';
export type CloseBehavior = 'tray' | 'quit';

export interface AppPreferences {
  theme: ThemePreference;
  closeBehavior: CloseBehavior;
  developerMode: boolean;
  sidebarCollapsed: boolean;
  onboardingCompleted: boolean;
  crashReportsEnabled: boolean;
  automaticUpdates: boolean;
  exclusions: string[];
  lastPage: string;
}

export interface ISettingsService {
  load(): AppPreferences;
  save(preferences: AppPreferences): void;
  reset(): AppPreferences;
}

const DEFAULT_PREFERENCES: AppPreferences = {
  theme: 'dark',
  closeBehavior: 'tray',
  developerMode: false,
  sidebarCollapsed: false,
  onboardingCompleted: false,
  crashReportsEnabled: false,
  automaticUpdates: true,
  exclusions: [],
  lastPage: 'home',
};

const STORAGE_KEY = 'filescope.preferences.v1';

export class LocalSettingsService implements ISettingsService {
  load(): AppPreferences {
    try {
      const raw = window.localStorage.getItem(STORAGE_KEY);
      if (!raw) return { ...DEFAULT_PREFERENCES };
      const parsed = JSON.parse(raw) as Partial<AppPreferences>;
      return {
        ...DEFAULT_PREFERENCES,
        ...parsed,
        exclusions: Array.isArray(parsed.exclusions)
          ? parsed.exclusions.filter((item): item is string => typeof item === 'string')
          : [],
      };
    } catch {
      return { ...DEFAULT_PREFERENCES };
    }
  }

  save(preferences: AppPreferences): void {
    try {
      window.localStorage.setItem(STORAGE_KEY, JSON.stringify(preferences));
    } catch {
      // Ошибка локального хранилища не должна блокировать запуск приложения.
    }
  }

  reset(): AppPreferences {
    try {
      window.localStorage.removeItem(STORAGE_KEY);
    } catch {
      // Ошибка локального хранилища не должна ломать интерфейс.
    }
    return { ...DEFAULT_PREFERENCES };
  }
}

export const settingsService: ISettingsService = new LocalSettingsService();
export { DEFAULT_PREFERENCES };
