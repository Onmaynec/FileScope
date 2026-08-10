export type ThemePreference = 'system' | 'dark' | 'light';
export type CloseBehavior = 'tray' | 'quit';
export type HistoryRetention = 'session' | '1d' | '7d' | '30d' | 'forever';

export interface HistoryPreferences {
  enabled: boolean;
  retention: HistoryRetention;
  preserveFullPath: boolean;
  preserveFullUrl: boolean;
}

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
  history: HistoryPreferences;
}

export interface ISettingsService {
  load(): AppPreferences;
  save(preferences: AppPreferences): void;
  reset(): AppPreferences;
}

export const DEFAULT_HISTORY_PREFERENCES: HistoryPreferences = {
  enabled: true,
  retention: 'forever',
  preserveFullPath: false,
  preserveFullUrl: false,
};

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
  history: DEFAULT_HISTORY_PREFERENCES,
};

const STORAGE_KEY = 'filescope.preferences.v1';
const RETENTION_VALUES = new Set<HistoryRetention>(['session', '1d', '7d', '30d', 'forever']);

export class LocalSettingsService implements ISettingsService {
  load(): AppPreferences {
    const storage = resolveStorage();
    if (!storage) return cloneDefaults();
    try {
      const raw = storage.getItem(STORAGE_KEY);
      if (!raw) return cloneDefaults();
      const parsed = JSON.parse(raw) as Partial<AppPreferences>;
      return {
        ...DEFAULT_PREFERENCES,
        ...parsed,
        exclusions: Array.isArray(parsed.exclusions)
          ? parsed.exclusions.filter((item): item is string => typeof item === 'string')
          : [],
        history: sanitizeHistoryPreferences(parsed.history),
      };
    } catch {
      return cloneDefaults();
    }
  }

  save(preferences: AppPreferences): void {
    const storage = resolveStorage();
    if (!storage) return;
    try {
      storage.setItem(STORAGE_KEY, JSON.stringify({
        ...preferences,
        history: sanitizeHistoryPreferences(preferences.history),
      }));
    } catch {
      // Ошибка локального хранилища не должна блокировать запуск приложения.
    }
  }

  reset(): AppPreferences {
    const storage = resolveStorage();
    if (storage) {
      try {
        storage.removeItem(STORAGE_KEY);
      } catch {
        // Ошибка локального хранилища не должна ломать интерфейс.
      }
    }
    return cloneDefaults();
  }
}

export function sanitizeHistoryPreferences(value: unknown): HistoryPreferences {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return { ...DEFAULT_HISTORY_PREFERENCES };
  }
  const candidate = value as Partial<HistoryPreferences>;
  return {
    enabled: typeof candidate.enabled === 'boolean' ? candidate.enabled : DEFAULT_HISTORY_PREFERENCES.enabled,
    retention: typeof candidate.retention === 'string' && RETENTION_VALUES.has(candidate.retention as HistoryRetention)
      ? candidate.retention as HistoryRetention
      : DEFAULT_HISTORY_PREFERENCES.retention,
    preserveFullPath: typeof candidate.preserveFullPath === 'boolean'
      ? candidate.preserveFullPath
      : DEFAULT_HISTORY_PREFERENCES.preserveFullPath,
    preserveFullUrl: typeof candidate.preserveFullUrl === 'boolean'
      ? candidate.preserveFullUrl
      : DEFAULT_HISTORY_PREFERENCES.preserveFullUrl,
  };
}

function resolveStorage(): Storage | null {
  if (typeof globalThis === 'undefined' || !('localStorage' in globalThis)) return null;
  try {
    return globalThis.localStorage;
  } catch {
    return null;
  }
}

function cloneDefaults(): AppPreferences {
  return {
    ...DEFAULT_PREFERENCES,
    exclusions: [...DEFAULT_PREFERENCES.exclusions],
    history: { ...DEFAULT_HISTORY_PREFERENCES },
  };
}

export const settingsService: ISettingsService = new LocalSettingsService();
export { DEFAULT_PREFERENCES };
