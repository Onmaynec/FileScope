import { beforeEach, describe, expect, it } from 'vitest';

import {
  DEFAULT_HISTORY_PREFERENCES,
  LocalSettingsService,
} from './settings-service';

beforeEach(() => installMemoryStorage());

describe('settings service v0.4 history preferences', () => {
  it('добавляет безопасные history defaults к старым preferences', () => {
    localStorage.setItem('filescope.preferences.v1', JSON.stringify({
      theme: 'light',
      closeBehavior: 'quit',
      lastPage: 'reports',
    }));

    const loaded = new LocalSettingsService().load();

    expect(loaded.theme).toBe('light');
    expect(loaded.history).toEqual(DEFAULT_HISTORY_PREFERENCES);
  });

  it('санитизирует неизвестный retention и типы privacy flags', () => {
    localStorage.setItem('filescope.preferences.v1', JSON.stringify({
      history: {
        enabled: 'yes',
        retention: '365d',
        preserveFullPath: 1,
        preserveFullUrl: true,
      },
    }));

    const loaded = new LocalSettingsService().load();

    expect(loaded.history).toEqual({
      ...DEFAULT_HISTORY_PREFERENCES,
      preserveFullUrl: true,
    });
  });

  it('сохраняет валидную privacy/retention policy', () => {
    const service = new LocalSettingsService();
    const preferences = service.load();
    preferences.history = {
      enabled: false,
      retention: '7d',
      preserveFullPath: true,
      preserveFullUrl: false,
    };

    service.save(preferences);

    expect(service.load().history).toEqual(preferences.history);
  });
});

function installMemoryStorage(): void {
  const values = new Map<string, string>();
  const storage: Storage = {
    get length() { return values.size; },
    clear: () => values.clear(),
    getItem: (key) => values.get(key) ?? null,
    key: (index) => [...values.keys()][index] ?? null,
    removeItem: (key) => { values.delete(key); },
    setItem: (key, value) => { values.set(key, value); },
  };
  Object.defineProperty(globalThis, 'localStorage', { configurable: true, value: storage });
}
