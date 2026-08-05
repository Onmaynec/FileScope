import { useEffect } from 'react';
import { create } from 'zustand';
import { type AppPreferences, settingsService } from '../services/settings-service';

interface PreferencesState {
  preferences: AppPreferences;
  patchPreferences: (patch: Partial<AppPreferences>) => void;
  resetPreferences: () => void;
}

const usePreferencesStore = create<PreferencesState>((set) => ({
  preferences: settingsService.load(),
  patchPreferences: (patch) => set((state) => ({
    preferences: { ...state.preferences, ...patch },
  })),
  resetPreferences: () => set({ preferences: settingsService.reset() }),
}));

export function useAppPreferences() {
  const preferences = usePreferencesStore((state) => state.preferences);
  const patchPreferences = usePreferencesStore((state) => state.patchPreferences);
  const resetPreferences = usePreferencesStore((state) => state.resetPreferences);

  useEffect(() => {
    settingsService.save(preferences);
  }, [preferences]);

  return { preferences, patchPreferences, resetPreferences };
}
