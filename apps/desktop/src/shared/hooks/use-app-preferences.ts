import { useEffect, useMemo, useState } from 'react';
import { type AppPreferences, settingsService } from '../services/settings-service';

export function useAppPreferences() {
  const initial = useMemo(() => settingsService.load(), []);
  const [preferences, setPreferences] = useState<AppPreferences>(initial);

  useEffect(() => {
    settingsService.save(preferences);
  }, [preferences]);

  const patchPreferences = (patch: Partial<AppPreferences>) => {
    setPreferences((current) => ({ ...current, ...patch }));
  };

  const resetPreferences = () => {
    setPreferences(settingsService.reset());
  };

  return { preferences, patchPreferences, resetPreferences };
}
