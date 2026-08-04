import { getCurrentWindow } from '@tauri-apps/api/window';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import { open } from '@tauri-apps/plugin-dialog';
import type { CloseBehavior } from '../services/settings-service';

export interface SelectedObject {
  path: string;
  displayName: string;
}

export async function selectLocalObject(directory = false): Promise<SelectedObject | null> {
  try {
    const selected = await open({ multiple: false, directory });
    if (!selected || Array.isArray(selected)) return null;
    const normalized = selected.replaceAll('\\', '/');
    return {
      path: selected,
      displayName: normalized.split('/').at(-1) || selected,
    };
  } catch {
    return null;
  }
}

export async function bindCloseBehavior(getBehavior: () => CloseBehavior): Promise<UnlistenFn | null> {
  try {
    const window = getCurrentWindow();
    return await window.onCloseRequested(async (event) => {
      if (getBehavior() === 'tray') {
        event.preventDefault();
        await window.hide();
      }
    });
  } catch {
    return null;
  }
}

export async function bindNativeNavigation(onNavigate: (page: string) => void, onSelectFile: () => void): Promise<UnlistenFn[]> {
  const listeners: UnlistenFn[] = [];
  try {
    listeners.push(await listen<string>('filescope:navigate', (event) => onNavigate(event.payload)));
    listeners.push(await listen('filescope:select-file', () => onSelectFile()));
  } catch {
    // В браузерном режиме нативные события недоступны — это ожидаемо.
  }
  return listeners;
}
