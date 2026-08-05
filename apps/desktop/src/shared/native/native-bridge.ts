import { invoke } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import { open } from '@tauri-apps/plugin-dialog';
import type { CloseBehavior } from '../services/settings-service';

export interface SelectedObject {
  path: string;
  displayName: string;
}

export async function selectLocalObject(directory = false): Promise<SelectedObject | null> {
  const selected = await selectLocalObjects({ directory, multiple: false });
  return selected[0] ?? null;
}

export async function selectLocalObjects(options: { directory?: boolean; multiple?: boolean } = {}): Promise<SelectedObject[]> {
  try {
    const selected = await open({
      multiple: options.multiple ?? true,
      directory: options.directory ?? false,
    });
    if (!selected) return [];
    const paths = Array.isArray(selected) ? selected : [selected];
    return paths.map((path) => {
      const normalized = path.replaceAll('\\', '/');
      return {
        path,
        displayName: normalized.split('/').at(-1) || path,
      };
    });
  } catch {
    return [];
  }
}

export async function syncCloseBehavior(behavior: CloseBehavior): Promise<void> {
  try {
    await invoke('set_close_behavior', { behavior });
  } catch {
    // В браузерном режиме Rust backend недоступен — это ожидаемо.
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
