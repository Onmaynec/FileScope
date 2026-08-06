import { invoke } from '@tauri-apps/api/core';

export interface LocalObjectCandidate {
  path: string;
  displayName: string;
  accepted: boolean;
  reason?: string;
}

export async function inspectLocalPaths(
  paths: string[],
  archiveOnly: boolean,
): Promise<LocalObjectCandidate[]> {
  if (typeof window === 'undefined' || !('__TAURI_INTERNALS__' in window)) return [];
  return invoke<LocalObjectCandidate[]>('inspect_local_paths', { paths, archiveOnly });
}
