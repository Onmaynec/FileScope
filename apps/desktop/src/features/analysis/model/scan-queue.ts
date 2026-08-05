import type { AnalysisReport, ObjectKind } from './types';

export type QueueStatus = 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';

export interface AnalysisQueueItem {
  id: string;
  kind: ObjectKind;
  target: string;
  displayName: string;
  activeNetwork: boolean;
  status: QueueStatus;
  createdAt: string;
  startedAt?: string;
  completedAt?: string;
  report?: AnalysisReport;
  error?: string;
}

export function createQueueItem(
  kind: ObjectKind,
  target: string,
  displayName: string,
  activeNetwork = false,
): AnalysisQueueItem {
  return {
    id: queueId(),
    kind,
    target,
    displayName,
    activeNetwork,
    status: 'pending',
    createdAt: new Date().toISOString(),
  };
}

export function appendUniqueQueueItems(current: AnalysisQueueItem[], next: AnalysisQueueItem[]): AnalysisQueueItem[] {
  const existing = new Set(current.filter((item) => item.status !== 'cancelled').map(queueIdentity));
  const result = [...current];
  for (const item of next) {
    const identity = queueIdentity(item);
    if (existing.has(identity)) continue;
    existing.add(identity);
    result.push(item);
  }
  return result;
}

export function updateQueueItem(
  queue: AnalysisQueueItem[],
  id: string,
  patch: Partial<AnalysisQueueItem>,
): AnalysisQueueItem[] {
  return queue.map((item) => item.id === id ? { ...item, ...patch } : item);
}

export function cancelOpenQueueItems(queue: AnalysisQueueItem[]): AnalysisQueueItem[] {
  const completedAt = new Date().toISOString();
  return queue.map((item) => item.status === 'pending' || item.status === 'running'
    ? { ...item, status: 'cancelled', completedAt }
    : item);
}

export function removeFinishedQueueItems(queue: AnalysisQueueItem[]): AnalysisQueueItem[] {
  return queue.filter((item) => item.status === 'pending' || item.status === 'running');
}

export function pendingQueueItems(queue: AnalysisQueueItem[]): AnalysisQueueItem[] {
  return queue.filter((item) => item.status === 'pending');
}

function queueIdentity(item: AnalysisQueueItem): string {
  const networkMode = item.kind === 'url' && item.activeNetwork ? 'active' : 'passive';
  return `${item.kind}:${networkMode}:${item.target.trim().toLowerCase()}`;
}

function queueId(): string {
  if (typeof crypto !== 'undefined' && 'randomUUID' in crypto) return crypto.randomUUID();
  return `queue-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}
