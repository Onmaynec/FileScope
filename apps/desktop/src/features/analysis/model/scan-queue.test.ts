import { describe, expect, it } from 'vitest';
import {
  appendUniqueQueueItems,
  confirmQueueCancellation,
  createQueueItem,
  pendingQueueItems,
  requestCurrentCancellation,
  requestQueueCancellation,
  updateQueueItem,
} from './scan-queue';

describe('очередь анализа', () => {
  it('не добавляет один объект повторно', () => {
    const first = createQueueItem('file', 'C:/Temp/sample.exe', 'sample.exe');
    const duplicate = createQueueItem('file', 'c:/temp/SAMPLE.exe', 'SAMPLE.exe');
    expect(appendUniqueQueueItems([first], [duplicate])).toHaveLength(1);
  });

  it('разрешает повтор завершённого объекта как новый jobId', () => {
    const completed = { ...createQueueItem('file', 'a.exe', 'a.exe'), status: 'completed' as const };
    const retry = createQueueItem('file', 'a.exe', 'a.exe');
    const result = appendUniqueQueueItems([completed], [retry]);
    expect(result).toHaveLength(2);
    expect(result[0].id).not.toBe(result[1].id);
  });

  it('последовательно меняет состояние задания', () => {
    const item = createQueueItem('url', 'https://example.com', 'example.com');
    const running = updateQueueItem([item], item.id, { status: 'running' });
    const completed = updateQueueItem(running, item.id, { status: 'completed' });
    expect(completed[0].status).toBe('completed');
  });

  it('отмена текущего не повреждает pending-задания', () => {
    const running = { ...createQueueItem('file', 'a.exe', 'a.exe'), status: 'running' as const };
    const pending = createQueueItem('file', 'b.exe', 'b.exe');
    const requested = requestCurrentCancellation([running, pending], running.id);
    expect(requested.map((item) => item.status)).toEqual(['cancelling', 'pending']);
  });

  it('не называет running-задание отменённым до ответа backend', () => {
    const running = { ...createQueueItem('file', 'a.exe', 'a.exe'), status: 'running' as const };
    const pending = createQueueItem('file', 'b.exe', 'b.exe');
    const completed = { ...createQueueItem('file', 'c.exe', 'c.exe'), status: 'completed' as const };
    const requested = requestQueueCancellation([running, pending, completed], running.id);
    expect(requested.map((item) => item.status)).toEqual(['cancelling', 'cancelled', 'completed']);
    expect(pendingQueueItems(requested)).toHaveLength(0);
    const confirmed = confirmQueueCancellation(requested, running.id);
    expect(confirmed[0].status).toBe('cancelled');
    expect(confirmed[0].error).toContain('Rust backend');
  });
});
