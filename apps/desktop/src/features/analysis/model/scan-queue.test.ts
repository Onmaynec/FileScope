import { describe, expect, it } from 'vitest';
import {
  appendUniqueQueueItems,
  appendUniqueQueueItemsDetailed,
  confirmQueueCancellation,
  createQueueItem,
  pendingQueueItems,
  requestCurrentCancellation,
  requestQueueCancellation,
  updateQueueItem,
} from './scan-queue';

describe('очередь анализа', () => {
  it('не добавляет один объект повторно и возвращает существующий item', () => {
    const first = createQueueItem('file', 'C:/Temp/sample.exe', 'sample.exe');
    const duplicate = createQueueItem('file', 'c:/temp/SAMPLE.exe', 'SAMPLE.exe');
    const result = appendUniqueQueueItemsDetailed([first], [duplicate]);
    expect(result.queue).toHaveLength(1);
    expect(result.added).toHaveLength(0);
    expect(result.duplicates).toHaveLength(1);
    expect(result.duplicates[0]?.existing.id).toBe(first.id);
    expect(result.duplicates[0]?.attempted.id).toBe(duplicate.id);
  });

  it('legacy append helper сохраняет обратную совместимость', () => {
    const first = createQueueItem('file', 'C:/Temp/sample.exe', 'sample.exe');
    const duplicate = createQueueItem('file', 'c:/temp/SAMPLE.exe', 'SAMPLE.exe');
    expect(appendUniqueQueueItems([first], [duplicate])).toHaveLength(1);
  });

  it('разделяет active и passive URL как разные queue identity', () => {
    const passive = createQueueItem('url', 'https://example.com/a', 'example.com', false);
    const active = createQueueItem('url', 'https://example.com/a', 'example.com', true);
    const result = appendUniqueQueueItemsDetailed([passive], [active]);
    expect(result.added.map((item) => item.id)).toEqual([active.id]);
    expect(result.duplicates).toHaveLength(0);
  });

  it('корректно обрабатывает batch новый + duplicate', () => {
    const existing = createQueueItem('file', 'a.exe', 'a.exe');
    const duplicate = createQueueItem('file', 'A.EXE', 'A.EXE');
    const fresh = createQueueItem('file', 'b.exe', 'b.exe');
    const result = appendUniqueQueueItemsDetailed([existing], [duplicate, fresh]);
    expect(result.queue.map((item) => item.id)).toEqual([existing.id, fresh.id]);
    expect(result.added.map((item) => item.id)).toEqual([fresh.id]);
    expect(result.duplicates[0]?.existing.id).toBe(existing.id);
  });

  it('разрешает повтор завершённого объекта как новый jobId', () => {
    const completed = { ...createQueueItem('file', 'a.exe', 'a.exe'), status: 'completed' as const };
    const retry = createQueueItem('file', 'a.exe', 'a.exe');
    const result = appendUniqueQueueItemsDetailed([completed], [retry]);
    expect(result.queue).toHaveLength(2);
    expect(result.added[0]?.id).toBe(retry.id);
    expect(result.queue[0].id).not.toBe(result.queue[1].id);
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
