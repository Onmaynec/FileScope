import { describe, expect, it } from 'vitest';
import {
  appendUniqueQueueItems,
  cancelOpenQueueItems,
  createQueueItem,
  pendingQueueItems,
  updateQueueItem,
} from './scan-queue';

describe('очередь анализа', () => {
  it('не добавляет один объект повторно', () => {
    const first = createQueueItem('file', 'C:/Temp/sample.exe', 'sample.exe');
    const duplicate = createQueueItem('file', 'c:/temp/SAMPLE.exe', 'SAMPLE.exe');
    expect(appendUniqueQueueItems([first], [duplicate])).toHaveLength(1);
  });

  it('последовательно меняет состояние задания', () => {
    const item = createQueueItem('url', 'https://example.com', 'example.com');
    const running = updateQueueItem([item], item.id, { status: 'running' });
    const completed = updateQueueItem(running, item.id, { status: 'completed' });
    expect(completed[0].status).toBe('completed');
  });

  it('отменяет активные и ожидающие задания, сохраняя завершённые', () => {
    const running = { ...createQueueItem('file', 'a.exe', 'a.exe'), status: 'running' as const };
    const pending = createQueueItem('file', 'b.exe', 'b.exe');
    const completed = { ...createQueueItem('file', 'c.exe', 'c.exe'), status: 'completed' as const };
    const result = cancelOpenQueueItems([running, pending, completed]);
    expect(result.map((item) => item.status)).toEqual(['cancelled', 'cancelled', 'completed']);
    expect(pendingQueueItems(result)).toHaveLength(0);
  });
});
