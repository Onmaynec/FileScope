import { describe, expect, it } from 'vitest';
import { AnalysisError, analyzeUrlPassive, friendlyAnalysisError, normalizeAnalysisError } from './analysis-api';

describe('канонический URL-анализ', () => {
  it('не выдаёт production verdict через browser fallback', async () => {
    await expect(analyzeUrlPassive('job-1', 'https://example.com/path')).rejects.toThrow(
      'Browser preview не выдаёт production verdict',
    );
  });
});

describe('типизированные ошибки анализа', () => {
  it('объясняет подтверждённую backend-отмену', () => {
    expect(friendlyAnalysisError({ code: 'cancelled', message: 'cancelled' })).toContain(
      'Rust backend подтвердил остановку',
    );
  });

  it('объясняет изменение файла во время проверки', () => {
    expect(friendlyAnalysisError({ code: 'fileChanged', message: 'changed' })).toContain(
      'Файл изменился во время проверки',
    );
  });

  it('объясняет защитную блокировку сети', () => {
    expect(friendlyAnalysisError({ code: 'securityBlocked', message: 'Локальный адрес заблокирован.' }))
      .toBe('Локальный адрес заблокирован.');
  });

  it('объясняет отсутствие доступа к файлу', () => {
    expect(friendlyAnalysisError('Access is denied. (os error 5)')).toContain('Windows запретила чтение объекта');
  });

  it('объясняет исчезнувший файл', () => {
    expect(friendlyAnalysisError('The system cannot find the file specified. (os error 2)')).toContain('Файл больше не найден');
  });

  it('читает JSON-ошибку Tauri', () => {
    const error = normalizeAnalysisError('{"code":"timeout","message":"deadline"}');
    expect(error).toBeInstanceOf(AnalysisError);
    expect(error.code).toBe('timeout');
  });

  it('сохраняет неизвестную диагностическую ошибку без подмены', () => {
    expect(friendlyAnalysisError('custom parser failure')).toBe('custom parser failure');
  });
});
