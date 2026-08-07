
import { describe, expect, it } from 'vitest';
import {
  filterHeadersForHistory,
  minimizePathForHistory,
  redactUrlForHistory,
} from './history-privacy';

const privatePolicy = {
  preserveFullPath: false,
  preserveUrlQuery: false,
  preserveUrlFragment: false,
};

describe('v0.4 privacy preparation properties', () => {
  it('никогда не возвращает username/password из корректного HTTP URL', () => {
    for (let index = 0; index < 256; index += 1) {
      const password = `secret-${index}-value`;
      const value = `https://user:${password}@example.com/path?q=${index}#fragment`;
      const redacted = redactUrlForHistory(value, privatePolicy);
      expect(redacted).not.toContain(password);
      expect(redacted).not.toContain('user:');
      expect(redacted).not.toContain('?');
      expect(redacted).not.toContain('#');
    }
  });

  it('фильтрует чувствительные headers независимо от регистра', () => {
    const safe = filterHeadersForHistory([
      ['Set-Cookie', 'session=secret'],
      ['AUTHORIZATION', 'Bearer secret'],
      ['Content-Type', 'text/plain'],
    ]);
    expect(safe).toEqual([['Content-Type', 'text/plain']]);
  });

  it('сохраняет только basename при выключенном полном пути', () => {
    expect(minimizePathForHistory('C:\\Users\\Example\\sample.exe', false)).toBe('sample.exe');
    expect(minimizePathForHistory('/home/example/sample.bin', false)).toBe('sample.bin');
  });
});
