import { describe, expect, it } from 'vitest';
import { ru } from './ru';

describe('русская локализация', () => {
  it('содержит обязательное сообщение о недоступности анализа', () => {
    expect(ru.dialogs.unavailableText).toContain('Модуль анализа находится в разработке');
  });

  it('не утверждает абсолютную безопасность', () => {
    expect(JSON.stringify(ru)).not.toContain('100% безопас');
  });
});
