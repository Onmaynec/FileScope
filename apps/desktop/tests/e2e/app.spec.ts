import { expect, test, type Locator } from '@playwright/test';

test.beforeEach(async ({ page }) => {
  await page.goto('/');
  await page.evaluate(() => window.localStorage.clear());
  await page.reload();
});

test('открывается функциональный главный экран v0.3.3', async ({ page }) => {
  await expect(page.getByRole('heading', { name: 'Реальный анализ до запуска' })).toBeVisible();
  await expect(page.locator('aside[aria-label="Основная навигация"]')).toBeVisible();
  await expect(page.getByText('Версия 0.3.3')).toBeVisible();
});

test('кнопка загрузки файлов использует понятный текст', async ({ page }) => {
  await page.getByRole('button', { name: /Файлы/ }).click();
  await expect(page.getByText('Загрузить файлы', { exact: true })).toBeVisible();
  await expect(page.getByText('Открыть файловый диалог', { exact: true })).toHaveCount(0);
});

test('кастомный select доступен с клавиатуры и сохраняет настройку', async ({ page }) => {
  await page.getByRole('button', { name: /Настройки/ }).click();
  const closeBehavior = page.getByRole('button', { name: 'Поведение при закрытии' });

  await expect(page.getByText('Версия приложения')).toBeVisible();
  await expect(page.getByText('0.3.3', { exact: true })).toBeVisible();
  await expect(closeBehavior).toContainText('Сворачивать в трей');
  await closeBehavior.focus();
  await closeBehavior.press('Enter');
  await page.getByRole('option', { name: 'Закрывать полностью' }).press('Enter');
  await page.reload();
  await page.getByRole('button', { name: /Настройки/ }).click();

  await expect(page.getByRole('button', { name: 'Поведение при закрытии' })).toContainText('Закрывать полностью');
});

test('browser preview не выдаёт ложный production verdict', async ({ page }) => {
  await page.getByRole('button', { name: /Ссылки/ }).click();
  await page.getByLabel('Адрес').fill('https://login@example.com/open?redirect=https%3A%2F%2Fevil.test');
  await page.getByRole('button', { name: 'Начать анализ' }).click();

  await expect(page.getByText(/Browser preview не выдаёт production verdict/)).toBeVisible();
  await expect(page.getByText('Реальный локальный отчёт')).toHaveCount(0);
});

test('несколько URL образуют master-detail очередь', async ({ page }) => {
  await page.getByRole('button', { name: /Ссылки/ }).click();
  const input = page.getByLabel('Адрес');

  await input.fill('https://example.com/first');
  await page.getByRole('button', { name: 'Добавить URL в очередь' }).click();
  await input.fill('https://example.org/second');
  await page.getByRole('button', { name: 'Добавить URL в очередь' }).click();

  await expect(page.getByRole('heading', { name: 'Очередь' })).toBeVisible();
  await expect(page.getByLabel('Очередь проверок')).toContainText('example.com');
  await expect(page.getByLabel('Очередь проверок')).toContainText('example.org');
  await expect(page.getByLabel('Детали выбранного задания')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Запустить очередь (2)' })).toBeVisible();
});

test('фильтры очереди используют доступные listbox', async ({ page }) => {
  await page.getByRole('button', { name: /Ссылки/ }).click();
  await page.getByLabel('Адрес').fill('https://example.com/first');
  await page.getByRole('button', { name: 'Добавить URL в очередь' }).click();

  const status = page.getByRole('button', { name: 'Фильтр статуса' });
  await status.click();
  await expect(page.getByRole('listbox', { name: 'Фильтр статуса' })).toBeVisible();
  await page.getByRole('option', { name: 'Ожидают' }).click();
  await expect(status).toContainText('Ожидают');
});

test('синий текст светлой темы остаётся читаемым на светлых поверхностях', async ({ page }) => {
  await page.getByRole('button', { name: /Настройки/ }).click();
  await page.getByRole('button', { name: 'Тема приложения' }).click();
  await page.getByRole('option', { name: 'Светлая' }).click();
  await page.getByRole('button', { name: /Главная/ }).click();

  const checkedText = [
    page.locator('.info-banner strong'),
    page.locator('.info-banner span'),
    page.locator('.v020-hero__shield span'),
  ];

  for (const locator of checkedText) {
    await expect(locator).toBeVisible();
    expect(await contrastRatio(locator)).toBeGreaterThanOrEqual(4.5);
  }
});

async function contrastRatio(locator: Locator): Promise<number> {
  return locator.evaluate((element) => {
    const parseRgb = (value: string): [number, number, number, number] => {
      const match = value.match(/rgba?\(([^)]+)\)/);
      if (!match) return [255, 255, 255, 1];
      const parts = match[1].split(',').map((part) => Number.parseFloat(part.trim()));
      return [parts[0], parts[1], parts[2], parts[3] ?? 1];
    };

    const luminance = ([red, green, blue]: [number, number, number, number]) => {
      const channels = [red, green, blue].map((channel) => {
        const normalized = channel / 255;
        return normalized <= 0.03928
          ? normalized / 12.92
          : ((normalized + 0.055) / 1.055) ** 2.4;
      });
      return channels[0] * 0.2126 + channels[1] * 0.7152 + channels[2] * 0.0722;
    };

    const foreground = parseRgb(getComputedStyle(element).color);
    let background: [number, number, number, number] = [255, 255, 255, 1];
    let current: Element | null = element;

    while (current) {
      const candidate = parseRgb(getComputedStyle(current).backgroundColor);
      if (candidate[3] > 0) {
        background = candidate;
        break;
      }
      current = current.parentElement;
    }

    const lighter = Math.max(luminance(foreground), luminance(background));
    const darker = Math.min(luminance(foreground), luminance(background));
    return (lighter + 0.05) / (darker + 0.05);
  });
}
