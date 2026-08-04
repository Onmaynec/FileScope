import { expect, test } from '@playwright/test';

test.beforeEach(async ({ page }) => {
  await page.goto('/');
  await page.evaluate(() => window.localStorage.clear());
  await page.reload();
});

test('пользователь завершает onboarding и открывает главный экран', async ({ page }) => {
  await expect(page.getByRole('heading', { name: 'FileScope' })).toBeVisible();
  await page.getByRole('button', { name: 'Начать' }).click();
  await expect(page.getByRole('heading', { name: 'Проверяйте до запуска' })).toBeVisible();
  await page.getByRole('button', { name: /Продолжить/ }).click();
  await expect(page.getByRole('heading', { name: 'Ваши данные остаются на устройстве' })).toBeVisible();
  await page.getByRole('button', { name: /Продолжить/ }).click();
  await page.getByRole('checkbox', { name: 'Я понимаю' }).check();
  await page.getByRole('button', { name: /Продолжить/ }).click();
  await page.getByRole('button', { name: 'Открыть FileScope' }).click();

  await expect(page.getByRole('heading', { name: 'Проверка ссылок, файлов и архивов до запуска' })).toBeVisible();
  await expect(page.getByRole('navigation', { name: 'Основная навигация' })).toBeVisible();
});

test('демонстрационный отчёт открывается без реального анализа', async ({ page }) => {
  await page.evaluate(() => window.localStorage.setItem('filescope.preferences.v1', JSON.stringify({ onboardingCompleted: true })));
  await page.reload();
  await page.getByRole('button', { name: /Отчёты/ }).click();
  await page.getByRole('button', { name: /demo-malware.exe/ }).click();

  await expect(page.getByRole('heading', { name: 'Опасный объект' })).toBeVisible();
  await expect(page.getByText('Демонстрационные данные').first()).toBeVisible();
  await expect(page.getByText('isDemo')).toBeVisible();
});
