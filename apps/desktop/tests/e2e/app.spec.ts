import { expect, test } from '@playwright/test';

test.beforeEach(async ({ page }) => {
  await page.goto('/');
  await page.evaluate(() => window.localStorage.clear());
  await page.reload();
});

test('открывается функциональный главный экран v0.2.0', async ({ page }) => {
  await expect(page.getByRole('heading', { name: 'Реальный анализ до запуска' })).toBeVisible();
  await expect(page.locator('aside[aria-label="Основная навигация"]')).toBeVisible();
  await expect(page.getByText('Версия 0.2.0 · рабочая')).toBeVisible();
});

test('пассивный URL-анализ создаёт реальный локальный отчёт', async ({ page }) => {
  await page.getByRole('button', { name: /Ссылки/ }).click();
  const input = page.getByLabel('Адрес');
  await input.fill('https://login@example.com/open?redirect=https%3A%2F%2Fevil.test');
  await page.getByRole('button', { name: 'Начать анализ' }).click();

  await expect(page.getByText('Реальный локальный отчёт')).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Высокий риск' })).toBeVisible();
  await expect(page.getByText('В URL встроены учётные данные')).toBeVisible();
  await expect(page.getByText('В параметрах найден вложенный адрес')).toBeVisible();
});

test('отчёт сохраняется в локальной истории', async ({ page }) => {
  await page.getByRole('button', { name: /Ссылки/ }).click();
  await page.getByLabel('Адрес').fill('https://example.com/path');
  await page.getByRole('button', { name: 'Начать анализ' }).click();
  await expect(page.getByText('Реальный локальный отчёт')).toBeVisible();

  await page.getByRole('button', { name: /Отчёты/ }).click();
  await expect(page.getByRole('button', { name: /example.com/ })).toBeVisible();
});
