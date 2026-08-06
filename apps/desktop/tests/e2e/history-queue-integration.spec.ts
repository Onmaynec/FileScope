import { expect, test } from '@playwright/test';

test.beforeEach(async ({ page }) => {
  await page.goto('/');
  await page.evaluate(() => window.localStorage.clear());
  await page.reload();
});

test('длинное имя помещается внутри виртуальной карточки очереди', async ({ page }) => {
  await page.getByRole('button', { name: 'Ссылки', exact: true }).click();
  await page
    .getByLabel('Адрес')
    .fill('https://screen-shot-2026-08-06-102144.very-long-layout-regression-name.example.com/download');
  await page.getByRole('button', { name: 'Добавить URL в очередь' }).click();

  const row = page.locator('.analysis-queue-item').first();
  await expect(row).toBeVisible();
  await expect(row).toContainText('screen-shot-2026-08-06-102144');
  await expect(row).toContainText('URL · пассивная · Ожидает');

  const layout = await row.evaluate((element) => {
    const body = element.querySelector<HTMLElement>('.analysis-queue-item__body');
    const title = body?.querySelector<HTMLElement>('strong');
    const titleStyle = title ? getComputedStyle(title) : null;

    return {
      rowHeight: element.clientHeight,
      rowScrollHeight: element.scrollHeight,
      bodyHeight: body?.clientHeight ?? 0,
      bodyScrollHeight: body?.scrollHeight ?? 0,
      titleOverflow: titleStyle?.overflow,
      lineClamp: titleStyle?.webkitLineClamp,
    };
  });

  expect(layout.rowHeight).toBeGreaterThanOrEqual(68);
  expect(layout.rowScrollHeight).toBeLessThanOrEqual(layout.rowHeight + 1);
  expect(layout.bodyScrollHeight).toBeLessThanOrEqual(layout.bodyHeight + 1);
  expect(layout.titleOverflow).toBe('hidden');
  expect(layout.lineClamp).toBe('2');
});

test('очистка истории требует подтверждение и сохраняет migration backup', async ({ page }) => {
  await page.evaluate(() => {
    const report = {
      schemaVersion: 1,
      appVersion: '0.3.3',
      analyzerVersion: '0.3.3',
      ruleSetVersion: '2026.08.06',
      createdBy: { platform: 'windows', architecture: 'x64', runtime: 'test' },
      analysisCompleteness: 'complete',
      id: 'history-clear-test',
      objectKind: 'file',
      target: 'C:/Temp/Снимок экрана 2026-08-06 102144.png',
      displayName: 'Снимок экрана 2026-08-06 102144.png',
      startedAt: '2026-08-06T10:21:44Z',
      completedAt: '2026-08-06T10:21:45Z',
      durationMs: 1000,
      sha256: 'a'.repeat(64),
      detectedType: 'PNG image',
      sizeBytes: 1024,
      riskLevel: 'noThreatsFound',
      riskScore: 0,
      indicators: [],
      metadata: {},
      isDemo: false,
      limitations: [],
    };

    localStorage.setItem('filescope:reports:schema-1', JSON.stringify([report]));
    localStorage.setItem('filescope:v0.2.0:reports', JSON.stringify([report]));
    localStorage.setItem('filescope:migration-backup:v0.3.3', '{"preserve":true}');
  });

  await page.reload();
  await page.getByRole('button', { name: 'Отчёты', exact: true }).click();
  await expect(page.getByText('Снимок экрана 2026-08-06 102144.png')).toBeVisible();

  await page.getByRole('button', { name: 'Очистить историю', exact: true }).click();
  const firstDialog = page.getByRole('alertdialog', { name: 'Очистить всю историю?' });
  await expect(firstDialog).toBeVisible();
  await firstDialog.getByRole('button', { name: 'Отмена' }).click();
  await expect(page.getByText('Снимок экрана 2026-08-06 102144.png')).toBeVisible();

  await page.getByRole('button', { name: 'Очистить историю', exact: true }).click();
  const confirmation = page.getByRole('alertdialog', { name: 'Очистить всю историю?' });
  await confirmation.getByRole('button', { name: 'Удалить все отчёты' }).click();
  await expect(page.getByRole('heading', { name: 'Отчётов пока нет' })).toBeVisible();

  const storage = await page.evaluate(() => ({
    current: localStorage.getItem('filescope:reports:schema-1'),
    legacy: localStorage.getItem('filescope:v0.2.0:reports'),
    backup: localStorage.getItem('filescope:migration-backup:v0.3.3'),
  }));

  expect(storage.current).toBeNull();
  expect(storage.legacy).toBeNull();
  expect(storage.backup).toBe('{"preserve":true}');
});
