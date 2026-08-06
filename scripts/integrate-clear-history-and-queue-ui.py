from pathlib import Path
import re
import subprocess

REPORT_PATH = 'apps/desktop/src/features/analysis/ui/ReportHistory.tsx'

report = subprocess.check_output(
    ['git', 'show', f'origin/feature/clear-report-history:{REPORT_PATH}'],
    text=True,
)
report = report.replace(
    '    clearReports();\n    setReports([]);',
    '    setReports(clearReports());',
    1,
)
report = report.replace(
    '          className="analysis-history__confirmation card"\n          aria-labelledby=',
    '          className="analysis-history__confirmation card"\n          role="alertdialog"\n          aria-modal="true"\n          aria-labelledby=',
    1,
)
report = report.replace(
    'className="button button-secondary danger"',
    'className="button button-danger"',
    1,
)
Path(REPORT_PATH).write_text(report, encoding='utf-8')

storage_path = Path('apps/desktop/src/features/analysis/model/analysis-storage.ts')
storage = storage_path.read_text(encoding='utf-8')
storage, replaced = re.subn(
    r"export function clearReports\(\): void \{.*?\n\}",
    """export function clearReports(): AnalysisReport[] {
  if (typeof localStorage !== 'undefined') {
    localStorage.removeItem(REPORTS_KEY);
    for (const key of LEGACY_REPORT_KEYS) localStorage.removeItem(key);
  }
  return [];
}""",
    storage,
    count=1,
    flags=re.S,
)
if replaced != 1:
    raise SystemExit('clearReports не найден')
storage_path.write_text(storage, encoding='utf-8')

css_path = Path('apps/desktop/src/shared/styles/v033-bugfix.css')
css = css_path.read_text(encoding='utf-8')
marker = '/* integration: clear history and readable queue rows */'
if marker not in css:
    css += r'''

/* integration: clear history and readable queue rows */
.analysis-history__clear {
  flex: 0 0 auto;
  margin-left: auto;
  white-space: nowrap;
}
.analysis-history__confirmation {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 18px;
  border-color: rgba(239, 68, 68, .42);
  background: color-mix(in srgb, #ef4444 7%, var(--surface));
}
.analysis-history__confirmation-content {
  min-width: 0;
  display: grid;
  gap: 6px;
}
.analysis-history__confirmation-content p {
  margin: 0;
  color: var(--secondary);
  line-height: 1.5;
}
.analysis-history__confirmation-actions {
  flex: 0 0 auto;
  display: flex;
  align-items: center;
  gap: 8px;
}
.analysis-queue-item__status {
  flex: 0 0 46px;
  width: 46px;
}
.analysis-queue-item__body {
  align-self: stretch;
  min-height: 0;
  gap: 1px;
  padding: 4px 3px;
  overflow: hidden;
}
.analysis-queue-item__body strong {
  min-width: 0;
  display: -webkit-box;
  overflow: hidden;
  -webkit-box-orient: vertical;
  -webkit-line-clamp: 2;
  line-clamp: 2;
  font-size: 13px;
  line-height: 1.15;
  overflow-wrap: anywhere;
}
.analysis-queue-item__body span,
.analysis-queue-item__body small {
  min-width: 0;
  overflow: hidden;
  white-space: nowrap;
  text-overflow: ellipsis;
  font-size: 11px;
  line-height: 1.15;
}
.analysis-queue-item > .icon-button {
  flex: 0 0 34px;
  width: 34px;
  height: 34px;
  margin-right: 2px;
}
.analysis-queue-item > .icon-button svg {
  width: 17px;
  height: 17px;
}

@media (max-width: 1050px) {
  .analysis-history__clear { width: 100%; margin-left: 0; }
  .analysis-history__confirmation { align-items: stretch; flex-direction: column; }
  .analysis-history__confirmation-actions { justify-content: flex-end; }
}

@media (max-width: 560px) {
  .analysis-history__confirmation-actions { align-items: stretch; flex-direction: column-reverse; }
  .analysis-history__confirmation-actions .button { width: 100%; }
}

@media (forced-colors: active) {
  .analysis-queue-item.selected { outline: 2px solid Highlight; outline-offset: -2px; }
  .analysis-history__confirmation { border: 2px solid CanvasText; }
}
'''
css_path.write_text(css, encoding='utf-8')

unit_path = Path('apps/desktop/src/features/analysis/model/analysis-storage.test.ts')
unit = unit_path.read_text(encoding='utf-8')
unit = unit.replace(
    "import { describe, expect, it } from 'vitest';",
    "import { beforeEach, describe, expect, it } from 'vitest';",
    1,
)
unit = unit.replace(
    "import { migrateReport, sanitizeLimits } from './analysis-storage';",
    "import { clearReports, migrateReport, sanitizeLimits } from './analysis-storage';",
    1,
)
if 'beforeEach(() => localStorage.clear());' not in unit:
    unit = unit.replace(
        "import { currentReportSchemaVersion, defaultAnalysisLimits } from './types';\n",
        "import { currentReportSchemaVersion, defaultAnalysisLimits } from './types';\n\nbeforeEach(() => localStorage.clear());\n",
        1,
    )
clear_test = r'''

describe('очистка истории', () => {
  it('удаляет current и legacy отчёты, сохраняя backup и настройки', () => {
    localStorage.setItem('filescope:reports:schema-1', '[{"id":"current"}]');
    localStorage.setItem('filescope:v0.2.0:reports', '[{"id":"legacy"}]');
    localStorage.setItem('filescope:migration-backup:v0.3.3', '{"legacy":"backup"}');
    localStorage.setItem('filescope:limits:v1', '{"jobTimeoutMs":30000}');

    expect(clearReports()).toEqual([]);
    expect(localStorage.getItem('filescope:reports:schema-1')).toBeNull();
    expect(localStorage.getItem('filescope:v0.2.0:reports')).toBeNull();
    expect(localStorage.getItem('filescope:migration-backup:v0.3.3')).toBe('{"legacy":"backup"}');
    expect(localStorage.getItem('filescope:limits:v1')).toBe('{"jobTimeoutMs":30000}');
  });
});
'''
if "describe('очистка истории'" not in unit:
    index = unit.index("\ndescribe('миграция отчётов'")
    unit = unit[:index] + clear_test + unit[index:]
unit_path.write_text(unit, encoding='utf-8')

e2e_path = Path('apps/desktop/tests/e2e/app.spec.ts')
e2e = e2e_path.read_text(encoding='utf-8')
extra = r'''

test('длинное имя и ошибка помещаются внутри карточки очереди', async ({ page }) => {
  await page.getByRole('button', { name: 'Ссылки', exact: true }).click();
  await page.getByLabel('Адрес').fill('https://screen-shot-2026-08-06-102144.very-long-layout-regression-name.example.com/download');
  await page.getByRole('button', { name: 'Добавить URL в очередь' }).click();
  await page.getByRole('button', { name: 'Запустить очередь (1)' }).click();

  const row = page.locator('.analysis-queue-item').first();
  await expect(row).toHaveClass(/status-failed/);
  const layout = await row.evaluate((element) => {
    const body = element.querySelector('.analysis-queue-item__body');
    const title = body?.querySelector('strong');
    const style = title ? getComputedStyle(title) : null;
    return {
      rowHeight: element.clientHeight,
      rowScrollHeight: element.scrollHeight,
      bodyHeight: body?.clientHeight ?? 0,
      bodyScrollHeight: body?.scrollHeight ?? 0,
      lineClamp: style?.webkitLineClamp,
    };
  });

  expect(layout.rowHeight).toBeGreaterThanOrEqual(68);
  expect(layout.rowScrollHeight).toBeLessThanOrEqual(layout.rowHeight + 1);
  expect(layout.bodyScrollHeight).toBeLessThanOrEqual(layout.bodyHeight + 1);
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
  await firstDialog.getByRole('button', { name: 'Отмена' }).click();
  await expect(page.getByText('Снимок экрана 2026-08-06 102144.png')).toBeVisible();

  await page.getByRole('button', { name: 'Очистить историю', exact: true }).click();
  const confirmation = page.getByRole('alertdialog', { name: 'Очистить всю историю?' });
  await confirmation.getByRole('button', { name: 'Очистить историю' }).click();
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
'''
if 'длинное имя и ошибка помещаются внутри карточки очереди' not in e2e:
    e2e = e2e.replace('\nasync function contrastRatio', extra + '\nasync function contrastRatio', 1)
e2e_path.write_text(e2e, encoding='utf-8')

for path in [
    Path('.github/.integration-placeholder'),
    Path('docs/worklogs/v0.3.3-integration.md'),
]:
    if path.exists():
        path.unlink()
