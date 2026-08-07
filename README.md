# FileScope

FileScope — desktop-приложение Veilbyte для Windows, предназначенное для понятной предварительной проверки файлов, HTTP/HTTPS URL и архивов до запуска.

> **Классификация:** Public Source-Available · Active · Pre-1.0  
> **Текущая стабильная версия:** `v0.3.3`  
> **Последний опубликованный релиз:** `v0.3.3`  
> **Текущая версия разработки:** `v0.4.0`  
> **Владелец:** Veilbyte · `@Onmaynec`

Исходный код доступен для просмотра и security-review, но FileScope **не является open-source проектом**. Использование, изменение, распространение, размещение и интеграция регулируются [ограниченной лицензией](LICENSE) и без отдельного письменного разрешения запрещены.

## Возможности v0.3.3

- вычисление SHA-256 выбранного файла;
- определение фактического типа по сигнатуре содержимого;
- поиск двойных расширений и несоответствия расширения формату;
- базовый разбор Windows PE: архитектура, точка входа, секции, энтропия и импорты;
- определение наличия каталога Authenticode без заявления о доверенности подписи;
- контекстная оценка PE-импортов вместо автоматического высокого риска за одиночный системный API;
- дедупликация одинаковых нормализованных признаков и защита от повторного начисления риска;
- высокий риск для полных цепочек внедрения в процесс и комбинаций загрузки с последующим запуском;
- пассивный анализ HTTP/HTTPS URL без сетевого обращения;
- поиск Punycode, IP вместо домена, встроенных учётных данных, вложенных redirect-параметров и подозрительных загрузок;
- ручная активная URL-проверка с DNS и минимальным HEAD/Range-запросом;
- структурный анализ ZIP без извлечения файлов на диск;
- защита от path traversal, чрезмерной глубины, количества записей и архивных бомб;
- явный статус частичного анализа для RAR, 7Z, повреждённых PE и остановки защитным лимитом;
- Rule Engine с объяснимой оценкой риска и доказательствами;
- четыре уровня результата без формулировки «100% безопасно»;
- локальная история реальных отчётов;
- копирование SHA-256 и краткого результата проверки;
- экспорт отчётов в JSON и автономный HTML;
- настраиваемые, но не отключаемые защитные лимиты;
- команда `pnpm doctor` для локальной диагностики окружения сборки;
- фиксированные `pnpm-lock.yaml` и `Cargo.lock` для воспроизводимых сборок;
- светлая, тёмная и системная темы;
- системный трей и локальное сохранение настроек;
- надёжное нативное сворачивание в трей по кнопке закрытия окна;
- отдельный режим полного завершения приложения;
- Windows release EXE без дополнительного консольного окна;
- единый утверждённый логотип для EXE, установщика, ярлыка, окна, панели задач и трея.

## Разработка v0.4.0

Ветка `feature/v0.4.0` развивает storage/privacy/security foundation, подготовленный в v0.3.4. Текущий кодовый scope включает:

- authoritative history backend в Rust/Tauri app-data вместо WebView `localStorage`;
- generation-based persistence через temporary write, `sync_all` и atomic rename с recovery предыдущей валидной generation;
- безопасную read-only миграцию legacy WebView history без double-write новых reports;
- настройки сохранения history и retention: текущий сеанс / 1 / 7 / 30 дней / без автоудаления;
- privacy minimization полного пути, URL credentials/query/fragment и sensitive response headers до persistence;
- Windows current-user DPAPI для новых persistent history generations без plaintext fallback;
- фактический DPAPI/plaintext/mixed status в Settings UI;
- portable policy: EXE переносим, persistent history остаётся per-user app-data и не переносится вместе с приложением;
- bounded property/fuzz testing для report serde, passive URL, Rule Engine, file/PE и ZIP metadata parser families;
- быстрый PR fuzz smoke и отдельный scheduled/manual long fuzz profile.

v0.4.0 пока **не является опубликованным релизом**. До release остаются ручная migration/crash/read-only/cross-user DPAPI проверка, фактический long fuzz run и финальный release preflight.

Подробности: [план v0.4.0](docs/product/v0.4.0-development-plan.md), [readiness checklist](docs/product/v0.4.0-readiness-checklist.md), [ручной QA](docs/product/v0.4.0-manual-qa.md), [защита history storage](docs/architecture/history-storage-protection-v040.md) и [fuzzing policy](docs/security/fuzzing-policy.md).

## BugFix v0.3.3

- активная URL-проверка блокирует private/local/metadata IPv4 и IPv6, закрепляет DNS за проверенным IP и повторно проверяет каждый redirect;
- credentials не отправляются в сеть и удаляются из evidence, истории и экспорта;
- SHA-256, сигнатура и PE-разбор формируются из одного открытого file handle;
- каталоги, symbolic links, junction и reparse points отклоняются;
- реальная backend-cancellation использует `jobId`, `JobRegistry`, deadline и ресурсные бюджеты;
- отчёты используют schema v1 с версиями приложения, анализатора и набора правил;
- legacy-история мигрируется с резервной копией исходных данных;
- native drag-and-drop добавляет файлы без автозапуска;
- тематический Select/Listbox поддерживает мышь и клавиатуру;
- master-detail очередь виртуализирована и рассчитана на 150+ объектов.

Подробности: [release notes v0.3.3](docs/releases/v0.3.3.md), [границы активной сети](docs/security/active-url-boundaries.md), [атомарность и задания](docs/architecture/atomic-analysis-and-jobs.md).

## Как интерпретируется PE-риск

FileScope не считает сам факт использования `VirtualAlloc`, `ShellExecuteW` или другого распространённого системного API доказательством вредоносности. Такие функции применяются мессенджерами, установщиками, браузерами, обновляторами и обычными desktop-приложениями.

Одинаковые API, повторённые в таблице импортов или полученные через разные DLL, нормализуются и учитываются один раз. Повтор одного и того же индикатора с теми же доказательствами не увеличивает итоговую оценку.

Высокий уровень формируется только при более сильном контексте, например:

- `VirtualAllocEx` вместе с `WriteProcessMemory` и `CreateRemoteThread`;
- сетевой API загрузки вместе с API последующего запуска;
- критическая маскировка имени, повреждённая структура или несколько независимых сильных признаков.

Отсутствие Authenticode снижает проверяемость происхождения, но само по себе не означает наличие вредоносного кода. Наличие таблицы сертификатов также не означает, что FileScope проверил цепочку доверия или имя издателя.

## Внешние антивирусные вердикты

Локальная оценка FileScope и результаты внешних антивирусных движков независимы. Единичное ML-срабатывание на новом неподписанном EXE может быть ложным положительным результатом и не может быть гарантированно устранено изменением внутренних правил FileScope.

Для официальных Windows-релизов рекомендуется:

- подписывать installer и portable EXE через Authenticode или Microsoft Artifact Signing;
- не изменять бинарный файл после подписи;
- публиковать SHA-256 вместе с релизом;
- отправлять подтверждённые ложные срабатывания через официальный портал Microsoft Security Intelligence для разработчиков ПО;
- повторно проверять новый неизменённый хеш после обработки обращения.

Подробный процесс описан в [документе о репутации Windows](docs/security/windows-reputation.md).

## Принципы безопасности

- исследуемые файлы никогда не запускаются;
- содержимое ZIP не извлекается на диск;
- пассивный URL-анализ не обращается к сети;
- активная URL-проверка запускается только после явного согласия;
- `pnpm doctor` выполняет только локальные проверки, не меняет систему и не отправляет сведения наружу;
- файлы и отчёты не отправляются во внешние сервисы;
- настоящие вредоносные образцы в репозитории отсутствуют;
- fuzz corpus не должен содержать malware, активные вредоносные URL, secrets или пользовательские файлы;
- отсутствие обнаруженных признаков не считается абсолютной гарантией безопасности.

FileScope предназначен только для законной защиты пользователя и разрешённого исследования. Подробности: [ответственное использование](RESPONSIBLE_USE.md).

## Поддерживаемый объём

| Объект | v0.3.3 |
|---|---|
| Обычные файлы | SHA-256, сигнатура, имя, размер, энтропия |
| Windows PE | Заголовки, секции, контекстные и дедуплицированные импорты, каталог сертификатов |
| HTTP/HTTPS URL | Пассивный разбор и ручная активная проверка |
| ZIP | Дерево, размеры, глубина, пути, исполняемые файлы, вложенные архивы |
| RAR / 7Z | Распознавание формата и явный статус частичного анализа без структурного разбора |
| Запуск в sandbox | Не входит в v0.3.3 |

## Поведение окна Windows

По умолчанию кнопка закрытия скрывает главное окно и оставляет FileScope в системном трее. Поведение можно изменить в разделе «Настройки → При закрытии окна».

- **Сворачивать в трей** — окно скрывается, анализатор продолжает работать;
- **Закрывать полностью** — процесс FileScope завершается;
- пункт **Выйти** в меню трея всегда полностью завершает приложение.

Официальная release-сборка запускается как Windows GUI-приложение и не открывает отдельную консоль. В debug-сборках консоль может использоваться для диагностики.

## Установка

Официальные установщики и portable-сборки публикуются только в GitHub Releases организации Veilbyte. Проверяйте тег версии и SHA-256 из файла `SHA256SUMS.txt`.

Неофициальные сборки не поддерживаются и не могут использовать названия, логотипы или оформление FileScope/Veilbyte без письменного разрешения. См. [BRAND_POLICY.md](BRAND_POLICY.md).

## Локальная разработка

Требования:

- Node.js 22;
- pnpm 10.14.0;
- Rust stable с target `x86_64-pc-windows-msvc`;
- Microsoft C++ Build Tools и Windows SDK;
- Microsoft Edge WebView2 Runtime;
- не менее 20 ГБ свободного места для первой полной Windows-сборки.

Проверка окружения без изменения системы и сетевых запросов:

```bash
pnpm doctor
```

Установка строго зафиксированных зависимостей:

```bash
pnpm install --frozen-lockfile
pnpm dev
```

Запуск desktop-оболочки:

```bash
pnpm --filter @filescope/desktop tauri dev
```

Сборка Windows-приложения:

```bash
pnpm --filter @filescope/desktop build:desktop
```

Перед запуском и production-сборкой Tauri автоматически генерирует Windows iconset из `apps/desktop/src-tauri/icons/filescope-logo.svg`.

## Проверки качества

```bash
pnpm install --frozen-lockfile
node --check scripts/doctor.mjs
pnpm --filter @filescope/desktop lint
pnpm --filter @filescope/desktop typecheck
pnpm --filter @filescope/desktop test
pnpm --filter @filescope/desktop build
pnpm --filter @filescope/desktop test:e2e
cd apps/desktop/src-tauri
cargo fmt --all --check
cargo test --locked
cargo check --locked
```

После установки зависимостей и production-сборки `pnpm-lock.yaml` и `apps/desktop/src-tauri/Cargo.lock` не должны изменяться. Официальная релизная сборка дополнительно проходит Tauri production build и Windows x64 NSIS packaging в GitHub Actions.

Security-sensitive parser changes дополнительно проходят cargo-fuzz. PR использует 20-секундный smoke на target; scheduled/manual профиль использует 600 секунд на target. Активные targets: `report_deserialization`, `passive_url`, `rule_engine`, `file_format_pe`, `zip_metadata`. Подробные ограничения corpus, ресурсов и private triage находятся в [fuzzing policy](docs/security/fuzzing-policy.md).

## Архитектура

- `apps/desktop/src/app/v020` — оболочка функциональной версии;
- `apps/desktop/src/features/analysis` — frontend API, модели, отчёты и рабочее пространство;
- `apps/desktop/src-tauri/src/analysis` — Rust-анализаторы, Rule Engine и доменные типы;
- `apps/desktop/src-tauri/src/history_storage.rs` — authoritative generation-based history store;
- `apps/desktop/src-tauri/src/history_protection.rs` — Windows current-user DPAPI boundary для persistent history;
- `apps/desktop/src-tauri/src/window_lifecycle.rs` — нативная политика закрытия окна;
- `apps/desktop/src-tauri/icons/filescope-logo.svg` — единый исходник иконок Windows;
- `scripts/doctor.mjs` — локальная диагностика окружения сборки;
- `scripts/check-v040-readiness.mjs` — автоматическая проверка storage/DPAPI/fuzzing release invariants;
- `docs/architecture` — архитектурные решения;
- `docs/product` — границы версий;
- `docs/design-system` — дизайн- и motion-система.

## Ветки и изменения

```text
main
├── develop
├── feature/*
├── fix/*
├── release/*
├── hotfix/*
└── chore/*
```

Прямые изменения в `main` и `develop` запрещены. Работа проходит по схеме:

```text
Issue → рабочая ветка → Pull Request → CI → Review → Merge
```

Полные правила находятся в [REPOSITORY_POLICY.md](REPOSITORY_POLICY.md) и [CONTRIBUTING.md](CONTRIBUTING.md).

## Участие

Перед Pull Request прочитайте:

- [CONTRIBUTING.md](CONTRIBUTING.md);
- [CONTRIBUTOR_LICENSE_AGREEMENT.md](CONTRIBUTOR_LICENSE_AGREEMENT.md);
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md);
- [SECURITY.md](SECURITY.md);
- [RESPONSIBLE_USE.md](RESPONSIBLE_USE.md).

Вклады принимаются только через Pull Request, должны быть связаны с Issue, проходить обязательные проверки и подтверждать CLA.

## Безопасность и поддержка

Не публикуйте уязвимости в Issues, Discussions или обычных Pull Requests. Используйте GitHub Private Vulnerability Reporting согласно [SECURITY.md](SECURITY.md).

Для воспроизводимых ошибок и запросов функций используйте Issue Forms. Общие правила поддержки описаны в [SUPPORT.md](SUPPORT.md).

## Лицензия

Copyright © 2026 Veilbyte and its owner. All rights reserved.

FileScope распространяется по **Veilbyte Restricted Source License 1.0**. Это ограниченная source-available лицензия, а не open-source лицензия. Полные условия: [LICENSE](LICENSE).