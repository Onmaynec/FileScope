# FileScope

FileScope — desktop-приложение Veilbyte для Windows, предназначенное для понятной предварительной проверки файлов, HTTP/HTTPS URL и архивов до запуска.

> **Классификация:** Public Source-Available · Active · Pre-1.0  
> **Актуальный релиз:** `v0.2.0`  
> **Владелец:** Veilbyte · `@Onmaynec`

Исходный код доступен для просмотра и security-review, но FileScope **не является open-source проектом**. Использование, изменение, распространение, размещение и интеграция регулируются [ограниченной лицензией](LICENSE) и без отдельного письменного разрешения запрещены.

## Возможности v0.2.0

- вычисление SHA-256 выбранного файла;
- определение фактического типа по сигнатуре содержимого;
- поиск двойных расширений и несоответствия расширения формату;
- базовый разбор Windows PE: архитектура, точка входа, секции, энтропия и импорты;
- определение наличия каталога Authenticode без заявления о доверенности подписи;
- пассивный анализ HTTP/HTTPS URL без сетевого обращения;
- поиск Punycode, IP вместо домена, встроенных учётных данных, вложенных redirect-параметров и подозрительных загрузок;
- ручная активная URL-проверка с DNS и минимальным HEAD/Range-запросом;
- структурный анализ ZIP без извлечения файлов на диск;
- защита от path traversal, чрезмерной глубины, количества записей и архивных бомб;
- Rule Engine с объяснимой оценкой риска и доказательствами;
- четыре уровня результата без формулировки «100% безопасно»;
- локальная история реальных отчётов;
- экспорт отчётов в JSON и автономный HTML;
- настраиваемые, но не отключаемые защитные лимиты;
- светлая, тёмная и системная темы;
- системный трей и локальное сохранение настроек.

## Принципы безопасности

- исследуемые файлы никогда не запускаются;
- содержимое ZIP не извлекается на диск;
- пассивный URL-анализ не обращается к сети;
- активная URL-проверка запускается только после явного согласия;
- файлы и отчёты не отправляются во внешние сервисы;
- настоящие вредоносные образцы в репозитории отсутствуют;
- отсутствие обнаруженных признаков не считается абсолютной гарантией безопасности.

FileScope предназначен только для законной защиты пользователя и разрешённого исследования. Подробности: [ответственное использование](RESPONSIBLE_USE.md).

## Поддерживаемый объём

| Объект | v0.2.0 |
|---|---|
| Обычные файлы | SHA-256, сигнатура, имя, размер, энтропия |
| Windows PE | Заголовки, секции, импорты, каталог сертификатов |
| HTTP/HTTPS URL | Пассивный разбор и ручная активная проверка |
| ZIP | Дерево, размеры, глубина, пути, исполняемые файлы, вложенные архивы |
| RAR / 7Z | Распознавание формата без структурного разбора |
| Запуск в sandbox | Не входит в v0.2.0 |

## Установка

Официальные установщики и portable-сборки публикуются только в GitHub Releases организации Veilbyte. Проверяйте тег версии и SHA-256 из файла `SHA256SUMS.txt`.

Неофициальные сборки не поддерживаются и не могут использовать названия, логотипы или оформление FileScope/Veilbyte без письменного разрешения. См. [BRAND_POLICY.md](BRAND_POLICY.md).

## Локальная разработка

Требования:

- Node.js 22;
- pnpm 10.14;
- Rust stable с target `x86_64-pc-windows-msvc`;
- Microsoft C++ Build Tools и Windows SDK;
- системные зависимости Tauri 2 для Windows.

```bash
pnpm install --no-frozen-lockfile
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

## Проверки качества

```bash
pnpm --filter @filescope/desktop lint
pnpm --filter @filescope/desktop typecheck
pnpm --filter @filescope/desktop test
pnpm --filter @filescope/desktop build
pnpm --filter @filescope/desktop test:e2e
cd apps/desktop/src-tauri
cargo fmt --all --check
cargo test
cargo check
```

Официальная релизная сборка дополнительно проходит Tauri production build и Windows x64 NSIS packaging в GitHub Actions.

## Архитектура

- `apps/desktop/src/app/v020` — оболочка функциональной версии;
- `apps/desktop/src/features/analysis` — frontend API, модели, отчёты и рабочее пространство;
- `apps/desktop/src-tauri/src/analysis` — Rust-анализаторы, Rule Engine и доменные типы;
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