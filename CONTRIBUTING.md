# Участие в разработке FileScope

## Ветки

- `main` — только проверенные релизы;
- `develop` — интеграционная ветка;
- `feature/*` — новые функции;
- `fix/*` — исправления;
- `release/*` — подготовка релиза.

Прямой push в `main` не допускается. Изменения проходят через Pull Request.

## Перед созданием Pull Request

```bash
pnpm install --no-frozen-lockfile
pnpm --filter @filescope/desktop lint
pnpm --filter @filescope/desktop typecheck
pnpm --filter @filescope/desktop test
pnpm --filter @filescope/desktop build
pnpm --filter @filescope/desktop test:e2e
```

Для проверки нативной оболочки Windows:

```bash
pnpm --filter @filescope/desktop build:desktop
```

## Описание Pull Request

Укажите:

- цель;
- реализованные изменения;
- изменённые экраны;
- выполненные тесты;
- известные ограничения;
- скриншоты интерфейса;
- шаги ручной проверки.

## Требования к коду

- TypeScript strict mode;
- пользовательские тексты на русском и подготовка к локализации;
- UI не зависит напрямую от будущих реализаций анализаторов;
- нативные вызовы изолируются в `shared/native`;
- реальные пользовательские файлы не изменяются в версии 0.1.0;
- mock-данные имеют `isDemo: true`;
- смысл состояния не передаётся только цветом;
- все действия имеют видимый результат.

## Документация

Документация, Issues, Pull Request и release notes проекта ведутся на русском языке.
