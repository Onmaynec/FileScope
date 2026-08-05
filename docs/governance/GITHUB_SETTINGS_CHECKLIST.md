# Чек-лист настроек GitHub для FileScope

Файлы репозитория не могут самостоятельно включить rulesets, security-функции, Environments и права GitHub Apps. Этот чек-лист фиксирует обязательную конфигурацию `Veilbyte/FileScope`.

## Репозиторий

- [ ] Видимость: `Public`.
- [ ] Default branch: `main`.
- [ ] Классификация в документации: `Public Source-Available`.
- [ ] Разрешён squash merge.
- [ ] Разрешён merge commit.
- [ ] Rebase merge отключён.
- [ ] Automatically delete head branches включён.
- [ ] Web commit signoff включён, если доступен.

## Ruleset для `main`

- [ ] Restrict deletions.
- [ ] Block force pushes.
- [ ] Require a pull request before merging.
- [ ] Require conversation resolution.
- [ ] Require status checks to pass.
- [ ] Require branches to be up to date before merging.
- [ ] Require signed commits.
- [ ] Запретить прямой push для обычных участников.
- [ ] Bypass оставить только владельцу для emergency-процесса.

Рекомендуемые обязательные checks:

- `Lint, типы, тесты и frontend`;
- `Rust, Windows x64 и NSIS` для release/hotfix либо всегда, если стоимость CI приемлема;
- `Структура, лицензия и процесс`.

PR в `main` разрешаются из `develop`, `release/*` и `hotfix/*`.

## Ruleset для `develop`

- [ ] Restrict deletions.
- [ ] Block force pushes.
- [ ] Require a pull request before merging.
- [ ] Require conversation resolution.
- [ ] Require status checks to pass.
- [ ] Require signed commits.
- [ ] Запретить прямой push для обычных участников.

Рекомендуемые обязательные checks:

- `Lint, типы, тесты и frontend`;
- `Rust, Windows x64 и NSIS`;
- `Структура, лицензия и процесс`.

Пока активен один разработчик, независимое approval может не требоваться, но PR и CI обязательны. После появления reviewers установить 1 approval, а для критичных путей использовать CODEOWNERS и 2 approvals либо отдельный security ruleset.

## Ruleset тегов

Для `v*`:

- [ ] запретить удаление опубликованных тегов;
- [ ] запретить force update;
- [ ] разрешить создание только владельцу и release workflow;
- [ ] использовать только SemVer `vMAJOR.MINOR.PATCH`.

## Security and analysis

- [ ] Dependency graph включён.
- [ ] Dependabot alerts включены.
- [ ] Dependabot security updates включены.
- [ ] Private Vulnerability Reporting включён.
- [ ] Secret scanning включён, если доступен плану.
- [ ] Push protection включён, если доступен плану.
- [ ] Code scanning / CodeQL включён после утверждения конфигурации языков.
- [ ] Security Advisories доступны владельцу.

## Actions

- [ ] Workflow permissions по умолчанию: Read repository contents.
- [ ] `GITHUB_TOKEN` получает write permissions только в конкретном release job.
- [ ] Actions из сторонних источников разрешаются только после review.
- [ ] Все release workflow используют фиксированные major/tag или commit SHA согласно выбранной supply-chain политике.
- [ ] Fork Pull Requests не получают secrets.
- [ ] Actions artifacts имеют ограниченный срок хранения.

## Environment `production`

- [ ] Создан Environment `production`.
- [ ] Deployment branch: только `main` и защищённые теги `v*`.
- [ ] Required reviewer: владелец либо назначенный Release Maintainer.
- [ ] Release secrets хранятся только в Environment.
- [ ] Не использовать environment secrets в обычном CI.

## Доступ

- [ ] Единственный Organization Owner — владелец Veilbyte.
- [ ] Доступ к репозиторию выдаётся по принципу минимальных прав.
- [ ] GitHub Apps имеют доступ только к нужным репозиториям.
- [ ] Outside collaborators, deploy keys, Apps, secrets и токены проверяются владельцем не реже одного раза в квартал.
- [ ] 2FA рекомендуется всем участникам.

## CODEOWNERS

Сейчас критические пути закреплены за `@Onmaynec`. После создания команд и выдачи им Write-доступа можно заменить или дополнить владельцев:

- `@Veilbyte/maintainers` — обычный код;
- `@Veilbyte/security` — Rust-анализаторы, сеть, архивы, SECURITY;
- `@Veilbyte/administrators` — `.github`, LICENSE, release workflow.

Команду нельзя указывать в CODEOWNERS, пока она не существует, не видима и не имеет явного доступа к репозиторию.

## Проверка после настройки

- [ ] Тестовый прямой push в `main` отклоняется.
- [ ] PR без обязательного check нельзя слить.
- [ ] PR с неразрешённым thread нельзя слить.
- [ ] Неподписанный commit в защищённую ветку отклоняется.
- [ ] Тег `v*` нельзя удалить или переместить обычному участнику.
- [ ] Private Vulnerability Reporting открывается из Security.
- [ ] Dependabot создаёт PR в `develop`.
- [ ] Release job не получает production secrets до разрешения Environment.