# Политика fuzzing FileScope

## Разрешённые входы

Разрешены только synthetic/random bytes, минимальные conformance fixtures с проверенной лицензией и минимизированные невредоносные crash inputs.

Запрещены malware samples, активные вредоносные URL, credentials, tokens, пользовательские файлы и большие бинарные corpus без отдельного review.

## Безопасная граница fuzz targets

Fuzz targets не должны:

- выполнять сеть;
- запускать процессы или анализируемые файлы;
- извлекать архивы на диск;
- записывать corpus-derived данные в пользовательские каталоги;
- читать пользовательские документы/историю;
- использовать production secrets или Environment.

Разрешены bounded in-memory parser operations. Для FileScope v0.4.0 fuzz покрывает:

- `report_deserialization` — serde report contract;
- `passive_url` — URL parser/normalization/passive rules без сети;
- `rule_engine` — risk calculation и deduplication combinations;
- `file_format_pe` — file magic, Goblin PE parsing, section boundary arithmetic и entropy;
- `zip_metadata` — ZIP central-directory metadata, enclosed-path checks, depth/extension classification и compression arithmetic без extraction.

## PR smoke и длительный fuzz

Один workflow разделяет профиль по событию:

- `pull_request` — bounded smoke: 20 секунд на каждый target;
- `schedule` — long run: 600 секунд на каждый target;
- `workflow_dispatch` — long run: 600 секунд на каждый target.

Для каждого target заданы отдельный `-max_len`, `-timeout=10` и `-rss_limit_mb=1024`. Общий job имеет жёсткий timeout 75 минут.

Scheduled run выполняется еженедельно. Manual long run используется перед security-sensitive release candidate или после изменения parser family.

Workflow работает с `contents: read`, без secrets и production Environment. Crash artifacts загружаются только при failure и хранятся не более трёх дней.

## Corpus

Corpus может содержать:

- минимальные synthetic PE/ZIP/JSON fixtures;
- случайно созданные bytes;
- безопасные format-conformance fixtures с подтверждённой лицензией;
- минимизированный crash input только после проверки, что он не содержит malware, секретов или пользовательских данных.

Нельзя использовать repository corpus как склад больших бинарников. Каждый добавленный persistent fixture должен иметь понятное назначение и маленький размер.

## Private triage

Потенциально security-sensitive crash не публикуется публичным Issue с exploit details. Он проходит private triage:

1. сохранить crash artifact с коротким retention;
2. минимизировать input;
3. проверить отсутствие malware/секретов/пользовательских данных;
4. классифицировать panic, OOM, hang, parser differential или invariant failure;
5. определить affected versions и security impact;
6. добавить безопасный regression fixture/test;
7. исправить root cause;
8. только после удаления чувствительных деталей обновить публичную документацию/Issue, если это необходимо.

Для потенциальной уязвимости используется GitHub Private Vulnerability Reporting и процесс из `SECURITY.md`.

## Метрики

Для #49 и release readiness отслеживаются:

- список активных fuzz targets;
- время последнего успешного scheduled/manual long run;
- длительность профиля на target;
- число уникальных crashes/hangs;
- parser families, для которых существует target;
- regression fixtures, добавленные после найденных проблем;
- размер persistent corpus.

Процент line coverage сам по себе не считается доказательством безопасности.

## Release gate

#49 можно закрывать только когда:

- основные parser families имеют safe fuzz targets;
- PR smoke стабильно зелёный;
- scheduled/manual long profile реально выполнен хотя бы один раз на актуальном release line;
- crash artifact policy и private triage подтверждены;
- property invariants и synthetic regression cases присутствуют;
- README/CONTRIBUTING/security docs не противоречат фактическому CI.
