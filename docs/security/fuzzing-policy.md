# Политика fuzzing FileScope

Разрешены только synthetic/random bytes, минимальные conformance fixtures с проверенной лицензией и минимизированные невредоносные crash inputs.

Запрещены malware samples, активные вредоносные URL, credentials, tokens, пользовательские файлы и большие бинарные corpus без review.

## Активные fuzz-направления

Cargo-fuzz покрывает пять bounded parser families:

- `report_deserialization` — serde/deserialization сохранённых `AnalysisReport`;
- `passive_url` — пассивный URL parsing/normalization без сети;
- `rule_engine` — bounded combinations indicators/evidence и расчёт риска;
- `file_format_and_pe` — magic/type detection и Goblin PE parsing с ограничением sections/imports;
- `zip_metadata` — ZIP central-directory metadata, path handling, depth и saturating size arithmetic без извлечения на диск.

HTML export escaping закреплён отдельным frontend regression-набором с synthetic `<script>`, `<img>`, `<svg>`, closing-tag и entity payloads. Fuzz targets не выполняют сеть, процессы, извлечение архивов или запись в пользовательские каталоги.

## CI budgets и права

Pull request smoke использует короткий bounded budget 20 секунд на target. `schedule`, `workflow_dispatch` и push специальной release-candidate ветки `fuzz-release-candidate` используют расширенный bounded budget 180 секунд на target. Каждый target также ограничен per-input timeout, максимальным размером input и RSS; весь job имеет общий timeout.

Workflow работает с `contents: read`, без secrets и production Environment. Все fuzz artifacts имеют retention не более трёх дней. Readiness/release-boundary gates автоматически проверяют все `.rs` targets в `fuzz/fuzz_targets`, их регистрацию в Cargo manifest, обязательные targets в workflow и отсутствие запрещённых side effects в target wrappers.

Dedicated `fuzz-release-candidate` не является веткой разработки: она должна только fast-forward указывать на уже существующий release-candidate commit. Push evidence принимается release-preflight только если `ref` строго равен `refs/heads/fuzz-release-candidate`.

## Evidence длительных запусков

Успешный `schedule`, `workflow_dispatch` или dedicated release-candidate push формирует metadata-only artifact `FileScope-fuzz-evidence-<run id>`. Он содержит JSON с:

- `runId` и `runAttempt`;
- типом события и `ref`;
- `headSha`;
- фактическим budget на target;
- `conclusion=success`;
- `crashArtifacts=0`;
- точным набором всех пяти fuzz targets.

Metadata artifact не содержит corpus, crash input, пользовательские данные или секреты и, как и остальные fuzz artifacts, хранится не более трёх дней. После проверки его значения переносятся в постоянный structured release evidence; transient artifact не является единственным источником release-доказательства.

Финальный/automated release evidence для v0.4.0 требует минимум два независимых успешных extended run с budget не менее 180 секунд на каждый target. Хотя бы один trusted run обязан совпадать с `validatedHeadSha`; trusted exact-head события — `workflow_dispatch` либо push `refs/heads/fuzz-release-candidate`. PR smoke run не считается extended evidence независимо от количества накопившихся PR запусков.

## Обработка находок

Потенциально security-sensitive crash не публикуется публичным Issue с exploit details. Он проходит private triage: минимизация, проверка отсутствия секретов, классификация panic/OOM/hang/invariant, безопасный regression fixture и исправление root cause.

Если extended runs завершаются без находок, отсутствие нового minimized crash fixture не является незакрытым gate: private triage/fixture обязательны только при фактическом crash/hang/invariant finding. Для закрытия #49 нужны подтверждённые длительные runs без panics/hangs/OOM либо полностью обработанные найденные безопасные regressions.
