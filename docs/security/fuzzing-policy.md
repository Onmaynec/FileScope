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

Первый attempt pull request fuzz всегда использует короткий bounded budget 20 секунд на target. Явный rerun completed PR fuzz job (`runAttempt >= 2`) использует extended budget 180 секунд на target. `schedule`, `workflow_dispatch` и push специальной release-candidate ветки `fuzz-release-candidate` также используют 180 секунд на target.

Каждый target ограничен per-input timeout, максимальным размером input и RSS; весь job имеет общий timeout. Workflow работает с `contents: read`, без secrets и production Environment. Ни один extended-механизм не добавляет write permissions.

Все fuzz artifacts имеют retention не более трёх дней. Readiness/release-boundary gates автоматически проверяют все `.rs` targets в `fuzz/fuzz_targets`, их регистрацию в Cargo manifest, обязательные targets в workflow и отсутствие запрещённых side effects в target wrappers.

## Evidence длительных запусков

Успешный extended execution формирует metadata-only artifact `FileScope-fuzz-evidence-<run id>-attempt-<attempt>`. Он содержит JSON с:

- `runId` и `runAttempt`;
- logical типом события и raw GitHub event;
- source `ref`;
- source `headSha`;
- фактическим `checkoutSha`;
- budget на target;
- `conclusion=success`;
- `crashArtifacts=0`;
- точным набором всех пяти fuzz targets.

Для pull request source SHA фиксируется отдельно от PR merge SHA: release evidence использует `github.event.pull_request.head.sha`, а `checkoutSha` сохраняет фактически протестированный merge checkout. Logical event такого explicit extended rerun — `pull_request_rerun`; он разрешён только при raw event `pull_request`, `runAttempt >= 2` и source ref `feature/v0.4.0`.

Dedicated `fuzz-release-candidate` остаётся fallback-механизмом и должна только fast-forward указывать на существующий release-candidate commit. Push evidence принимается preflight только если ref строго равен `refs/heads/fuzz-release-candidate`.

Metadata artifact не содержит corpus, crash input, пользовательские данные или секреты и хранится не более трёх дней. После проверки значения переносятся в постоянный structured release evidence.

## Критерий extended readiness

Для v0.4.0 нужны минимум два независимых успешных extended execution с budget не менее 180 секунд на каждый target. Независимость определяется по паре `runId + runAttempt`, поэтому два отдельных rerun-attempt одного Actions run являются двумя отдельными execution.

Хотя бы один trusted execution обязан совпадать с `validatedHeadSha`. Trusted exact-head события: `workflow_dispatch`, explicit `pull_request_rerun` либо push `refs/heads/fuzz-release-candidate`.

Обычный PR attempt 1 не считается extended evidence независимо от количества накопившихся smoke runs.

## Обработка находок

Потенциально security-sensitive crash не публикуется публичным Issue с exploit details. Он проходит private triage: минимизация, проверка отсутствия секретов, классификация panic/OOM/hang/invariant, безопасный regression fixture и исправление root cause.

Если extended executions завершаются без находок, отсутствие нового minimized crash fixture не является незакрытым gate: private triage/fixture обязательны только при фактическом crash/hang/invariant finding. Для закрытия #49 нужны подтверждённые длительные execution без panics/hangs/OOM либо полностью обработанные найденные безопасные regressions.
