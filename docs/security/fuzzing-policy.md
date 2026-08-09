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

Pull request smoke использует короткий bounded budget 20 секунд на target. Scheduled и ручной запуск используют расширенный bounded budget 180 секунд на target. Каждый target также ограничен per-input timeout, максимальным размером input и RSS; весь job имеет общий timeout.

Workflow работает с `contents: read`, без secrets и production Environment. Crash artifacts создаются только при ошибке и хранятся не более трёх дней. Readiness gate автоматически проверяет все `.rs` targets в `fuzz/fuzz_targets`, их регистрацию в Cargo manifest, присутствие обязательных targets в workflow и отсутствие запрещённых side effects в target wrappers.

## Обработка находок

Потенциально security-sensitive crash не публикуется публичным Issue с exploit details. Он проходит private triage: минимизация, проверка отсутствия секретов, классификация panic/OOM/hang/invariant, безопасный regression fixture и исправление root cause.

Для закрытия #49 одних PR smoke runs недостаточно: нужны подтверждённые длительные scheduled/manual runs без panics, hangs и OOM, а найденные безопасные synthetic regressions должны сохраняться как минимальные fixtures.
