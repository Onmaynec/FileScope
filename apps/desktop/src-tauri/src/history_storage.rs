use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::Mutex,
};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tauri::{AppHandle, Manager, State};
use uuid::Uuid;

use crate::analysis::{AnalysisReport, REPORT_SCHEMA_VERSION};

pub const HISTORY_STORAGE_VERSION: u16 = 2;
pub const MAXIMUM_REPORTS: usize = 250;
pub const MAXIMUM_HISTORY_PAYLOAD_BYTES: usize = 8 * 1024 * 1024;
const HISTORY_DIRECTORY: &str = "history";
const GENERATION_PREFIX: &str = "reports-v2-";
const GENERATION_SUFFIX: &str = ".json";
const TEMP_SUFFIX: &str = ".tmp";
const GENERATIONS_TO_KEEP: usize = 2;

#[derive(Default)]
pub struct HistoryStorageState {
    gate: Mutex<()>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum HistoryStorageStatus {
    Ready,
    Empty,
    Corrupted,
    Unsupported,
    TooLarge,
    Unavailable,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryStorageSnapshot {
    pub reports: Vec<AnalysisReport>,
    pub status: HistoryStorageStatus,
    pub persisted: bool,
    pub size_bytes: u64,
    pub generation: Option<String>,
    pub message: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HistoryEnvelope {
    storage_version: u16,
    report_schema_version: u16,
    saved_at: String,
    reports: Vec<AnalysisReport>,
}

#[derive(Debug)]
struct HistoryStore {
    directory: PathBuf,
}

impl HistoryStore {
    fn new(directory: PathBuf) -> Self {
        Self { directory }
    }

    fn load(&self) -> HistoryStorageSnapshot {
        let generations = match self.generations() {
            Ok(value) => value,
            Err(message) => return unavailable(message),
        };
        if generations.is_empty() {
            return empty_snapshot();
        }

        for (index, path) in generations.iter().enumerate() {
            match self.read_generation(path) {
                GenerationRead::Ready(mut snapshot) => {
                    if index > 0 {
                        snapshot.message = Some(format!(
                            "Последняя генерация истории повреждена. Восстановлена предыдущая валидная копия {}.",
                            snapshot.generation.as_deref().unwrap_or("history")
                        ));
                    }
                    return snapshot;
                }
                GenerationRead::Corrupted(message) if index + 1 < generations.len() => {
                    let _ = message;
                    continue;
                }
                GenerationRead::Corrupted(message) => {
                    return HistoryStorageSnapshot {
                        reports: Vec::new(),
                        status: HistoryStorageStatus::Corrupted,
                        persisted: false,
                        size_bytes: file_size(path),
                        generation: file_name(path),
                        message: Some(message),
                    };
                }
                GenerationRead::Blocked(snapshot) => return snapshot,
            }
        }

        HistoryStorageSnapshot {
            reports: Vec::new(),
            status: HistoryStorageStatus::Corrupted,
            persisted: false,
            size_bytes: 0,
            generation: None,
            message: Some("Не удалось восстановить валидную генерацию истории.".to_string()),
        }
    }

    fn save_report(&self, report: AnalysisReport) -> HistoryStorageSnapshot {
        if report.schema_version != REPORT_SCHEMA_VERSION {
            return unsupported(format!(
                "Отчёт schemaVersion={} не соответствует поддерживаемой schemaVersion={} и не был сохранён.",
                report.schema_version, REPORT_SCHEMA_VERSION
            ));
        }
        let current = self.load();
        if !can_mutate(current.status) {
            return current;
        }
        let mut reports = Vec::with_capacity((current.reports.len() + 1).min(MAXIMUM_REPORTS));
        let id = report.id.clone();
        reports.push(report);
        reports.extend(
            current
                .reports
                .into_iter()
                .filter(|item| item.id != id)
                .take(MAXIMUM_REPORTS.saturating_sub(1)),
        );
        self.publish(reports)
    }

    fn replace_if_empty(&self, reports: Vec<AnalysisReport>) -> HistoryStorageSnapshot {
        let current = self.load();
        if current.status == HistoryStorageStatus::Ready {
            return current;
        }
        if current.status != HistoryStorageStatus::Empty {
            return current;
        }
        if reports
            .iter()
            .any(|report| report.schema_version != REPORT_SCHEMA_VERSION)
        {
            return unsupported(format!(
                "Миграция содержит отчёт неподдерживаемой schemaVersion; ожидается {}.",
                REPORT_SCHEMA_VERSION
            ));
        }
        self.publish(reports.into_iter().take(MAXIMUM_REPORTS).collect())
    }

    fn delete_report(&self, id: &str) -> HistoryStorageSnapshot {
        let current = self.load();
        if !can_mutate(current.status) {
            return current;
        }
        let reports = current
            .reports
            .into_iter()
            .filter(|report| report.id != id)
            .collect();
        self.publish(reports)
    }

    fn clear(&self) -> HistoryStorageSnapshot {
        let entries = match fs::read_dir(&self.directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return empty_snapshot(),
            Err(error) => {
                return unavailable(format!(
                    "Не удалось открыть каталог истории для удаления: {error}"
                ))
            }
        };

        let mut failures = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            if !is_history_file(&path) {
                continue;
            }
            if let Err(error) = fs::remove_file(&path) {
                failures.push(format!("{}: {error}", path.display()));
            }
        }
        if failures.is_empty() {
            empty_snapshot()
        } else {
            unavailable(format!(
                "Не удалось полностью удалить историю: {}",
                failures.join("; ")
            ))
        }
    }

    fn publish(&self, reports: Vec<AnalysisReport>) -> HistoryStorageSnapshot {
        if reports.len() > MAXIMUM_REPORTS {
            return unavailable(
                "Количество отчётов превышает внутренний лимит history store.".to_string(),
            );
        }
        if reports
            .iter()
            .any(|report| report.schema_version != REPORT_SCHEMA_VERSION)
        {
            return unsupported(
                "History store не записывает отчёты неизвестной schemaVersion.".to_string(),
            );
        }

        let envelope = HistoryEnvelope {
            storage_version: HISTORY_STORAGE_VERSION,
            report_schema_version: REPORT_SCHEMA_VERSION,
            saved_at: Utc::now().to_rfc3339(),
            reports,
        };
        let raw = match serde_json::to_vec(&envelope) {
            Ok(raw) => raw,
            Err(error) => return unavailable(format!("Не удалось сериализовать историю: {error}")),
        };
        if raw.len() > MAXIMUM_HISTORY_PAYLOAD_BYTES {
            return HistoryStorageSnapshot {
                reports: envelope.reports,
                status: HistoryStorageStatus::TooLarge,
                persisted: false,
                size_bytes: raw.len() as u64,
                generation: None,
                message: Some(format!(
                    "История превышает безопасный лимит {} байт и не была записана.",
                    MAXIMUM_HISTORY_PAYLOAD_BYTES
                )),
            };
        }

        if let Err(error) = fs::create_dir_all(&self.directory) {
            return unavailable(format!("Не удалось создать каталог истории: {error}"));
        }
        let generation = format!(
            "{GENERATION_PREFIX}{:020}-{}{GENERATION_SUFFIX}",
            Utc::now().timestamp_millis(),
            Uuid::new_v4()
        );
        let final_path = self.directory.join(&generation);
        let temp_path = self.directory.join(format!("{generation}{TEMP_SUFFIX}"));

        let write_result = (|| -> Result<(), String> {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temp_path)
                .map_err(|error| format!("Не удалось создать временную историю: {error}"))?;
            file.write_all(&raw)
                .map_err(|error| format!("Не удалось записать временную историю: {error}"))?;
            file.sync_all().map_err(|error| {
                format!("Не удалось синхронизировать временную историю: {error}")
            })?;
            drop(file);
            fs::rename(&temp_path, &final_path)
                .map_err(|error| format!("Не удалось атомарно опубликовать историю: {error}"))?;
            Ok(())
        })();

        if let Err(message) = write_result {
            let _ = fs::remove_file(&temp_path);
            return unavailable(message);
        }

        self.cleanup_old_generations();
        HistoryStorageSnapshot {
            reports: envelope.reports,
            status: if envelope.reports.is_empty() {
                HistoryStorageStatus::Empty
            } else {
                HistoryStorageStatus::Ready
            },
            persisted: true,
            size_bytes: raw.len() as u64,
            generation: Some(generation),
            message: None,
        }
    }

    fn generations(&self) -> Result<Vec<PathBuf>, String> {
        let entries = match fs::read_dir(&self.directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(format!("Не удалось прочитать каталог истории: {error}")),
        };
        let mut values = entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| is_generation_file(path))
            .collect::<Vec<_>>();
        values.sort_by(|left, right| right.file_name().cmp(&left.file_name()));
        Ok(values)
    }

    fn read_generation(&self, path: &Path) -> GenerationRead {
        let size = file_size(path);
        if size as usize > MAXIMUM_HISTORY_PAYLOAD_BYTES {
            return GenerationRead::Blocked(HistoryStorageSnapshot {
                reports: Vec::new(),
                status: HistoryStorageStatus::TooLarge,
                persisted: false,
                size_bytes: size,
                generation: file_name(path),
                message: Some(
                    "History generation превышает безопасный лимит и оставлена без изменений."
                        .to_string(),
                ),
            });
        }
        let raw = match fs::read(path) {
            Ok(raw) => raw,
            Err(error) => {
                return GenerationRead::Corrupted(format!(
                    "Не удалось прочитать generation {}: {error}",
                    path.display()
                ))
            }
        };
        let value: Value = match serde_json::from_slice(&raw) {
            Ok(value) => value,
            Err(error) => {
                return GenerationRead::Corrupted(format!(
                    "Generation истории содержит повреждённый JSON: {error}"
                ))
            }
        };
        let Some(storage_version) = value.get("storageVersion").and_then(Value::as_u64) else {
            return GenerationRead::Corrupted(
                "History generation не содержит storageVersion.".to_string(),
            );
        };
        let Some(report_schema_version) = value.get("reportSchemaVersion").and_then(Value::as_u64)
        else {
            return GenerationRead::Corrupted(
                "History generation не содержит reportSchemaVersion.".to_string(),
            );
        };
        if storage_version > HISTORY_STORAGE_VERSION as u64
            || report_schema_version > REPORT_SCHEMA_VERSION as u64
        {
            return GenerationRead::Blocked(HistoryStorageSnapshot {
                reports: Vec::new(),
                status: HistoryStorageStatus::Unsupported,
                persisted: false,
                size_bytes: size,
                generation: file_name(path),
                message: Some(format!(
                    "History generation создана более новой версией: storageVersion={storage_version}, reportSchemaVersion={report_schema_version}. Данные не перезаписаны."
                )),
            });
        }
        if storage_version != HISTORY_STORAGE_VERSION as u64
            || report_schema_version != REPORT_SCHEMA_VERSION as u64
        {
            return GenerationRead::Corrupted(format!(
                "History generation имеет неподдерживаемую старую версию: storageVersion={storage_version}, reportSchemaVersion={report_schema_version}."
            ));
        }
        let Some(reports) = value.get("reports").and_then(Value::as_array) else {
            return GenerationRead::Corrupted(
                "History generation не содержит массив reports.".to_string(),
            );
        };
        if reports.len() > MAXIMUM_REPORTS {
            return GenerationRead::Blocked(HistoryStorageSnapshot {
                reports: Vec::new(),
                status: HistoryStorageStatus::TooLarge,
                persisted: false,
                size_bytes: size,
                generation: file_name(path),
                message: Some(format!(
                    "History generation содержит {} отчётов при лимите {} и оставлена без изменений.",
                    reports.len(), MAXIMUM_REPORTS
                )),
            });
        }
        if reports.iter().any(|report| {
            report
                .get("schemaVersion")
                .and_then(Value::as_u64)
                .is_some_and(|version| version > REPORT_SCHEMA_VERSION as u64)
        }) {
            return GenerationRead::Blocked(unsupported_with_file(
                path,
                size,
                "History generation содержит report schema новее поддерживаемой.".to_string(),
            ));
        }

        let envelope: HistoryEnvelope = match serde_json::from_value(value) {
            Ok(envelope) => envelope,
            Err(error) => {
                return GenerationRead::Corrupted(format!(
                    "History generation не проходит строгую валидацию отчётов: {error}"
                ))
            }
        };
        if envelope
            .reports
            .iter()
            .any(|report| report.schema_version != REPORT_SCHEMA_VERSION)
        {
            return GenerationRead::Corrupted(
                "History generation содержит отчёт старой schemaVersion без миграции.".to_string(),
            );
        }
        GenerationRead::Ready(HistoryStorageSnapshot {
            status: if envelope.reports.is_empty() {
                HistoryStorageStatus::Empty
            } else {
                HistoryStorageStatus::Ready
            },
            reports: envelope.reports,
            persisted: true,
            size_bytes: size,
            generation: file_name(path),
            message: None,
        })
    }

    fn cleanup_old_generations(&self) {
        let Ok(generations) = self.generations() else {
            return;
        };
        for path in generations.into_iter().skip(GENERATIONS_TO_KEEP) {
            let _ = fs::remove_file(path);
        }
        let Ok(entries) = fs::read_dir(&self.directory) else {
            return;
        };
        for path in entries.filter_map(Result::ok).map(|entry| entry.path()) {
            if path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    name.starts_with(GENERATION_PREFIX) && name.ends_with(TEMP_SUFFIX)
                })
            {
                let _ = fs::remove_file(path);
            }
        }
    }
}

enum GenerationRead {
    Ready(HistoryStorageSnapshot),
    Corrupted(String),
    Blocked(HistoryStorageSnapshot),
}

#[tauri::command]
pub fn history_load(
    app: AppHandle,
    state: State<'_, HistoryStorageState>,
) -> HistoryStorageSnapshot {
    with_store(&app, &state, HistoryStore::load)
}

#[tauri::command]
pub fn history_inspect(
    app: AppHandle,
    state: State<'_, HistoryStorageState>,
) -> HistoryStorageSnapshot {
    with_store(&app, &state, HistoryStore::load)
}

#[tauri::command]
pub fn history_save_report(
    app: AppHandle,
    state: State<'_, HistoryStorageState>,
    report: AnalysisReport,
) -> HistoryStorageSnapshot {
    with_store(&app, &state, |store| store.save_report(report))
}

#[tauri::command]
pub fn history_replace_all(
    app: AppHandle,
    state: State<'_, HistoryStorageState>,
    reports: Vec<AnalysisReport>,
) -> HistoryStorageSnapshot {
    with_store(&app, &state, |store| store.replace_if_empty(reports))
}

#[tauri::command]
pub fn history_delete_report(
    app: AppHandle,
    state: State<'_, HistoryStorageState>,
    id: String,
) -> HistoryStorageSnapshot {
    with_store(&app, &state, |store| store.delete_report(&id))
}

#[tauri::command]
pub fn history_clear(
    app: AppHandle,
    state: State<'_, HistoryStorageState>,
) -> HistoryStorageSnapshot {
    with_store(&app, &state, HistoryStore::clear)
}

fn with_store(
    app: &AppHandle,
    state: &State<'_, HistoryStorageState>,
    operation: impl FnOnce(&HistoryStore) -> HistoryStorageSnapshot,
) -> HistoryStorageSnapshot {
    let _guard = match state.gate.lock() {
        Ok(guard) => guard,
        Err(_) => return unavailable("History storage lock повреждён.".to_string()),
    };
    let directory = match app.path().app_data_dir() {
        Ok(path) => path.join(HISTORY_DIRECTORY),
        Err(error) => {
            return unavailable(format!("Не удалось определить app-data каталог: {error}"))
        }
    };
    operation(&HistoryStore::new(directory))
}

fn can_mutate(status: HistoryStorageStatus) -> bool {
    matches!(
        status,
        HistoryStorageStatus::Ready | HistoryStorageStatus::Empty
    )
}

fn empty_snapshot() -> HistoryStorageSnapshot {
    HistoryStorageSnapshot {
        reports: Vec::new(),
        status: HistoryStorageStatus::Empty,
        persisted: true,
        size_bytes: 0,
        generation: None,
        message: None,
    }
}

fn unavailable(message: String) -> HistoryStorageSnapshot {
    HistoryStorageSnapshot {
        reports: Vec::new(),
        status: HistoryStorageStatus::Unavailable,
        persisted: false,
        size_bytes: 0,
        generation: None,
        message: Some(message),
    }
}

fn unsupported(message: String) -> HistoryStorageSnapshot {
    HistoryStorageSnapshot {
        reports: Vec::new(),
        status: HistoryStorageStatus::Unsupported,
        persisted: false,
        size_bytes: 0,
        generation: None,
        message: Some(message),
    }
}

fn unsupported_with_file(path: &Path, size: u64, message: String) -> HistoryStorageSnapshot {
    HistoryStorageSnapshot {
        reports: Vec::new(),
        status: HistoryStorageStatus::Unsupported,
        persisted: false,
        size_bytes: size,
        generation: file_name(path),
        message: Some(message),
    }
}

fn file_name(path: &Path) -> Option<String> {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(str::to_string)
}

fn file_size(path: &Path) -> u64 {
    fs::metadata(path)
        .map(|metadata| metadata.len())
        .unwrap_or(0)
}

fn is_generation_file(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            name.starts_with(GENERATION_PREFIX) && name.ends_with(GENERATION_SUFFIX)
        })
}

fn is_history_file(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            name.starts_with(GENERATION_PREFIX)
                && (name.ends_with(GENERATION_SUFFIX) || name.ends_with(TEMP_SUFFIX))
        })
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn publishes_and_loads_generation_without_overwriting_previous_file() {
        let temp = TempDir::new().unwrap();
        let store = HistoryStore::new(temp.path().join("history"));
        let first = store.save_report(sample_report("one"));
        assert_eq!(first.status, HistoryStorageStatus::Ready);
        assert!(first.persisted);
        let first_generation = first.generation.clone().unwrap();

        let second = store.save_report(sample_report("two"));
        assert_eq!(second.reports.len(), 2);
        assert_ne!(
            second.generation.as_deref(),
            Some(first_generation.as_str())
        );
        assert!(store.directory.join(first_generation).exists());
        assert_eq!(store.load().reports[0].id, "two");
    }

    #[test]
    fn future_generation_is_read_only_and_not_replaced_by_save() {
        let temp = TempDir::new().unwrap();
        let directory = temp.path().join("history");
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join(format!(
            "{GENERATION_PREFIX}99999999999999999999-future{GENERATION_SUFFIX}"
        ));
        let raw = serde_json::to_vec(&json!({
            "storageVersion": HISTORY_STORAGE_VERSION + 1,
            "reportSchemaVersion": REPORT_SCHEMA_VERSION + 1,
            "savedAt": "2026-08-07T00:00:00Z",
            "reports": []
        }))
        .unwrap();
        fs::write(&path, &raw).unwrap();
        let store = HistoryStore::new(directory);
        assert_eq!(store.load().status, HistoryStorageStatus::Unsupported);
        assert_eq!(
            store.save_report(sample_report("new")).status,
            HistoryStorageStatus::Unsupported
        );
        assert_eq!(fs::read(path).unwrap(), raw);
    }

    #[test]
    fn corrupted_latest_generation_recovers_previous_valid_generation() {
        let temp = TempDir::new().unwrap();
        let store = HistoryStore::new(temp.path().join("history"));
        let valid = store.save_report(sample_report("safe"));
        assert_eq!(valid.status, HistoryStorageStatus::Ready);
        let corrupt = store.directory.join(format!(
            "{GENERATION_PREFIX}99999999999999999999-corrupt{GENERATION_SUFFIX}"
        ));
        fs::write(corrupt, b"{broken").unwrap();
        let recovered = store.load();
        assert_eq!(recovered.status, HistoryStorageStatus::Ready);
        assert_eq!(recovered.reports[0].id, "safe");
        assert!(recovered
            .message
            .as_deref()
            .unwrap_or_default()
            .contains("Восстановлена"));
    }

    #[test]
    fn replace_all_only_initializes_empty_store() {
        let temp = TempDir::new().unwrap();
        let store = HistoryStore::new(temp.path().join("history"));
        let migrated = store.replace_if_empty(vec![sample_report("legacy")]);
        assert_eq!(migrated.reports[0].id, "legacy");
        let ignored = store.replace_if_empty(vec![sample_report("second")]);
        assert_eq!(ignored.reports[0].id, "legacy");
    }

    #[test]
    fn clear_removes_generations_and_temp_files() {
        let temp = TempDir::new().unwrap();
        let store = HistoryStore::new(temp.path().join("history"));
        store.save_report(sample_report("one"));
        fs::write(
            store
                .directory
                .join(format!("{GENERATION_PREFIX}orphan{TEMP_SUFFIX}")),
            b"partial",
        )
        .unwrap();
        let cleared = store.clear();
        assert_eq!(cleared.status, HistoryStorageStatus::Empty);
        assert!(store.generations().unwrap().is_empty());
        assert!(!store
            .directory
            .join(format!("{GENERATION_PREFIX}orphan{TEMP_SUFFIX}"))
            .exists());
    }

    fn sample_report(id: &str) -> AnalysisReport {
        serde_json::from_value(json!({
            "schemaVersion": REPORT_SCHEMA_VERSION,
            "appVersion": "0.4.0",
            "analyzerVersion": "test",
            "ruleSetVersion": "test",
            "createdBy": { "platform": "test", "architecture": "test", "runtime": "test" },
            "analysisCompleteness": "complete",
            "id": id,
            "objectKind": "file",
            "target": format!("C:/{id}.exe"),
            "displayName": format!("{id}.exe"),
            "startedAt": "2026-08-07T00:00:00Z",
            "completedAt": "2026-08-07T00:00:01Z",
            "durationMs": 1000,
            "riskLevel": "noThreatsFound",
            "riskScore": 0,
            "indicators": [],
            "metadata": {},
            "isDemo": false,
            "limitations": []
        }))
        .unwrap()
    }
}
