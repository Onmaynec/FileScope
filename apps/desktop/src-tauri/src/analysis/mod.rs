mod archive;
mod file;
#[cfg(feature = "fuzzing")]
pub mod fuzzing;
mod jobs;
#[cfg(test)]
mod properties;
mod rules;
mod types;
mod url;

use std::{fs::Metadata, path::PathBuf};

use serde::Serialize;
use serde_json::{json, Value};
use tauri::State;

pub use jobs::{AnalysisFailure, JobRegistry};
pub use types::{AnalysisLimits, AnalysisReport};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalObjectCandidate {
    path: String,
    display_name: String,
    accepted: bool,
    reason: Option<String>,
}

#[tauri::command]
pub async fn analyze_local_file(
    job_id: String,
    path: String,
    limits: Option<AnalysisLimits>,
    registry: State<'_, JobRegistry>,
) -> Result<AnalysisReport, AnalysisFailure> {
    let limits = limits.unwrap_or_default().validated()?;
    let applied_limits = limits.clone();
    let token = registry.start(&job_id, limits.job_timeout_ms)?;
    let joined =
        tauri::async_runtime::spawn_blocking(move || file::analyze_file(path, limits, &token))
            .await;
    registry.finish(&job_id);
    let mut report = joined.map_err(|error| {
        AnalysisFailure::new(
            jobs::AnalysisFailureCode::Internal,
            format!("Фоновое файловое задание завершилось аварийно: {error}"),
        )
    })??;
    attach_applied_limits(&mut report, &applied_limits);
    Ok(report)
}

#[tauri::command]
pub async fn analyze_local_archive(
    job_id: String,
    path: String,
    limits: Option<AnalysisLimits>,
    registry: State<'_, JobRegistry>,
) -> Result<AnalysisReport, AnalysisFailure> {
    let limits = limits.unwrap_or_default().validated()?;
    let applied_limits = limits.clone();
    let token = registry.start(&job_id, limits.job_timeout_ms)?;
    let joined =
        tauri::async_runtime::spawn_blocking(move || archive::analyze_zip(path, limits, &token))
            .await;
    registry.finish(&job_id);
    let mut report = joined.map_err(|error| {
        AnalysisFailure::new(
            jobs::AnalysisFailureCode::Internal,
            format!("Фоновое архивное задание завершилось аварийно: {error}"),
        )
    })??;
    attach_applied_limits(&mut report, &applied_limits);
    Ok(report)
}

#[tauri::command]
pub fn analyze_url_passive(
    job_id: String,
    url: String,
    registry: State<'_, JobRegistry>,
) -> Result<AnalysisReport, AnalysisFailure> {
    let timeout_ms = AnalysisLimits::default().validated()?.job_timeout_ms;
    let token = registry.start(&job_id, timeout_ms)?;
    let result = url::analyze_url_passive(url, &token);
    registry.finish(&job_id);
    result
}

#[tauri::command]
pub async fn analyze_url_active(
    job_id: String,
    url: String,
    limits: Option<AnalysisLimits>,
    registry: State<'_, JobRegistry>,
) -> Result<AnalysisReport, AnalysisFailure> {
    let limits = limits.unwrap_or_default().validated()?;
    let applied_limits = limits.clone();
    let token = registry.start(&job_id, limits.job_timeout_ms)?;
    let result = url::analyze_url_active(url, limits, &token).await;
    registry.finish(&job_id);
    let mut report = result?;
    attach_applied_limits(&mut report, &applied_limits);
    Ok(report)
}

#[tauri::command]
pub fn cancel_analysis(job_id: String, registry: State<'_, JobRegistry>) -> bool {
    registry.cancel(&job_id)
}

#[tauri::command]
pub fn inspect_local_paths(paths: Vec<String>, archive_only: bool) -> Vec<LocalObjectCandidate> {
    paths
        .into_iter()
        .take(2_000)
        .map(|path| inspect_local_path(path, archive_only))
        .collect()
}

#[tauri::command]
pub fn get_analysis_metadata() -> Value {
    json!({
        "schemaVersion": types::REPORT_SCHEMA_VERSION,
        "appVersion": types::app_version(),
        "analyzerVersion": types::ANALYZER_VERSION,
        "ruleSetVersion": types::RULE_SET_VERSION,
    })
}

fn attach_applied_limits(report: &mut AnalysisReport, limits: &AnalysisLimits) {
    let applied = json!({
        "maximumFileSizeBytes": limits.maximum_file_size_bytes,
        "maximumReadBytes": limits.maximum_read_bytes,
        "maximumParserMemoryBytes": limits.maximum_parser_memory_bytes,
        "jobTimeoutMs": limits.job_timeout_ms,
        "maximumArchiveEntries": limits.maximum_archive_entries,
        "maximumArchiveUncompressedBytes": limits.maximum_archive_uncompressed_bytes,
        "maximumArchiveDepth": limits.maximum_archive_depth,
        "maximumCompressionRatio": limits.maximum_compression_ratio,
        "activeUrlTimeoutMs": limits.active_url_timeout_ms,
        "activeUrlRedirectLimit": limits.active_url_redirect_limit,
    });
    if let Some(metadata) = report.metadata.as_object_mut() {
        metadata.insert("appliedLimits".to_string(), applied);
    }
}

fn inspect_local_path(path: String, archive_only: bool) -> LocalObjectCandidate {
    let file_path = PathBuf::from(&path);
    let display_name = file_path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("объект")
        .to_string();
    let metadata = std::fs::symlink_metadata(&file_path);
    let reason = match metadata {
        Err(_) => Some("Объект недоступен или больше не существует.".to_string()),
        Ok(metadata) if metadata.file_type().is_symlink() || is_reparse_point(&metadata) => {
            Some("Ссылки, junction и reparse points не добавляются в очередь.".to_string())
        }
        Ok(metadata) if !metadata.is_file() => {
            Some("Каталоги и специальные объекты не поддерживаются.".to_string())
        }
        Ok(_) if archive_only && !is_zip_path(&file_path) => {
            Some("В режиме архивов через drop принимаются только ZIP-файлы.".to_string())
        }
        Ok(_) => None,
    };
    LocalObjectCandidate {
        path,
        display_name,
        accepted: reason.is_none(),
        reason,
    }
}

fn is_zip_path(path: &std::path::Path) -> bool {
    path.extension()
        .and_then(|value| value.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("zip"))
}

#[cfg(windows)]
fn is_reparse_point(metadata: &Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & 0x0400 != 0
}

#[cfg(not(windows))]
fn is_reparse_point(_metadata: &Metadata) -> bool {
    false
}
