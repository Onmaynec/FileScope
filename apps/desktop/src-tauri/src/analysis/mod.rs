mod archive;
mod file;
mod jobs;
mod rules;
mod types;
mod url;

use serde_json::{json, Value};
use tauri::State;

pub use jobs::{AnalysisFailure, JobRegistry};
pub use types::{AnalysisLimits, AnalysisReport};

#[tauri::command]
pub async fn analyze_local_file(
    job_id: String,
    path: String,
    limits: Option<AnalysisLimits>,
    registry: State<'_, JobRegistry>,
) -> Result<AnalysisReport, AnalysisFailure> {
    let limits = limits.unwrap_or_default();
    let token = registry.start(&job_id, limits.job_timeout_ms)?;
    let result = tauri::async_runtime::spawn_blocking(move || file::analyze_file(path, limits, &token))
        .await
        .map_err(|error| {
            AnalysisFailure::new(
                jobs::AnalysisFailureCode::Internal,
                format!("Фоновое файловое задание завершилось аварийно: {error}"),
            )
        })?;
    registry.finish(&job_id);
    result
}

#[tauri::command]
pub async fn analyze_local_archive(
    job_id: String,
    path: String,
    limits: Option<AnalysisLimits>,
    registry: State<'_, JobRegistry>,
) -> Result<AnalysisReport, AnalysisFailure> {
    let limits = limits.unwrap_or_default();
    let token = registry.start(&job_id, limits.job_timeout_ms)?;
    let result = tauri::async_runtime::spawn_blocking(move || archive::analyze_zip(path, limits, &token))
        .await
        .map_err(|error| {
            AnalysisFailure::new(
                jobs::AnalysisFailureCode::Internal,
                format!("Фоновое архивное задание завершилось аварийно: {error}"),
            )
        })?;
    registry.finish(&job_id);
    result
}

#[tauri::command]
pub fn analyze_url_passive(
    job_id: String,
    url: String,
    registry: State<'_, JobRegistry>,
) -> Result<AnalysisReport, AnalysisFailure> {
    let token = registry.start(&job_id, AnalysisLimits::default().job_timeout_ms)?;
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
    let limits = limits.unwrap_or_default();
    let token = registry.start(&job_id, limits.job_timeout_ms)?;
    let result = url::analyze_url_active(url, limits, &token).await;
    registry.finish(&job_id);
    result
}

#[tauri::command]
pub fn cancel_analysis(job_id: String, registry: State<'_, JobRegistry>) -> bool {
    registry.cancel(&job_id)
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
