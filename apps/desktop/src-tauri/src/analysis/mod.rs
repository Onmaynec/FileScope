mod archive;
mod file;
mod rules;
mod types;
mod url;

pub use types::{AnalysisLimits, AnalysisReport};

#[tauri::command]
pub fn analyze_local_file(
    path: String,
    limits: Option<AnalysisLimits>,
) -> Result<AnalysisReport, String> {
    file::analyze_file(path, limits.unwrap_or_default())
}

#[tauri::command]
pub fn analyze_local_archive(
    path: String,
    limits: Option<AnalysisLimits>,
) -> Result<AnalysisReport, String> {
    archive::analyze_zip(path, limits.unwrap_or_default())
}

#[tauri::command]
pub fn analyze_url_passive(url: String) -> Result<AnalysisReport, String> {
    url::analyze_url_passive(url)
}

#[tauri::command]
pub async fn analyze_url_active(
    url: String,
    limits: Option<AnalysisLimits>,
) -> Result<AnalysisReport, String> {
    url::analyze_url_active(url, limits.unwrap_or_default()).await
}
