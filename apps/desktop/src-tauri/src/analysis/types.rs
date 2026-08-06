use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const REPORT_SCHEMA_VERSION: u16 = 1;
pub const ANALYZER_VERSION: &str = "1.1";
pub const RULE_SET_VERSION: &str = "2026.08.06.1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ObjectKind {
    File,
    Url,
    Archive,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub enum RiskLevel {
    NoThreatsFound,
    Caution,
    HighRisk,
    Dangerous,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum IndicatorSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum AnalysisCompleteness {
    Complete,
    Partial,
    StoppedByLimit,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CreatedBy {
    pub platform: String,
    pub architecture: String,
    pub runtime: String,
}

impl Default for CreatedBy {
    fn default() -> Self {
        Self {
            platform: std::env::consts::OS.to_string(),
            architecture: std::env::consts::ARCH.to_string(),
            runtime: "tauri-desktop".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ThreatIndicator {
    pub id: String,
    pub title: String,
    pub description: String,
    pub category: String,
    pub severity: IndicatorSeverity,
    pub score: u16,
    pub evidence: Vec<String>,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct PeSection {
    pub name: String,
    pub virtual_size: u64,
    pub raw_size: u64,
    pub entropy: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct PeAnalysis {
    pub architecture: String,
    pub entry_point: u64,
    pub sections: Vec<PeSection>,
    pub imports: Vec<String>,
    pub suspicious_imports: Vec<String>,
    pub signature_present: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct UrlAnalysis {
    pub normalized_url: String,
    pub scheme: String,
    pub host: String,
    pub ascii_host: String,
    pub unicode_host: String,
    pub registrable_domain: Option<String>,
    pub port: Option<u16>,
    pub path: String,
    pub query_parameters: usize,
    pub contains_punycode: bool,
    pub host_is_ip: bool,
    pub has_credentials: bool,
    pub subdomain_count: usize,
    pub redirect_parameters: Vec<String>,
    pub resolved_addresses: Vec<String>,
    pub final_url: Option<String>,
    pub status_code: Option<u16>,
    pub response_headers: Vec<(String, String)>,
    pub redirect_count: Option<usize>,
    pub active_check_performed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ArchiveEntry {
    pub path: String,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    pub depth: usize,
    pub is_directory: bool,
    pub is_executable: bool,
    pub is_archive: bool,
    pub suspicious_path: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ArchiveAnalysis {
    pub format: String,
    pub entries: Vec<ArchiveEntry>,
    pub total_entries: usize,
    pub total_compressed_size: u64,
    pub total_uncompressed_size: u64,
    pub maximum_depth: usize,
    pub compression_ratio: f64,
    pub nested_archives: usize,
    pub executable_entries: usize,
    pub suspicious_paths: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisReport {
    pub schema_version: u16,
    pub app_version: String,
    pub analyzer_version: String,
    pub rule_set_version: String,
    pub created_by: CreatedBy,
    pub analysis_completeness: AnalysisCompleteness,
    pub id: String,
    pub object_kind: ObjectKind,
    pub target: String,
    pub display_name: String,
    pub started_at: String,
    pub completed_at: String,
    pub duration_ms: u128,
    pub sha256: Option<String>,
    pub detected_type: Option<String>,
    pub size_bytes: Option<u64>,
    pub risk_level: RiskLevel,
    pub risk_score: u16,
    pub indicators: Vec<ThreatIndicator>,
    pub metadata: Value,
    pub pe: Option<PeAnalysis>,
    pub url: Option<UrlAnalysis>,
    pub archive: Option<ArchiveAnalysis>,
    pub is_demo: bool,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AnalysisLimits {
    pub maximum_file_size_bytes: u64,
    pub maximum_read_bytes: u64,
    pub maximum_parser_memory_bytes: u64,
    pub job_timeout_ms: u64,
    pub maximum_archive_entries: usize,
    pub maximum_archive_uncompressed_bytes: u64,
    pub maximum_archive_depth: usize,
    pub maximum_compression_ratio: f64,
    pub active_url_timeout_ms: u64,
    pub active_url_redirect_limit: usize,
}

impl Default for AnalysisLimits {
    fn default() -> Self {
        Self {
            maximum_file_size_bytes: 512 * 1024 * 1024,
            maximum_read_bytes: 512 * 1024 * 1024,
            maximum_parser_memory_bytes: 128 * 1024 * 1024,
            job_timeout_ms: 120_000,
            maximum_archive_entries: 10_000,
            maximum_archive_uncompressed_bytes: 2 * 1024 * 1024 * 1024,
            maximum_archive_depth: 12,
            maximum_compression_ratio: 150.0,
            active_url_timeout_ms: 8_000,
            active_url_redirect_limit: 5,
        }
    }
}

pub fn app_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

pub fn report_created_by() -> CreatedBy {
    CreatedBy::default()
}
