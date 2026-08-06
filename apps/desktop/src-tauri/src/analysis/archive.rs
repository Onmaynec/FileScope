use std::{
    fs::{File, Metadata, OpenOptions},
    path::{Path, PathBuf},
    time::Instant,
};

use chrono::Utc;
use serde_json::json;
use uuid::Uuid;
use zip::ZipArchive;

use super::{
    jobs::{AnalysisFailure, AnalysisFailureCode, JobToken},
    rules::{calculate_risk, indicator},
    types::{
        app_version, report_created_by, AnalysisCompleteness, AnalysisLimits, AnalysisReport,
        ArchiveAnalysis, ArchiveEntry, IndicatorSeverity, ObjectKind, ThreatIndicator,
        ANALYZER_VERSION, REPORT_SCHEMA_VERSION, RULE_SET_VERSION,
    },
};

const EXECUTABLE_EXTENSIONS: &[&str] = &[
    "exe", "dll", "scr", "com", "bat", "cmd", "ps1", "msi", "js", "jse", "vbs", "vbe", "wsf",
    "hta", "lnk", "cpl",
];
const ARCHIVE_EXTENSIONS: &[&str] = &["zip", "rar", "7z", "tar", "gz", "bz2", "xz", "cab"];
const DECOY_EXTENSIONS: &[&str] = &[
    "pdf", "doc", "docx", "xls", "xlsx", "jpg", "jpeg", "png", "gif", "txt", "mp3", "mp4",
];

pub fn analyze_zip(
    path: String,
    limits: AnalysisLimits,
    token: &JobToken,
) -> Result<AnalysisReport, AnalysisFailure> {
    token.checkpoint()?;
    let started = Instant::now();
    let started_at = Utc::now();
    let file_path = PathBuf::from(&path);

    if is_unc_path(&path) {
        return Err(AnalysisFailure::new(
            AnalysisFailureCode::UnsupportedObject,
            "UNC и сетевые пути не анализируются: удалённая файловая система не гарантирует локальную семантику identity и share mode.",
        ));
    }
    reject_special_path(&file_path)?;
    let file = open_archive_for_analysis(&file_path)?;
    let metadata_before = file.metadata().map_err(|error| {
        AnalysisFailure::io(format!(
            "Не удалось получить сведения об открытом ZIP-архиве: {error}"
        ))
    })?;
    if !metadata_before.is_file() || is_reparse_point(&metadata_before) {
        return Err(AnalysisFailure::new(
            AnalysisFailureCode::UnsupportedObject,
            "Для анализа архива требуется обычный локальный файл, а не каталог, ссылка или reparse point.",
        ));
    }
    if metadata_before.len() > limits.maximum_file_size_bytes
        || metadata_before.len() > limits.maximum_read_bytes
    {
        return Err(AnalysisFailure::new(
            AnalysisFailureCode::ReadLimit,
            format!(
                "Размер архива превышает защитный лимит {} байт.",
                limits
                    .maximum_file_size_bytes
                    .min(limits.maximum_read_bytes)
            ),
        ));
    }

    let display_name = file_path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("архив.zip")
        .to_string();
    let mut archive = ZipArchive::new(file).map_err(|error| {
        AnalysisFailure::parse(format!(
            "Файл не является поддерживаемым ZIP-архивом: {error}"
        ))
    })?;
    let mut indicators: Vec<ThreatIndicator> = Vec::new();
    let mut entries = Vec::new();
    let mut total_compressed = 0_u64;
    let mut total_uncompressed = 0_u64;
    let mut maximum_depth = 0_usize;
    let mut nested_archives = 0_usize;
    let mut executable_entries = 0_usize;
    let mut suspicious_paths = 0_usize;
    let archive_count = archive.len();

    if archive_count > limits.maximum_archive_entries {
        indicators.push(limit_indicator(
            "archive.entries.limit-exceeded",
            "Количество элементов превышает лимит анализа",
            vec![
                format!("Элементов: {archive_count}"),
                format!("Лимит анализа: {}", limits.maximum_archive_entries),
            ],
        ));
    }

    let scan_count = archive_count.min(limits.maximum_archive_entries);
    for index in 0..scan_count {
        token.checkpoint()?;
        let entry = archive.by_index(index).map_err(|error| {
            AnalysisFailure::parse(format!("Не удалось прочитать запись ZIP #{index}: {error}"))
        })?;
        let name = entry.name().replace('\\', "/");
        let depth = name.split('/').filter(|part| !part.is_empty()).count();
        let suspicious_path = entry.enclosed_name().is_none()
            || name.starts_with('/')
            || name.contains("../")
            || name.contains(":/")
            || name.contains(':');
        let extension = PathBuf::from(&name)
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let is_executable = EXECUTABLE_EXTENSIONS.contains(&extension.as_str());
        let is_archive = ARCHIVE_EXTENSIONS.contains(&extension.as_str());

        if suspicious_path {
            suspicious_paths += 1;
        }
        if is_executable {
            executable_entries += 1;
        }
        if is_archive {
            nested_archives += 1;
        }
        maximum_depth = maximum_depth.max(depth);
        total_compressed = total_compressed.saturating_add(entry.compressed_size());
        total_uncompressed = total_uncompressed.saturating_add(entry.size());

        if total_uncompressed > limits.maximum_archive_uncompressed_bytes.saturating_mul(2) {
            return Err(AnalysisFailure::new(
                AnalysisFailureCode::MemoryLimit,
                "Обход ZIP остановлен: заявленный распакованный объём превысил жёсткий ресурсный бюджет.",
            ));
        }

        if has_double_extension(&name) {
            indicators.push(indicator(
                "archive.entry.double-extension",
                "Файл внутри архива маскируется двойным расширением",
                "Запись выглядит как документ или медиафайл, но заканчивается исполняемым расширением.",
                "archive-entry",
                IndicatorSeverity::Critical,
                65,
                vec![name.clone()],
                "Не извлекайте и не запускайте этот файл.",
            ));
        }

        entries.push(ArchiveEntry {
            path: name,
            compressed_size: entry.compressed_size(),
            uncompressed_size: entry.size(),
            depth,
            is_directory: entry.is_dir(),
            is_executable,
            is_archive,
            suspicious_path,
        });
    }

    token.checkpoint()?;
    let file = archive.into_inner();
    let metadata_after = file.metadata().map_err(|error| {
        AnalysisFailure::io(format!(
            "Не удалось повторно проверить открытый ZIP-архив: {error}"
        ))
    })?;
    if file_changed(&metadata_before, &metadata_after) {
        return Err(AnalysisFailure::file_changed());
    }

    let (compression_ratio, compression_ratio_infinite) =
        safe_compression_ratio(total_compressed, total_uncompressed);

    if suspicious_paths > 0 {
        indicators.push(indicator(
            "archive.path-traversal",
            "Обнаружены опасные пути внутри архива",
            "Некоторые записи могут попытаться выйти за выбранную папку распаковки или использовать абсолютный путь.",
            "archive-path",
            IndicatorSeverity::Critical,
            70,
            entries
                .iter()
                .filter(|entry| entry.suspicious_path)
                .take(20)
                .map(|entry| entry.path.clone())
                .collect(),
            "Не распаковывайте архив. Используйте изолированный просмотр или удалите объект.",
        ));
    }
    if executable_entries > 0 {
        indicators.push(indicator(
            "archive.executable-content",
            "Архив содержит исполняемые файлы",
            "Внутри обнаружены объекты, способные запускать код или команды в Windows.",
            "archive-content",
            IndicatorSeverity::High,
            34,
            entries
                .iter()
                .filter(|entry| entry.is_executable)
                .take(30)
                .map(|entry| entry.path.clone())
                .collect(),
            "Проверьте каждый исполняемый файл отдельно до извлечения и запуска.",
        ));
    }
    if nested_archives > 0 {
        indicators.push(indicator(
            "archive.nested-archives",
            "Обнаружены вложенные архивы",
            "Вложенные контейнеры усложняют ручную проверку и могут скрывать содержимое.",
            "archive-content",
            IndicatorSeverity::Medium,
            16,
            entries
                .iter()
                .filter(|entry| entry.is_archive)
                .take(30)
                .map(|entry| entry.path.clone())
                .collect(),
            "Проверяйте вложенные архивы отдельно и соблюдайте ограничения глубины.",
        ));
    }
    if maximum_depth > limits.maximum_archive_depth {
        indicators.push(limit_indicator(
            "archive.depth.limit-exceeded",
            "Глубина структуры превышает лимит анализа",
            vec![
                format!("Глубина: {maximum_depth}"),
                format!("Лимит анализа: {}", limits.maximum_archive_depth),
            ],
        ));
    }
    if total_uncompressed > limits.maximum_archive_uncompressed_bytes {
        indicators.push(limit_indicator(
            "archive.uncompressed-size.limit-exceeded",
            "Заявленный распакованный объём превышает лимит анализа",
            vec![
                format!("Объём: {total_uncompressed} байт"),
                format!("Лимит анализа: {} байт", limits.maximum_archive_uncompressed_bytes),
            ],
        ));
    }
    if compression_ratio_infinite || compression_ratio > limits.maximum_compression_ratio {
        let evidence = if compression_ratio_infinite {
            "Коэффициент: ∞ (compressed=0 при ненулевом uncompressed)".to_string()
        } else {
            format!("Коэффициент: {compression_ratio:.1}x")
        };
        indicators.push(indicator(
            "archive.compression-ratio.suspicious",
            "Подозрительно высокая степень сжатия",
            "Соотношение распакованного и сжатого размера похоже на архивную бомбу.",
            "archive-bomb",
            IndicatorSeverity::Critical,
            72,
            vec![evidence],
            "Не распаковывайте архив и удалите его, если источник не подтверждён.",
        ));
    }

    let completeness = if scan_count < archive_count
        || maximum_depth > limits.maximum_archive_depth
        || total_uncompressed > limits.maximum_archive_uncompressed_bytes
    {
        AnalysisCompleteness::StoppedByLimit
    } else {
        AnalysisCompleteness::Complete
    };
    let analysis = ArchiveAnalysis {
        format: "ZIP".to_string(),
        entries,
        total_entries: archive_count,
        total_compressed_size: total_compressed,
        total_uncompressed_size: total_uncompressed,
        maximum_depth,
        compression_ratio,
        compression_ratio_infinite,
        nested_archives,
        executable_entries,
        suspicious_paths,
    };
    let (risk_score, risk_level) = calculate_risk(&indicators);

    Ok(AnalysisReport {
        schema_version: REPORT_SCHEMA_VERSION,
        app_version: app_version(),
        analyzer_version: ANALYZER_VERSION.to_string(),
        rule_set_version: RULE_SET_VERSION.to_string(),
        created_by: report_created_by(),
        analysis_completeness: completeness,
        id: Uuid::new_v4().to_string(),
        object_kind: ObjectKind::Archive,
        target: path,
        display_name,
        started_at: started_at.to_rfc3339(),
        completed_at: Utc::now().to_rfc3339(),
        duration_ms: started.elapsed().as_millis(),
        sha256: None,
        detected_type: Some("ZIP archive".to_string()),
        size_bytes: Some(metadata_before.len()),
        risk_level,
        risk_score,
        indicators,
        metadata: json!({
            "contentExtractedToDisk": false,
            "entriesRead": scan_count,
            "entryLimitApplied": scan_count < archive_count,
            "backendCancellation": true,
            "jobTimeoutMs": limits.job_timeout_ms,
            "openedOnce": true,
            "identityCheck": "opened-handle-size-and-modified-time",
            "reparsePointAllowed": false,
            "windowsShareMode": "FILE_SHARE_READ only; write/delete sharing denied",
            "networkPathPolicy": "UNC rejected",
            "appliedLimits": {
                "maximumArchiveEntries": limits.maximum_archive_entries,
                "maximumArchiveUncompressedBytes": limits.maximum_archive_uncompressed_bytes,
                "maximumArchiveDepth": limits.maximum_archive_depth,
                "maximumCompressionRatio": limits.maximum_compression_ratio
            }
        }),
        pe: None,
        url: None,
        archive: Some(analysis),
        is_demo: false,
        limitations: vec![
            "Содержимое записей не запускается и не извлекается на диск".to_string(),
            "RAR и 7Z распознаются как тип файла, но структурно пока не разбираются".to_string(),
        ],
    })
}

fn limit_indicator(id: &str, title: &str, evidence: Vec<String>) -> ThreatIndicator {
    indicator(
        id,
        title,
        "Защитный лимит ограничил полноту анализа. Сам факт остановки не является признаком вредоносности объекта.",
        "analysis-status",
        IndicatorSeverity::Info,
        0,
        evidence,
        "Учитывайте неполноту отчёта и при необходимости повторите анализ с допустимым большим бюджетом для доверенного объекта.",
    )
}

fn safe_compression_ratio(total_compressed: u64, total_uncompressed: u64) -> (f64, bool) {
    if total_compressed == 0 {
        return if total_uncompressed > 0 {
            (0.0, true)
        } else {
            (1.0, false)
        };
    }
    (total_uncompressed as f64 / total_compressed as f64, false)
}

#[cfg(windows)]
fn open_archive_for_analysis(path: &Path) -> Result<File, AnalysisFailure> {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_SHARE_READ: u32 = 0x00000001;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x00200000;
    OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|error| {
            AnalysisFailure::io(format!(
                "Не удалось открыть ZIP для стабильного чтения: {error}"
            ))
        })
}

#[cfg(not(windows))]
fn open_archive_for_analysis(path: &Path) -> Result<File, AnalysisFailure> {
    OpenOptions::new().read(true).open(path).map_err(|error| {
        AnalysisFailure::io(format!(
            "Не удалось открыть ZIP для стабильного чтения: {error}"
        ))
    })
}

#[cfg(windows)]
fn is_unc_path(path: &str) -> bool {
    path.starts_with(r"\\") || path.starts_with("//")
}

#[cfg(not(windows))]
fn is_unc_path(_path: &str) -> bool {
    false
}

fn reject_special_path(path: &Path) -> Result<(), AnalysisFailure> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        AnalysisFailure::io(format!("Не удалось проверить тип выбранного ZIP: {error}"))
    })?;
    if metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
        return Err(AnalysisFailure::new(
            AnalysisFailureCode::UnsupportedObject,
            "Ссылки, junction и другие reparse points не анализируются без отдельной безопасной политики.",
        ));
    }
    if !metadata.is_file() {
        return Err(AnalysisFailure::new(
            AnalysisFailureCode::UnsupportedObject,
            "Каталоги, устройства, named pipes и другие специальные объекты не поддерживаются.",
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn is_reparse_point(metadata: &Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_reparse_point(_metadata: &Metadata) -> bool {
    false
}

fn file_changed(before: &Metadata, after: &Metadata) -> bool {
    before.len() != after.len() || before.modified().ok() != after.modified().ok()
}

fn has_double_extension(name: &str) -> bool {
    let file_name = name.rsplit('/').next().unwrap_or(name).to_ascii_lowercase();
    let parts = file_name.split('.').collect::<Vec<_>>();
    if parts.len() < 3 {
        return false;
    }
    let final_extension = parts.last().copied().unwrap_or("");
    let previous_extension = parts.get(parts.len() - 2).copied().unwrap_or("");
    EXECUTABLE_EXTENSIONS.contains(&final_extension)
        && DECOY_EXTENSIONS.contains(&previous_extension)
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use tempfile::NamedTempFile;
    use zip::{write::FileOptions, CompressionMethod, ZipWriter};

    use super::*;
    use crate::analysis::jobs::JobRegistry;
    use crate::analysis::types::RiskLevel;

    fn make_zip(entries: &[(&str, &[u8])]) -> NamedTempFile {
        let file = NamedTempFile::new().unwrap();
        {
            let writer_file = file.reopen().unwrap();
            let mut writer = ZipWriter::new(writer_file);
            let options = FileOptions::default().compression_method(CompressionMethod::Deflated);
            for (name, contents) in entries {
                writer.start_file(*name, options).unwrap();
                writer.write_all(contents).unwrap();
            }
            writer.finish().unwrap();
        }
        file
    }

    #[test]
    fn reads_zip_without_extracting_content() {
        let file = make_zip(&[("docs/readme.txt", b"hello")]);
        let registry = JobRegistry::default();
        let token = registry.start("zip-job", 30_000).unwrap();
        let report = analyze_zip(
            file.path().to_string_lossy().to_string(),
            AnalysisLimits::default(),
            &token,
        )
        .unwrap();
        assert_eq!(report.archive.unwrap().total_entries, 1);
        assert_eq!(report.metadata["contentExtractedToDisk"], false);
        assert_eq!(report.metadata["openedOnce"], true);
    }

    #[test]
    fn detects_executable_and_double_extension() {
        let file = make_zip(&[("invoice.pdf.exe", b"MZbroken")]);
        let registry = JobRegistry::default();
        let token = registry.start("zip-danger", 30_000).unwrap();
        let report = analyze_zip(
            file.path().to_string_lossy().to_string(),
            AnalysisLimits::default(),
            &token,
        )
        .unwrap();
        assert!(report
            .indicators
            .iter()
            .any(|item| item.id == "archive.entry.double-extension"));
    }

    #[test]
    fn entry_limit_marks_incomplete_without_creating_threat_score() {
        let file = make_zip(&[("a.txt", b"a"), ("b.txt", b"b")]);
        let registry = JobRegistry::default();
        let token = registry.start("zip-limit", 30_000).unwrap();
        let limits = AnalysisLimits {
            maximum_archive_entries: 1,
            ..AnalysisLimits::default()
        };
        let report = analyze_zip(file.path().to_string_lossy().to_string(), limits, &token).unwrap();
        assert_eq!(report.analysis_completeness, AnalysisCompleteness::StoppedByLimit);
        assert_eq!(report.risk_score, 0);
        assert_eq!(report.risk_level, RiskLevel::NoThreatsFound);
        assert!(report.indicators.iter().any(|item| {
            item.id == "archive.entries.limit-exceeded" && item.score == 0
        }));
    }

    #[test]
    fn infinite_compression_ratio_has_explicit_json_safe_state() {
        let (ratio, infinite) = safe_compression_ratio(0, 10);
        assert!(ratio.is_finite());
        assert_eq!(ratio, 0.0);
        assert!(infinite);

        let value = ArchiveAnalysis {
            compression_ratio: ratio,
            compression_ratio_infinite: infinite,
            ..ArchiveAnalysis::default()
        };
        let json = serde_json::to_string(&value).unwrap();
        assert!(!json.contains("null"));
        assert!(!json.contains("Infinity"));
        assert!(json.contains("compressionRatioInfinite"));
    }

    #[test]
    fn cancellation_is_confirmed_by_backend() {
        let file = make_zip(&[("a.txt", b"hello")]);
        let registry = JobRegistry::default();
        let token = registry.start("zip-cancel", 30_000).unwrap();
        token.cancel();
        let error = analyze_zip(
            file.path().to_string_lossy().to_string(),
            AnalysisLimits::default(),
            &token,
        )
        .unwrap_err();
        assert_eq!(error.code, AnalysisFailureCode::Cancelled);
    }
}
