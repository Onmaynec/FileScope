use std::{
    fs::{File, Metadata, OpenOptions},
    io::Read,
    path::{Path, PathBuf},
    time::Instant,
};

use chrono::Utc;
use goblin::Object;
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{
    jobs::{AnalysisFailure, AnalysisFailureCode, JobToken},
    rules::{calculate_risk, indicator},
    types::{
        app_version, report_created_by, AnalysisCompleteness, AnalysisLimits, AnalysisReport,
        IndicatorSeverity, ObjectKind, PeAnalysis, PeSection, ThreatIndicator, ANALYZER_VERSION,
        REPORT_SCHEMA_VERSION, RULE_SET_VERSION,
    },
};

const EXECUTABLE_EXTENSIONS: &[&str] = &[
    "exe", "dll", "scr", "com", "bat", "cmd", "ps1", "msi", "js", "jse", "vbs", "vbe", "wsf",
    "hta", "lnk", "cpl",
];
const DECOY_EXTENSIONS: &[&str] = &[
    "pdf", "doc", "docx", "xls", "xlsx", "jpg", "jpeg", "png", "gif", "txt", "mp3", "mp4", "zip",
    "rar",
];
const SUSPICIOUS_IMPORTS: &[&str] = &[
    "VirtualAlloc",
    "VirtualAllocEx",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "NtWriteVirtualMemory",
    "WinExec",
    "ShellExecuteA",
    "ShellExecuteW",
    "URLDownloadToFileA",
    "URLDownloadToFileW",
    "InternetOpenUrlA",
    "InternetOpenUrlW",
    "SetWindowsHookExA",
    "SetWindowsHookExW",
];
const MAXIMUM_PE_BUFFER: u64 = 96 * 1024 * 1024;
const SAMPLE_BYTES: usize = 1024 * 1024;

pub fn analyze_file(
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
            "UNC и сетевые пути не анализируются в v0.3.3: удалённая файловая система не гарантирует локальную семантику identity и share mode.",
        ));
    }
    reject_special_path(&file_path)?;
    let mut file = open_file_for_analysis(&file_path)?;
    let metadata_before = file.metadata().map_err(|error| {
        AnalysisFailure::io(format!(
            "Не удалось получить сведения об открытом файле: {error}"
        ))
    })?;
    if !metadata_before.is_file() {
        return Err(AnalysisFailure::new(
            AnalysisFailureCode::UnsupportedObject,
            "Выбранный объект не является обычным файлом.",
        ));
    }

    let display_name = file_path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("неизвестный файл")
        .to_string();
    let size = metadata_before.len();
    let mut indicators: Vec<ThreatIndicator> = Vec::new();

    if size > limits.maximum_file_size_bytes {
        indicators.push(indicator(
            "file.size.limit-exceeded",
            "Размер превышает установленный лимит",
            "Полный анализ остановлен до чтения содержимого, чтобы не расходовать чрезмерный объём памяти и времени.",
            "limits",
            IndicatorSeverity::High,
            45,
            vec![
                format!("Размер: {size} байт"),
                format!("Лимит: {} байт", limits.maximum_file_size_bytes),
            ],
            "Увеличьте лимит только для доверенного объекта или проверьте файл другим изолированным инструментом.",
        ));
        let (risk_score, risk_level) = calculate_risk(&indicators);
        return Ok(AnalysisReport {
            schema_version: REPORT_SCHEMA_VERSION,
            app_version: app_version(),
            analyzer_version: ANALYZER_VERSION.to_string(),
            rule_set_version: RULE_SET_VERSION.to_string(),
            created_by: report_created_by(),
            analysis_completeness: AnalysisCompleteness::StoppedByLimit,
            id: Uuid::new_v4().to_string(),
            object_kind: ObjectKind::File,
            target: path,
            display_name,
            started_at: started_at.to_rfc3339(),
            completed_at: Utc::now().to_rfc3339(),
            duration_ms: started.elapsed().as_millis(),
            sha256: None,
            detected_type: None,
            size_bytes: Some(size),
            risk_level,
            risk_score,
            indicators,
            metadata: json!({
                "analysisStopped": "maximumFileSizeBytes",
                "openedOnce": true,
                "contentSource": "singleFileHandle"
            }),
            pe: None,
            url: None,
            archive: None,
            is_demo: false,
            limitations: vec!["Содержимое файла не читалось из-за превышения лимита".to_string()],
        });
    }

    let parser_cap = size
        .min(limits.maximum_parser_memory_bytes)
        .min(MAXIMUM_PE_BUFFER) as usize;
    let mut parser_bytes = Vec::with_capacity(parser_cap.min(8 * 1024 * 1024));
    let mut hasher = Sha256::new();
    let mut read_buffer = [0_u8; 64 * 1024];
    let mut total_read = 0_u64;

    loop {
        token.checkpoint()?;
        let count = file
            .read(&mut read_buffer)
            .map_err(|error| AnalysisFailure::io(format!("Ошибка чтения файла: {error}")))?;
        if count == 0 {
            break;
        }
        total_read = total_read.saturating_add(count as u64);
        if total_read > limits.maximum_read_bytes {
            return Err(AnalysisFailure::new(
                AnalysisFailureCode::ReadLimit,
                "Чтение остановлено: достигнут защитный бюджет прочитанных байт.",
            ));
        }
        hasher.update(&read_buffer[..count]);
        if parser_bytes.len() < parser_cap {
            let remaining = parser_cap - parser_bytes.len();
            parser_bytes.extend_from_slice(&read_buffer[..count.min(remaining)]);
        }
    }

    token.checkpoint()?;
    let metadata_after = file.metadata().map_err(|error| {
        AnalysisFailure::io(format!(
            "Не удалось повторно проверить открытый файл: {error}"
        ))
    })?;
    if file_changed(&metadata_before, &metadata_after) || total_read != metadata_before.len() {
        return Err(AnalysisFailure::file_changed());
    }

    let sha256 = hex::encode(hasher.finalize());
    let sample_end = parser_bytes.len().min(SAMPLE_BYTES);
    let sample = &parser_bytes[..sample_end];
    let detected_type = detect_type(sample).to_string();
    let extension = file_path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    evaluate_name_rules(&display_name, &extension, &detected_type, &mut indicators);

    let sample_entropy = entropy(sample);
    if sample.len() > 4096 && sample_entropy >= 7.65 {
        indicators.push(indicator(
            "file.entropy.high",
            "Высокая энтропия содержимого",
            "Высокая энтропия может быть признаком упаковки, шифрования или сильно сжатых данных. Сам по себе этот признак не доказывает вредоносность.",
            "content",
            IndicatorSeverity::Medium,
            18,
            vec![format!("Энтропия первых данных: {sample_entropy:.2} из 8.00")],
            "Сопоставьте признак с цифровой подписью, происхождением файла и другими результатами.",
        ));
    }

    let mut completeness = match detected_type.as_str() {
        "RAR archive" | "7-Zip archive" => AnalysisCompleteness::Partial,
        _ => AnalysisCompleteness::Complete,
    };
    let mut pe_analysis = None;
    if detected_type == "Windows PE" {
        if parser_bytes.len() as u64 != size {
            completeness = AnalysisCompleteness::Partial;
            indicators.push(indicator(
                "pe.parse.memory-limit",
                "PE-разбор ограничен бюджетом памяти",
                "SHA-256 рассчитан по всему открытому файлу, но полный PE-буфер не размещался в памяти.",
                "limits",
                IndicatorSeverity::Low,
                8,
                vec![
                    format!("Размер PE: {size} байт"),
                    format!("Бюджет parser: {} байт", limits.maximum_parser_memory_bytes),
                ],
                "Используйте отдельную изолированную среду для углублённого разбора очень крупного PE.",
            ));
        } else {
            token.checkpoint()?;
            match analyze_pe_bytes(&parser_bytes) {
                Ok(result) => {
                    if !result.signature_present {
                        indicators.push(indicator(
                            "pe.signature.missing",
                            "Цифровая подпись не обнаружена",
                            "Исполняемый PE-файл не содержит таблицу Authenticode. Это нормально для части программ, но снижает проверяемость происхождения.",
                            "signature",
                            IndicatorSeverity::Medium,
                            16,
                            vec!["Каталог сертификатов PE отсутствует или пуст".to_string()],
                            "Получите файл с официального сайта и проверьте издателя перед запуском.",
                        ));
                    }
                    if !result.suspicious_imports.is_empty() {
                        indicators.push(indicator(
                            "pe.imports.suspicious",
                            "Обнаружены потенциально опасные API",
                            "Файл импортирует функции, часто используемые для внедрения кода, загрузки данных или запуска команд. Законные программы тоже могут применять эти API.",
                            "pe-imports",
                            IndicatorSeverity::High,
                            34,
                            result.suspicious_imports.clone(),
                            "Не запускайте файл, пока не подтвердите его источник и назначение.",
                        ));
                    }
                    let packed_sections = result
                        .sections
                        .iter()
                        .filter(|section| section.raw_size > 2048 && section.entropy >= 7.5)
                        .map(|section| format!("{}: {:.2}", section.name, section.entropy))
                        .collect::<Vec<_>>();
                    if !packed_sections.is_empty() {
                        indicators.push(indicator(
                            "pe.sections.high-entropy",
                            "PE-секции похожи на упакованные или зашифрованные",
                            "Одна или несколько секций имеют высокую энтропию.",
                            "pe-sections",
                            IndicatorSeverity::Medium,
                            20,
                            packed_sections,
                            "Проверьте файл в изолированной среде и сопоставьте с подписью издателя.",
                        ));
                    }
                    pe_analysis = Some(result);
                }
                Err(error) => {
                    completeness = AnalysisCompleteness::Partial;
                    indicators.push(indicator(
                        "pe.parse.failed",
                        "PE-структура повреждена или нестандартна",
                        "Файл начинается с сигнатуры MZ, но его PE-структуру не удалось корректно разобрать.",
                        "format",
                        IndicatorSeverity::High,
                        38,
                        vec![error],
                        "Не запускайте объект и повторно скачайте его из доверенного источника.",
                    ));
                }
            }
        }
    }

    token.checkpoint()?;
    let (risk_score, risk_level) = calculate_risk(&indicators);
    Ok(AnalysisReport {
        schema_version: REPORT_SCHEMA_VERSION,
        app_version: app_version(),
        analyzer_version: ANALYZER_VERSION.to_string(),
        rule_set_version: RULE_SET_VERSION.to_string(),
        created_by: report_created_by(),
        analysis_completeness: completeness,
        id: Uuid::new_v4().to_string(),
        object_kind: ObjectKind::File,
        target: path,
        display_name,
        started_at: started_at.to_rfc3339(),
        completed_at: Utc::now().to_rfc3339(),
        duration_ms: started.elapsed().as_millis(),
        sha256: Some(sha256),
        detected_type: Some(detected_type),
        size_bytes: Some(size),
        risk_level,
        risk_score,
        indicators,
        metadata: json!({
            "extension": extension,
            "sampleEntropy": sample_entropy,
            "readOnly": metadata_before.permissions().readonly(),
            "modified": modified_seconds(&metadata_before),
            "openedOnce": true,
            "contentSource": "singleFileHandle",
            "bytesHashed": total_read,
            "bytesBufferedForParser": parser_bytes.len(),
            "identityCheck": "opened-handle-size-and-modified-time",
            "reparsePointAllowed": false,
            "windowsShareMode": "FILE_SHARE_READ only; write/delete sharing denied",
            "networkPathPolicy": "UNC rejected"
        }),
        pe: pe_analysis,
        url: None,
        archive: None,
        is_demo: false,
        limitations: vec![
            "Статический анализ не запускает файл и не наблюдает его поведение".to_string(),
            "Отсутствие обнаруженных признаков не гарантирует абсолютную безопасность".to_string(),
        ],
    })
}

#[cfg(windows)]
fn open_file_for_analysis(path: &Path) -> Result<File, AnalysisFailure> {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_SHARE_READ: u32 = 0x00000001;
    OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(path)
        .map_err(|error| {
            AnalysisFailure::io(format!(
                "Не удалось открыть файл для стабильного чтения: {error}"
            ))
        })
}

#[cfg(not(windows))]
fn open_file_for_analysis(path: &Path) -> Result<File, AnalysisFailure> {
    OpenOptions::new().read(true).open(path).map_err(|error| {
        AnalysisFailure::io(format!(
            "Не удалось открыть файл для стабильного чтения: {error}"
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
        AnalysisFailure::io(format!(
            "Не удалось проверить тип выбранного объекта: {error}"
        ))
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

fn modified_seconds(metadata: &Metadata) -> Option<u64> {
    metadata
        .modified()
        .ok()
        .and_then(|value| value.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|value| value.as_secs())
}

fn detect_type(data: &[u8]) -> &'static str {
    if data.starts_with(b"MZ") {
        "Windows PE"
    } else if data.starts_with(b"PK\x03\x04") || data.starts_with(b"PK\x05\x06") {
        "ZIP archive"
    } else if data.starts_with(b"Rar!\x1A\x07") {
        "RAR archive"
    } else if data.starts_with(b"7z\xBC\xAF\x27\x1C") {
        "7-Zip archive"
    } else if data.starts_with(b"%PDF-") {
        "PDF document"
    } else if data.starts_with(b"\x89PNG\r\n\x1A\n") {
        "PNG image"
    } else if data.starts_with(b"\xFF\xD8\xFF") {
        "JPEG image"
    } else if data.starts_with(b"\x7FELF") {
        "ELF executable"
    } else if data.starts_with(b"#!") {
        "Script"
    } else if std::str::from_utf8(data).is_ok() {
        "Text"
    } else {
        "Binary data"
    }
}

fn evaluate_name_rules(
    display_name: &str,
    extension: &str,
    detected_type: &str,
    indicators: &mut Vec<ThreatIndicator>,
) {
    let parts = display_name
        .split('.')
        .map(|part| part.to_ascii_lowercase())
        .collect::<Vec<_>>();
    if parts.len() >= 3 {
        let final_extension = parts.last().map(String::as_str).unwrap_or("");
        let previous_extension = parts.get(parts.len() - 2).map(String::as_str).unwrap_or("");
        if EXECUTABLE_EXTENSIONS.contains(&final_extension)
            && DECOY_EXTENSIONS.contains(&previous_extension)
        {
            indicators.push(indicator(
                "file.name.double-extension",
                "Двойное расширение маскирует исполняемый файл",
                "Имя заканчивается исполняемым расширением, перед которым указано расширение документа или медиафайла.",
                "filename",
                IndicatorSeverity::Critical,
                65,
                vec![display_name.to_string()],
                "Не открывайте файл и удалите его, если источник не подтверждён.",
            ));
        }
    }

    let expected = match extension {
        "exe" | "dll" | "scr" | "cpl" => Some("Windows PE"),
        "zip" | "docx" | "xlsx" | "pptx" | "jar" | "crx" | "xpi" => Some("ZIP archive"),
        "rar" => Some("RAR archive"),
        "7z" => Some("7-Zip archive"),
        "pdf" => Some("PDF document"),
        "png" => Some("PNG image"),
        "jpg" | "jpeg" => Some("JPEG image"),
        _ => None,
    };
    if let Some(expected_type) = expected {
        if expected_type != detected_type {
            indicators.push(indicator(
                "file.type.extension-mismatch",
                "Расширение не соответствует содержимому",
                "Фактическая сигнатура файла отличается от типа, заявленного расширением.",
                "format",
                IndicatorSeverity::High,
                42,
                vec![
                    format!("Расширение: .{extension}"),
                    format!("Ожидалось: {expected_type}"),
                    format!("Обнаружено: {detected_type}"),
                ],
                "Не запускайте объект, пока не выясните причину несоответствия.",
            ));
        }
    }
}

fn analyze_pe_bytes(data: &[u8]) -> Result<PeAnalysis, String> {
    let Object::PE(pe) = Object::parse(data).map_err(|error| error.to_string())? else {
        return Err("Сигнатура не распознана библиотекой PE".to_string());
    };
    let architecture = match pe.header.coff_header.machine {
        0x014c => "x86",
        0x8664 => "x64",
        0xAA64 => "ARM64",
        0x01c4 => "ARM",
        _ if pe.is_64 => "64-bit",
        _ => "32-bit",
    }
    .to_string();
    let sections = pe
        .sections
        .iter()
        .map(|section| {
            let start = section.pointer_to_raw_data as usize;
            let end = start
                .saturating_add(section.size_of_raw_data as usize)
                .min(data.len());
            let section_data = if start < end { &data[start..end] } else { &[] };
            PeSection {
                name: section.name().unwrap_or("<без имени>").to_string(),
                virtual_size: section.virtual_size as u64,
                raw_size: section.size_of_raw_data as u64,
                entropy: entropy(section_data),
            }
        })
        .collect::<Vec<_>>();
    let imports = pe
        .imports
        .iter()
        .map(|import| format!("{}!{}", import.dll, import.name))
        .collect::<Vec<_>>();
    let suspicious_imports = imports
        .iter()
        .filter(|value| {
            SUSPICIOUS_IMPORTS.iter().any(|name| {
                value
                    .to_ascii_lowercase()
                    .ends_with(&name.to_ascii_lowercase())
            })
        })
        .cloned()
        .collect::<Vec<_>>();
    Ok(PeAnalysis {
        architecture,
        entry_point: pe.entry as u64,
        sections,
        imports,
        suspicious_imports,
        signature_present: has_authenticode_directory(data),
    })
}

fn has_authenticode_directory(data: &[u8]) -> bool {
    if data.len() < 0x40 || &data[..2] != b"MZ" {
        return false;
    }
    let pe_offset = u32::from_le_bytes(data[0x3c..0x40].try_into().unwrap()) as usize;
    if pe_offset.saturating_add(24) >= data.len()
        || data.get(pe_offset..pe_offset + 4) != Some(b"PE\0\0")
    {
        return false;
    }
    let optional_offset = pe_offset + 24;
    if optional_offset + 2 > data.len() {
        return false;
    }
    let magic = u16::from_le_bytes([data[optional_offset], data[optional_offset + 1]]);
    let directory_offset = optional_offset + if magic == 0x20b { 112 } else { 96 };
    let security_offset = directory_offset + (4 * 8);
    if security_offset + 8 > data.len() {
        return false;
    }
    let certificate_file_offset = u32::from_le_bytes(
        data[security_offset..security_offset + 4]
            .try_into()
            .unwrap(),
    );
    let certificate_size = u32::from_le_bytes(
        data[security_offset + 4..security_offset + 8]
            .try_into()
            .unwrap(),
    );
    certificate_file_offset > 0 && certificate_size > 8
}

fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0_usize; 256];
    for byte in data {
        counts[*byte as usize] += 1;
    }
    let length = data.len() as f64;
    counts
        .iter()
        .filter(|count| **count > 0)
        .map(|count| {
            let probability = *count as f64 / length;
            -probability * probability.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::sync::Arc;

    use tempfile::NamedTempFile;

    use super::*;
    use crate::analysis::jobs::JobRegistry;

    fn token() -> Arc<JobToken> {
        JobRegistry::default().start("test-job", 30_000).unwrap()
    }

    #[test]
    fn calculates_real_sha256_and_detects_text_from_one_handle() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(b"FileScope test").unwrap();
        let report = analyze_file(
            file.path().to_string_lossy().to_string(),
            AnalysisLimits::default(),
            &token(),
        )
        .unwrap();
        assert_eq!(
            report.sha256.as_deref(),
            Some("79424917c77fac8e2d84db8b6064beba547968b81f200152a62f1442b48c250d")
        );
        assert_eq!(report.detected_type.as_deref(), Some("Text"));
        assert_eq!(report.metadata["openedOnce"], true);
        assert_eq!(report.schema_version, REPORT_SCHEMA_VERSION);
    }

    #[test]
    fn detects_double_extension() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("invoice.pdf.exe");
        std::fs::write(&path, b"MZbroken").unwrap();
        let report = analyze_file(
            path.to_string_lossy().to_string(),
            AnalysisLimits::default(),
            &token(),
        )
        .unwrap();
        assert!(report
            .indicators
            .iter()
            .any(|item| item.id == "file.name.double-extension"));
    }

    #[test]
    fn cancellation_stops_before_reading() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(&vec![1_u8; 1024 * 1024]).unwrap();
        let registry = JobRegistry::default();
        let token = registry.start("cancelled-job", 30_000).unwrap();
        token.cancel();
        let error = analyze_file(
            file.path().to_string_lossy().to_string(),
            AnalysisLimits::default(),
            &token,
        )
        .unwrap_err();
        assert_eq!(error.code, AnalysisFailureCode::Cancelled);
    }
}
