use std::{
    fs::File,
    io::{BufReader, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    time::Instant,
};

use chrono::Utc;
use goblin::Object;
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{
    rules::{calculate_risk, indicator},
    types::{
        AnalysisLimits, AnalysisReport, IndicatorSeverity, ObjectKind, PeAnalysis, PeSection,
        RiskLevel, ThreatIndicator,
    },
};

const EXECUTABLE_EXTENSIONS: &[&str] = &[
    "exe", "dll", "scr", "com", "bat", "cmd", "ps1", "msi", "js", "jse", "vbs",
    "vbe", "wsf", "hta", "lnk", "cpl",
];
const DECOY_EXTENSIONS: &[&str] = &[
    "pdf", "doc", "docx", "xls", "xlsx", "jpg", "jpeg", "png", "gif", "txt", "mp3",
    "mp4", "zip", "rar",
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

pub fn analyze_file(path: String, limits: AnalysisLimits) -> Result<AnalysisReport, String> {
    let started = Instant::now();
    let started_at = Utc::now();
    let file_path = PathBuf::from(&path);
    let metadata = std::fs::metadata(&file_path)
        .map_err(|error| format!("Не удалось получить сведения о файле: {error}"))?;
    if !metadata.is_file() {
        return Err("Выбранный путь не является обычным файлом".to_string());
    }

    let display_name = file_path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("неизвестный файл")
        .to_string();
    let size = metadata.len();
    let mut indicators: Vec<ThreatIndicator> = Vec::new();

    if size > limits.maximum_file_size_bytes {
        indicators.push(indicator(
            "file.size.limit-exceeded",
            "Размер превышает установленный лимит",
            "Полный анализ остановлен до чтения содержимого, чтобы не расходовать чрезмерный объём памяти и времени.",
            "limits",
            IndicatorSeverity::High,
            45,
            vec![format!("Размер: {size} байт"), format!("Лимит: {} байт", limits.maximum_file_size_bytes)],
            "Увеличьте лимит только для доверенного объекта или проверьте файл другим изолированным инструментом.",
        ));
        let (risk_score, risk_level) = calculate_risk(&indicators);
        return Ok(AnalysisReport {
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
            metadata: json!({ "analysisStopped": "maximumFileSizeBytes" }),
            pe: None,
            url: None,
            archive: None,
            is_demo: false,
            limitations: vec!["Содержимое файла не читалось из-за превышения лимита".to_string()],
        });
    }

    let sha256 = hash_file(&file_path)?;
    let sample = read_prefix(&file_path, 1024 * 1024)?;
    let detected_type = detect_type(&sample).to_string();
    let extension = file_path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    evaluate_name_rules(&display_name, &extension, &detected_type, &mut indicators);

    let sample_entropy = entropy(&sample);
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

    let mut pe_analysis = None;
    if detected_type == "Windows PE" {
        match analyze_pe(&file_path, size) {
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
                let packed_sections: Vec<String> = result
                    .sections
                    .iter()
                    .filter(|section| section.raw_size > 2048 && section.entropy >= 7.5)
                    .map(|section| format!("{}: {:.2}", section.name, section.entropy))
                    .collect();
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
            Err(error) => indicators.push(indicator(
                "pe.parse.failed",
                "PE-структура повреждена или нестандартна",
                "Файл начинается с сигнатуры MZ, но его PE-структуру не удалось корректно разобрать.",
                "format",
                IndicatorSeverity::High,
                38,
                vec![error],
                "Не запускайте объект и повторно скачайте его из доверенного источника.",
            )),
        }
    }

    let (risk_score, risk_level) = calculate_risk(&indicators);
    let completed_at = Utc::now();
    Ok(AnalysisReport {
        id: Uuid::new_v4().to_string(),
        object_kind: ObjectKind::File,
        target: path,
        display_name,
        started_at: started_at.to_rfc3339(),
        completed_at: completed_at.to_rfc3339(),
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
            "readOnly": metadata.permissions().readonly(),
            "modified": metadata.modified().ok().and_then(|value| value.duration_since(std::time::UNIX_EPOCH).ok()).map(|value| value.as_secs()),
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

fn hash_file(path: &Path) -> Result<String, String> {
    let file = File::open(path).map_err(|error| format!("Не удалось открыть файл: {error}"))?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = reader
            .read(&mut buffer)
            .map_err(|error| format!("Ошибка чтения файла: {error}"))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn read_prefix(path: &Path, maximum: usize) -> Result<Vec<u8>, String> {
    let mut file = File::open(path).map_err(|error| format!("Не удалось открыть файл: {error}"))?;
    let mut buffer = vec![0_u8; maximum];
    let count = file
        .read(&mut buffer)
        .map_err(|error| format!("Ошибка чтения файла: {error}"))?;
    buffer.truncate(count);
    Ok(buffer)
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
    let parts: Vec<String> = display_name
        .split('.')
        .map(|part| part.to_ascii_lowercase())
        .collect();
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
                vec![format!("Расширение: .{extension}"), format!("Ожидалось: {expected_type}"), format!("Обнаружено: {detected_type}")],
                "Не запускайте объект, пока не выясните причину несоответствия.",
            ));
        }
    }
}

fn analyze_pe(path: &Path, size: u64) -> Result<PeAnalysis, String> {
    if size > 96 * 1024 * 1024 {
        return Err("PE-файл слишком велик для полного разбора структуры".to_string());
    }
    let data = std::fs::read(path).map_err(|error| format!("Не удалось прочитать PE: {error}"))?;
    let Object::PE(pe) = Object::parse(&data).map_err(|error| error.to_string())? else {
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
            let section_data = if start < end && end <= data.len() {
                &data[start..end]
            } else {
                &[]
            };
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
            SUSPICIOUS_IMPORTS
                .iter()
                .any(|name| value.to_ascii_lowercase().ends_with(&name.to_ascii_lowercase()))
        })
        .cloned()
        .collect::<Vec<_>>();

    Ok(PeAnalysis {
        architecture,
        entry_point: pe.entry as u64,
        sections,
        imports,
        suspicious_imports,
        signature_present: has_authenticode_directory(&data),
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

    use tempfile::NamedTempFile;

    use super::*;

    #[test]
    fn calculates_real_sha256_and_detects_text() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(b"FileScope test").unwrap();
        let report = analyze_file(
            file.path().to_string_lossy().to_string(),
            AnalysisLimits::default(),
        )
        .unwrap();
        assert_eq!(
            report.sha256.as_deref(),
            Some("1a9fca643641626459702b825f5b3f67a466f82a24cb99e26eea249835b8cbfc")
        );
        assert_eq!(report.detected_type.as_deref(), Some("Text"));
        assert!(!report.is_demo);
    }

    #[test]
    fn detects_double_extension() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("invoice.pdf.exe");
        std::fs::write(&path, b"MZbroken").unwrap();
        let report = analyze_file(
            path.to_string_lossy().to_string(),
            AnalysisLimits::default(),
        )
        .unwrap();
        assert!(report
            .indicators
            .iter()
            .any(|item| item.id == "file.name.double-extension"));
        assert_eq!(report.risk_level, RiskLevel::Dangerous);
    }
}
