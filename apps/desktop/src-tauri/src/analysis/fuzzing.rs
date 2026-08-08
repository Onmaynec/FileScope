//! Safe, bounded entry points used only by cargo-fuzz targets.

use std::io::Cursor;

use goblin::Object;
use zip::ZipArchive;

use super::{
    jobs::JobRegistry,
    rules::{calculate_risk, indicator},
    types::{AnalysisReport, IndicatorSeverity},
    url,
};

const MAXIMUM_FUZZ_FILE_BYTES: usize = 1024 * 1024;
const MAXIMUM_FUZZ_ZIP_BYTES: usize = 2 * 1024 * 1024;
const MAXIMUM_FUZZ_ZIP_ENTRIES: usize = 512;
const MAXIMUM_FUZZ_PE_SECTIONS: usize = 512;
const MAXIMUM_FUZZ_PE_IMPORTS: usize = 4_096;

pub fn report_deserialization(data: &[u8]) {
    let result = serde_json::from_slice::<AnalysisReport>(data);
    if let Ok(report) = result {
        let _ = serde_json::to_vec(&report);
    }
}

pub fn passive_url(data: &[u8]) {
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };
    if input.len() > 4_096 {
        return;
    }
    let registry = JobRegistry::default();
    let Ok(token) = registry.start("fuzz-passive-url", 2_000) else {
        return;
    };
    let _ = url::analyze_url_passive(input.to_string(), &token);
}

pub fn rule_engine(data: &[u8]) {
    let indicators = data
        .chunks(4)
        .take(1_024)
        .enumerate()
        .map(|(index, chunk)| {
            let score = chunk.first().copied().unwrap_or_default() as u16;
            indicator(
                &format!("fuzz.{}", index % 64),
                "Fuzz",
                "Fuzz",
                "fuzz",
                IndicatorSeverity::Info,
                score,
                vec![format!(
                    "evidence-{}",
                    chunk.get(1).copied().unwrap_or_default()
                )],
                "review",
            )
        })
        .collect::<Vec<_>>();
    let _ = calculate_risk(&indicators);
}

pub fn file_format_and_pe(data: &[u8]) {
    if data.len() > MAXIMUM_FUZZ_FILE_BYTES {
        return;
    }

    let detected_type = if data.starts_with(b"MZ") {
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
    };
    let _ = detected_type;

    if !data.starts_with(b"MZ") {
        return;
    }
    let Ok(Object::PE(pe)) = Object::parse(data) else {
        return;
    };

    for section in pe.sections.iter().take(MAXIMUM_FUZZ_PE_SECTIONS) {
        let start = section.pointer_to_raw_data as usize;
        let end = start
            .saturating_add(section.size_of_raw_data as usize)
            .min(data.len());
        let section_data = if start < end { &data[start..end] } else { &[] };
        let _ = (section.name().ok(), section_data.len(), section.virtual_size);
    }

    for import in pe.imports.iter().take(MAXIMUM_FUZZ_PE_IMPORTS) {
        let _ = format!("{}!{}", import.dll, import.name);
    }
    let _ = (pe.entry, pe.is_64);
}

pub fn zip_metadata(data: &[u8]) {
    if data.len() > MAXIMUM_FUZZ_ZIP_BYTES {
        return;
    }
    let Ok(mut archive) = ZipArchive::new(Cursor::new(data)) else {
        return;
    };

    let scan_count = archive.len().min(MAXIMUM_FUZZ_ZIP_ENTRIES);
    let mut total_compressed = 0_u64;
    let mut total_uncompressed = 0_u64;
    let mut maximum_depth = 0_usize;

    for index in 0..scan_count {
        let Ok(entry) = archive.by_index(index) else {
            continue;
        };
        let name = entry.name().replace('\\', "/");
        let depth = name.split('/').filter(|part| !part.is_empty()).count();
        let suspicious_path = entry.enclosed_name().is_none()
            || name.starts_with('/')
            || name.contains("../")
            || name.contains(":/")
            || name.contains(':');

        maximum_depth = maximum_depth.max(depth);
        total_compressed = total_compressed.saturating_add(entry.compressed_size());
        total_uncompressed = total_uncompressed.saturating_add(entry.size());
        let _ = (
            suspicious_path,
            entry.is_dir(),
            entry.compressed_size(),
            entry.size(),
        );
    }

    let _ = (total_compressed, total_uncompressed, maximum_depth);
}
