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

const MAXIMUM_FILE_FUZZ_BYTES: usize = 4 * 1024 * 1024;
const MAXIMUM_ZIP_FUZZ_BYTES: usize = 8 * 1024 * 1024;
const MAXIMUM_ZIP_ENTRIES: usize = 512;
const MAXIMUM_PE_SECTIONS: usize = 256;

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

/// Fuzzes the same low-level parser families used by the local-file analyzer
/// without opening or executing any file. The input is kept entirely in memory.
pub fn file_format_and_pe(data: &[u8]) {
    if data.len() > MAXIMUM_FILE_FUZZ_BYTES {
        return;
    }

    let _magic = detect_magic(data);
    let _sample_entropy = entropy(data.get(..data.len().min(1024 * 1024)).unwrap_or(data));

    let Ok(object) = Object::parse(data) else {
        return;
    };
    let Object::PE(pe) = object else {
        return;
    };

    for section in pe.sections.iter().take(MAXIMUM_PE_SECTIONS) {
        let start = section.pointer_to_raw_data as usize;
        let size = section.size_of_raw_data as usize;
        let Some(end) = start.checked_add(size) else {
            continue;
        };
        if start >= data.len() || end > data.len() || start >= end {
            continue;
        }
        let _ = entropy(&data[start..end]);
    }

    for import in pe.imports.iter().take(2_048) {
        let _ = import.name.len();
        let _ = import.dll.len();
    }
}

/// Traverses ZIP metadata in memory only. It never extracts entries and never
/// writes corpus-derived bytes to disk itself.
pub fn zip_metadata(data: &[u8]) {
    if data.len() > MAXIMUM_ZIP_FUZZ_BYTES {
        return;
    }
    let Ok(mut archive) = ZipArchive::new(Cursor::new(data)) else {
        return;
    };

    let mut total_compressed = 0_u64;
    let mut total_uncompressed = 0_u64;
    for index in 0..archive.len().min(MAXIMUM_ZIP_ENTRIES) {
        let Ok(entry) = archive.by_index(index) else {
            continue;
        };
        let name = entry.name().replace('\\', "/");
        let _enclosed = entry.enclosed_name();
        let _depth = name.split('/').filter(|part| !part.is_empty()).count();
        let _suspicious = name.starts_with('/')
            || name.contains("../")
            || name.contains(":/")
            || name.contains(':');
        let _double_extension = has_double_extension(&name);
        total_compressed = total_compressed.saturating_add(entry.compressed_size());
        total_uncompressed = total_uncompressed.saturating_add(entry.size());
    }
    let _ratio = safe_compression_ratio(total_compressed, total_uncompressed);
}

fn detect_magic(data: &[u8]) -> &'static str {
    if data.starts_with(b"MZ") {
        "pe"
    } else if data.starts_with(b"PK\x03\x04") || data.starts_with(b"PK\x05\x06") {
        "zip"
    } else if data.starts_with(b"Rar!\x1A\x07") {
        "rar"
    } else if data.starts_with(b"7z\xBC\xAF\x27\x1C") {
        "7z"
    } else if data.starts_with(b"%PDF") {
        "pdf"
    } else {
        "unknown"
    }
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
        .into_iter()
        .filter(|count| *count > 0)
        .map(|count| {
            let probability = count as f64 / length;
            -probability * probability.log2()
        })
        .sum()
}

fn has_double_extension(name: &str) -> bool {
    let file_name = name.rsplit('/').next().unwrap_or(name).to_ascii_lowercase();
    let parts = file_name.split('.').collect::<Vec<_>>();
    if parts.len() < 3 {
        return false;
    }
    let final_extension = parts.last().copied().unwrap_or_default();
    matches!(
        final_extension,
        "exe" | "dll" | "scr" | "com" | "bat" | "cmd" | "ps1" | "msi" | "js" | "jse"
            | "vbs" | "vbe" | "wsf" | "hta" | "lnk" | "cpl"
    )
}

fn safe_compression_ratio(compressed: u64, uncompressed: u64) -> (f64, bool) {
    if uncompressed == 0 {
        return (0.0, false);
    }
    if compressed == 0 {
        return (0.0, true);
    }
    let ratio = uncompressed as f64 / compressed as f64;
    if ratio.is_finite() {
        (ratio, false)
    } else {
        (0.0, true)
    }
}
