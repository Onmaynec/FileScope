use std::{fs, fs::File, io::Write, path::Path};

use zip::{write::FileOptions, CompressionMethod, ZipWriter};

use super::{
    archive::analyze_zip,
    jobs::JobRegistry,
    types::{AnalysisLimits, IndicatorSeverity, RiskLevel},
};

const LOCAL_HEADER_SIGNATURE: [u8; 4] = [0x50, 0x4b, 0x03, 0x04];
const CENTRAL_HEADER_SIGNATURE: [u8; 4] = [0x50, 0x4b, 0x01, 0x02];

#[test]
fn encrypted_flag_is_reported_as_uncertainty_without_threat_score() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("encrypted-metadata.zip");
    write_single_file_zip(&path, b"harmless text");
    set_first_entry_encrypted_flags(&path);

    let registry = JobRegistry::default();
    let token = registry.start("zip-encrypted-metadata", 30_000).unwrap();
    let report = analyze_zip(
        path.to_string_lossy().to_string(),
        AnalysisLimits::default(),
        &token,
    )
    .unwrap();

    let archive = report.archive.as_ref().unwrap();
    assert_eq!(archive.encrypted_entries, 1);
    assert!(archive.entries[0].is_encrypted);
    assert_eq!(report.risk_score, 0);
    assert_eq!(report.risk_level, RiskLevel::NoThreatsFound);

    let indicator = report
        .indicators
        .iter()
        .find(|item| item.id == "archive.entry.encrypted")
        .expect("encrypted metadata indicator");
    assert_eq!(indicator.severity, IndicatorSeverity::Info);
    assert_eq!(indicator.score, 0);
    assert_eq!(report.metadata["contentExtractedToDisk"], false);
    assert_eq!(report.metadata["hashAndStructureSameHandle"], true);
}

fn write_single_file_zip(path: &Path, contents: &[u8]) {
    let writer_file = File::create(path).unwrap();
    let mut writer = ZipWriter::new(writer_file);
    let options = FileOptions::default().compression_method(CompressionMethod::Stored);
    writer.start_file("docs/readme.txt", options).unwrap();
    writer.write_all(contents).unwrap();
    writer.finish().unwrap();
}

fn set_first_entry_encrypted_flags(path: &Path) {
    let mut bytes = fs::read(path).unwrap();
    let local = find_signature(&bytes, LOCAL_HEADER_SIGNATURE).expect("local ZIP header");
    bytes[local + 6] |= 0x01;

    let central = find_signature(&bytes, CENTRAL_HEADER_SIGNATURE).expect("central ZIP header");
    bytes[central + 8] |= 0x01;

    fs::write(path, bytes).unwrap();
}

fn find_signature(bytes: &[u8], signature: [u8; 4]) -> Option<usize> {
    bytes
        .windows(signature.len())
        .position(|window| window == signature)
}
