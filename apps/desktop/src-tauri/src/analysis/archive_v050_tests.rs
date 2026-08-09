use std::{fs, fs::File, io::Write, path::Path};

use zip::{write::FileOptions, CompressionMethod, ZipWriter};

use super::{
    archive::analyze_zip,
    jobs::JobRegistry,
    types::{AnalysisCompleteness, AnalysisLimits, IndicatorSeverity, RiskLevel},
};

const LOCAL_HEADER_SIGNATURE: [u8; 4] = [0x50, 0x4b, 0x03, 0x04];
const CENTRAL_HEADER_SIGNATURE: [u8; 4] = [0x50, 0x4b, 0x01, 0x02];

#[test]
fn encrypted_flag_is_reported_as_uncertainty_without_threat_score() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("encrypted-metadata.zip");
    write_single_file_zip(&path, b"harmless text");
    set_first_entry_encrypted_flags(&path);

    let report = analyze_fixture(&path, "zip-encrypted-metadata");
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

#[test]
fn duplicate_central_directory_names_are_marked_as_windows_collisions() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("duplicate-names.zip");
    let writer_file = File::create(&path).unwrap();
    let mut writer = ZipWriter::new(writer_file);
    let options = FileOptions::default().compression_method(CompressionMethod::Stored);
    writer.start_file("docs/readme.txt", options).unwrap();
    writer.write_all(b"first").unwrap();
    writer.start_file("docs/readme.txt", options).unwrap();
    writer.write_all(b"second").unwrap();
    writer.finish().unwrap();

    let report = analyze_fixture(&path, "zip-duplicate-names");
    let archive = report.archive.as_ref().unwrap();
    assert_eq!(archive.total_entries, 2);
    assert_eq!(archive.path_collisions, 2);
    assert!(archive.entries.iter().all(|entry| entry.path_collision));
    assert!(report
        .indicators
        .iter()
        .any(|item| item.id == "archive.path.windows-collision"));
}

#[test]
fn file_and_directory_with_same_windows_key_are_marked_as_type_collision() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("file-directory-collision.zip");
    let writer_file = File::create(&path).unwrap();
    let mut writer = ZipWriter::new(writer_file);
    let options = FileOptions::default().compression_method(CompressionMethod::Stored);
    writer.add_directory("config/", options).unwrap();
    writer.start_file("CONFIG", options).unwrap();
    writer.write_all(b"file").unwrap();
    writer.finish().unwrap();

    let report = analyze_fixture(&path, "zip-file-directory-collision");
    let archive = report.archive.as_ref().unwrap();
    assert_eq!(archive.path_collisions, 2);
    assert_eq!(archive.file_directory_collisions, 2);
    assert!(archive
        .entries
        .iter()
        .all(|entry| entry.file_directory_collision));
    assert!(report
        .indicators
        .iter()
        .any(|item| item.id == "archive.path.file-directory-collision"));
}

#[test]
fn symlink_entry_is_classified_without_following_or_extracting_it() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("symlink-entry.zip");
    let writer_file = File::create(&path).unwrap();
    let mut writer = ZipWriter::new(writer_file);
    let options = FileOptions::default().compression_method(CompressionMethod::Stored);
    writer
        .add_symlink("links/payload", "../payload.exe", options)
        .unwrap();
    writer.finish().unwrap();

    let report = analyze_fixture(&path, "zip-symlink-entry");
    let archive = report.archive.as_ref().unwrap();
    assert_eq!(archive.symlink_entries, 1);
    assert!(archive.entries[0].is_symlink);
    assert_eq!(report.metadata["contentExtractedToDisk"], false);
    assert!(report
        .indicators
        .iter()
        .any(|item| item.id == "archive.entry.symlink"));
}

#[test]
fn damaged_local_header_keeps_readable_entries_in_partial_report() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("damaged-entry.zip");
    let writer_file = File::create(&path).unwrap();
    let mut writer = ZipWriter::new(writer_file);
    let options = FileOptions::default().compression_method(CompressionMethod::Stored);
    writer.start_file("docs/first.txt", options).unwrap();
    writer.write_all(b"first").unwrap();
    writer.start_file("docs/second.txt", options).unwrap();
    writer.write_all(b"second").unwrap();
    writer.finish().unwrap();
    corrupt_second_local_header(&path);

    let report = analyze_fixture(&path, "zip-damaged-entry");
    let archive = report.archive.as_ref().unwrap();
    assert_eq!(report.analysis_completeness, AnalysisCompleteness::Partial);
    assert_eq!(archive.total_entries, 2);
    assert_eq!(archive.entries_scanned, 1);
    assert_eq!(archive.unreadable_entries, 1);
    assert!(!archive.summary_complete);
    assert_eq!(archive.entries[0].path, "docs/first.txt");
    assert_eq!(report.risk_score, 0);
    assert_eq!(report.risk_level, RiskLevel::NoThreatsFound);
    assert_eq!(report.metadata["contentExtractedToDisk"], false);
    assert_eq!(report.metadata["unreadableEntries"], 1);
    assert!(report.indicators.iter().any(|item| {
        item.id == "archive.entry.metadata-unreadable"
            && item.severity == IndicatorSeverity::Info
            && item.score == 0
    }));
}

fn analyze_fixture(path: &Path, job_id: &str) -> super::types::AnalysisReport {
    let registry = JobRegistry::default();
    let token = registry.start(job_id, 30_000).unwrap();
    analyze_zip(
        path.to_string_lossy().to_string(),
        AnalysisLimits::default(),
        &token,
    )
    .unwrap()
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

fn corrupt_second_local_header(path: &Path) {
    let mut bytes = fs::read(path).unwrap();
    let local_headers = bytes
        .windows(LOCAL_HEADER_SIGNATURE.len())
        .enumerate()
        .filter_map(|(index, window)| (window == LOCAL_HEADER_SIGNATURE).then_some(index))
        .collect::<Vec<_>>();
    assert!(local_headers.len() >= 2, "fixture must contain two local headers");
    bytes[local_headers[1]] = 0;
    fs::write(path, bytes).unwrap();
}

fn find_signature(bytes: &[u8], signature: [u8; 4]) -> Option<usize> {
    bytes
        .windows(signature.len())
        .position(|window| window == signature)
}
