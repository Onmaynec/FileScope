use std::{
    collections::HashMap,
    fs::{File, Metadata, OpenOptions},
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    time::Instant,
};

use chrono::Utc;
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zip::ZipArchive;

use super::{
    archive_paths::assess_archive_path,
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
const MAX_INDICATOR_EVIDENCE: usize = 30;
const ZIP_LOCAL_HEADER_SIGNATURE: [u8; 4] = [0x50, 0x4b, 0x03, 0x04];
const ZIP_FLAG_ENCRYPTED: u16 = 0x0001;
const UNIX_FILE_TYPE_MASK: u32 = 0o170000;
const UNIX_REGULAR_FILE: u32 = 0o100000;
const UNIX_DIRECTORY: u32 = 0o040000;
const UNIX_SYMLINK: u32 = 0o120000;

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
    let mut file = open_archive_for_analysis(&file_path)?;
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

    let sha256 = hash_open_archive(&mut file, token)?;
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
    let mut local_header_offsets = Vec::new();
    let mut total_compressed = 0_u64;
    let mut total_uncompressed = 0_u64;
    let mut maximum_depth = 0_usize;
    let mut nested_archives = 0_usize;
    let mut executable_entries = 0_usize;
    let mut double_extension_count = 0_usize;
    let mut double_extension_evidence = Vec::new();
    let mut traversal_evidence = Vec::new();
    let mut unreadable_entries = 0_usize;
    let mut unreadable_entry_evidence = Vec::new();
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
        let entry = match archive.by_index_raw(index) {
            Ok(entry) => entry,
            Err(error) => {
                unreadable_entries = unreadable_entries.saturating_add(1);
                push_evidence(
                    &mut unreadable_entry_evidence,
                    &format!("Запись #{index}: {error}"),
                );
                continue;
            }
        };
        let display_path = entry.name().to_string();
        let raw_name_hex = hex::encode(entry.name_raw());
        let assessment = assess_archive_path(&display_path, entry.enclosed_name().is_some());
        let path_normalization_changed = display_path != assessment.normalized_path;
        let name = assessment.normalized_path;
        let depth = name.split('/').filter(|part| !part.is_empty()).count();
        let extension = PathBuf::from(&name)
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let is_executable = EXECUTABLE_EXTENSIONS.contains(&extension.as_str());
        let is_archive = ARCHIVE_EXTENSIONS.contains(&extension.as_str());
        let is_directory = entry.is_dir();
        let (is_symlink, is_special) = classify_unix_entry(entry.unix_mode(), is_directory);

        if assessment.has_parent_or_absolute_path {
            push_evidence(&mut traversal_evidence, &name);
        }
        if is_executable {
            executable_entries += 1;
        }
        if is_archive {
            nested_archives += 1;
        }
        if has_double_extension(&name) {
            double_extension_count += 1;
            push_evidence(&mut double_extension_evidence, &name);
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

        local_header_offsets.push(entry.header_start());
        entries.push(ArchiveEntry {
            path: name,
            display_path,
            raw_name_hex,
            path_normalization_changed,
            compressed_size: entry.compressed_size(),
            uncompressed_size: entry.size(),
            depth,
            is_directory,
            is_executable,
            is_archive,
            suspicious_path: assessment.suspicious
                || path_normalization_changed
                || is_symlink
                || is_special,
            windows_path_key: assessment.windows_comparison_key,
            is_encrypted: false,
            is_symlink,
            is_special,
            has_ads: assessment.has_ads,
            has_reserved_name: assessment.has_reserved_name,
            has_trailing_dot_or_space: assessment.has_trailing_dot_or_space,
            has_control_or_bidi: assessment.has_control_or_bidi,
            path_collision: false,
            file_directory_collision: false,
        });
    }

    token.checkpoint()?;
    let mut file = archive.into_inner();
    let metadata_after = file.metadata().map_err(|error| {
        AnalysisFailure::io(format!(
            "Не удалось повторно проверить открытый ZIP-архив: {error}"
        ))
    })?;
    if file_changed(&metadata_before, &metadata_after) {
        return Err(AnalysisFailure::file_changed());
    }

    let mut encryption_flags_read = 0_usize;
    for (entry, offset) in entries.iter_mut().zip(local_header_offsets) {
        token.checkpoint()?;
        if let Some(encrypted) = read_local_header_encryption_flag(&mut file, offset) {
            entry.is_encrypted = encrypted;
            encryption_flags_read += 1;
        }
    }
    mark_windows_path_collisions(&mut entries);

    let entries_scanned = entries.len();
    let encrypted_entries = entries.iter().filter(|entry| entry.is_encrypted).count();
    let symlink_entries = entries.iter().filter(|entry| entry.is_symlink).count();
    let special_entries = entries.iter().filter(|entry| entry.is_special).count();
    let ads_entries = entries.iter().filter(|entry| entry.has_ads).count();
    let reserved_name_entries = entries
        .iter()
        .filter(|entry| entry.has_reserved_name)
        .count();
    let trailing_dot_or_space_entries = entries
        .iter()
        .filter(|entry| entry.has_trailing_dot_or_space)
        .count();
    let control_or_bidi_entries = entries
        .iter()
        .filter(|entry| entry.has_control_or_bidi)
        .count();
    let normalization_changed_entries = entries
        .iter()
        .filter(|entry| entry.path_normalization_changed)
        .count();
    let path_collisions = entries.iter().filter(|entry| entry.path_collision).count();
    let file_directory_collisions = entries
        .iter()
        .filter(|entry| entry.file_directory_collision)
        .count();
    let suspicious_paths = entries.iter().filter(|entry| entry.suspicious_path).count();

    let (compression_ratio, compression_ratio_infinite) =
        safe_compression_ratio(total_compressed, total_uncompressed);

    if unreadable_entries > 0 {
        append_truncated_summary(
            &mut unreadable_entry_evidence,
            unreadable_entries,
            "непрочитанных записей",
        );
        indicators.push(indicator(
            "archive.entry.metadata-unreadable",
            "Часть ZIP-записей не удалось структурно прочитать",
            "Central directory доступен, но metadata/content offset одной или нескольких записей повреждены или несовместимы. FileScope сохранил доступную часть отчёта вместо полного отказа.",
            "analysis-status",
            IndicatorSeverity::Info,
            0,
            unreadable_entry_evidence,
            "Считайте структурную сводку частичной и не извлекайте архив обычным способом, пока повреждение не объяснено.",
        ));
    }
    if double_extension_count > 0 {
        append_truncated_summary(
            &mut double_extension_evidence,
            double_extension_count,
            "записей с двойным расширением",
        );
        indicators.push(indicator(
            "archive.entry.double-extension",
            "Файлы внутри архива маскируются двойным расширением",
            "Одна или несколько записей выглядят как документы или медиафайлы, но заканчиваются исполняемым расширением.",
            "archive-entry",
            IndicatorSeverity::Critical,
            65,
            double_extension_evidence,
            "Не извлекайте и не запускайте эти файлы.",
        ));
    }
    if !traversal_evidence.is_empty() {
        indicators.push(indicator(
            "archive.path-traversal",
            "Обнаружены пути, выходящие за безопасную корневую область",
            "Некоторые записи используют parent/absolute/drive semantics и не должны напрямую передаваться распаковщику.",
            "archive-path",
            IndicatorSeverity::Critical,
            70,
            traversal_evidence,
            "Не распаковывайте архив обычным способом. Проверяйте содержимое только в изолированной среде.",
        ));
    }
    if ads_entries > 0 {
        indicators.push(indicator_for_entries(
            &entries,
            |entry| entry.has_ads,
            "archive.path.ads",
            "Обнаружены NTFS Alternate Data Stream semantics",
            "Двоеточие внутри имени записи может интерпретироваться Windows как ADS и скрывать дополнительный поток данных.",
            IndicatorSeverity::High,
            38,
            "Не извлекайте такие записи на NTFS без безопасной нормализации имён.",
        ));
    }
    if path_collisions > 0 {
        indicators.push(indicator_for_entries(
            &entries,
            |entry| entry.path_collision,
            "archive.path.windows-collision",
            "Имена записей конфликтуют после Windows-нормализации",
            "Несколько ZIP-путей сводятся к одному Windows comparison key из-за регистра или trailing dot/space semantics.",
            IndicatorSeverity::High,
            32,
            "Не распаковывайте архив поверх существующего каталога; конфликтующие имена могут перезаписывать друг друга.",
        ));
    }
    if file_directory_collisions > 0 {
        indicators.push(indicator_for_entries(
            &entries,
            |entry| entry.file_directory_collision,
            "archive.path.file-directory-collision",
            "Один Windows-путь объявлен и файлом, и каталогом",
            "ZIP содержит несовместимые типы записей для одного нормализованного пути.",
            IndicatorSeverity::High,
            36,
            "Не распаковывайте архив обычным способом: результат зависит от поведения конкретного распаковщика.",
        ));
    }
    if reserved_name_entries > 0 {
        indicators.push(indicator_for_entries(
            &entries,
            |entry| entry.has_reserved_name,
            "archive.path.windows-reserved-name",
            "Используются зарезервированные Windows device names",
            "Имена вроде CON, NUL, AUX, COM1 или LPT1 имеют специальные semantics в Windows и могут обрабатываться неожиданно.",
            IndicatorSeverity::Medium,
            18,
            "Не извлекайте такие записи напрямую; используйте безопасный просмотр metadata.",
        ));
    }
    if trailing_dot_or_space_entries > 0 {
        indicators.push(indicator_for_entries(
            &entries,
            |entry| entry.has_trailing_dot_or_space,
            "archive.path.trailing-dot-space",
            "Имена различаются trailing dot/space semantics Windows",
            "Windows может удалить конечные точки или пробелы и тем самым изменить фактический путь при распаковке.",
            IndicatorSeverity::Medium,
            14,
            "Сравнивайте нормализованные пути до извлечения и не разрешайте перезапись коллизий.",
        ));
    }
    if control_or_bidi_entries > 0 {
        indicators.push(indicator_for_entries(
            &entries,
            |entry| entry.has_control_or_bidi,
            "archive.path.control-bidi",
            "В именах записей есть control/bidi characters",
            "Невидимые или bidi-символы могут менять визуальное представление имени и затруднять ручную проверку.",
            IndicatorSeverity::Medium,
            18,
            "Проверяйте исходное имя и нормализованное представление; не доверяйте только визуальному порядку символов.",
        ));
    }
    if normalization_changed_entries > 0 {
        indicators.push(indicator_for_entries(
            &entries,
            |entry| entry.path_normalization_changed,
            "archive.path.normalized",
            "Путь записи изменился при безопасной нормализации",
            "FileScope сохранил исходные bytes и отображаемое имя, но заменил Windows-style разделители на канонический ZIP-путь для сопоставления и collision detection.",
            IndicatorSeverity::Info,
            0,
            "Сравнивайте displayPath, path и rawNameHex в JSON-отчёте перед извлечением спорной записи.",
        ));
    }
    if symlink_entries > 0 {
        indicators.push(indicator_for_entries(
            &entries,
            |entry| entry.is_symlink,
            "archive.entry.symlink",
            "Архив содержит symbolic-link entries",
            "Symlink внутри архива может изменить место назначения последующей распаковки. FileScope ссылку не извлекает и не переходит по ней.",
            IndicatorSeverity::Medium,
            24,
            "Используйте распаковщик с явной политикой запрета ссылок для недоверенных архивов.",
        ));
    }
    if special_entries > 0 {
        indicators.push(indicator_for_entries(
            &entries,
            |entry| entry.is_special,
            "archive.entry.special",
            "Архив содержит special Unix-mode entries",
            "Metadata записи указывает не на обычный файл, каталог или symlink.",
            IndicatorSeverity::Medium,
            22,
            "Не материализуйте специальные entries из недоверенного архива.",
        ));
    }
    if encrypted_entries > 0 {
        indicators.push(indicator_for_entries(
            &entries,
            |entry| entry.is_encrypted,
            "archive.entry.encrypted",
            "Часть содержимого зашифрована",
            "FileScope определил encryption flag из ZIP local headers, но не запрашивает пароль и не расшифровывает содержимое. Это повышает неопределённость анализа, но само по себе не является признаком вредоносности.",
            IndicatorSeverity::Info,
            0,
            "Оценивайте происхождение архива и проверяйте зашифрованные файлы отдельно только в доверенной изолированной среде.",
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
                .take(MAX_INDICATOR_EVIDENCE)
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
                .take(MAX_INDICATOR_EVIDENCE)
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
                format!("Объём просмотренной части: {total_uncompressed} байт"),
                format!(
                    "Лимит анализа: {} байт",
                    limits.maximum_archive_uncompressed_bytes
                ),
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

    let stopped_by_limit = scan_count < archive_count
        || maximum_depth > limits.maximum_archive_depth
        || total_uncompressed > limits.maximum_archive_uncompressed_bytes;
    let summary_complete = !stopped_by_limit && unreadable_entries == 0 && entries_scanned == archive_count;
    let completeness = if stopped_by_limit {
        AnalysisCompleteness::StoppedByLimit
    } else if unreadable_entries > 0 {
        AnalysisCompleteness::Partial
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
        entries_scanned,
        summary_complete,
        unreadable_entries,
        encrypted_entries,
        symlink_entries,
        special_entries,
        ads_entries,
        reserved_name_entries,
        trailing_dot_or_space_entries,
        control_or_bidi_entries,
        normalization_changed_entries,
        path_collisions,
        file_directory_collisions,
    };
    let (risk_score, risk_level) = calculate_risk(&indicators);
    let mut limitations = vec![
        "Содержимое записей не запускается и не извлекается на диск".to_string(),
        "Зашифрованные записи определяются по metadata, но не расшифровываются и не проверяются по содержимому".to_string(),
        "RAR и 7Z распознаются как тип файла, но структурно пока не разбираются".to_string(),
    ];
    if unreadable_entries > 0 {
        limitations.push(
            "Часть ZIP-записей имеет повреждённые или несовместимые local headers; сводка включает только успешно прочитанные записи"
                .to_string(),
        );
    }

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
        sha256: Some(sha256),
        detected_type: Some("ZIP archive".to_string()),
        size_bytes: Some(metadata_before.len()),
        risk_level,
        risk_score,
        indicators,
        metadata: json!({
            "contentExtractedToDisk": false,
            "entriesRead": entries_scanned,
            "entriesAttempted": scan_count,
            "entriesTotal": archive_count,
            "summaryComplete": summary_complete,
            "unreadableEntries": unreadable_entries,
            "entryLimitApplied": scan_count < archive_count,
            "backendCancellation": true,
            "jobTimeoutMs": limits.job_timeout_ms,
            "openedOnce": true,
            "hashAndStructureSameHandle": true,
            "identityCheck": "opened-handle-size-and-modified-time",
            "reparsePointAllowed": false,
            "windowsShareMode": "FILE_SHARE_READ only; write/delete sharing denied",
            "networkPathPolicy": "UNC rejected",
            "doubleExtensionCount": double_extension_count,
            "encryptedEntries": encrypted_entries,
            "encryptionFlagsRead": encryption_flags_read,
            "symlinkEntries": symlink_entries,
            "specialEntries": special_entries,
            "adsEntries": ads_entries,
            "normalizationChangedEntries": normalization_changed_entries,
            "pathCollisions": path_collisions,
            "fileDirectoryCollisions": file_directory_collisions,
            "rawEntryNameEncoding": "hex",
            "indicatorEvidenceLimit": MAX_INDICATOR_EVIDENCE,
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
        limitations,
    })
}

fn hash_open_archive(file: &mut File, token: &JobToken) -> Result<String, AnalysisFailure> {
    file.seek(SeekFrom::Start(0)).map_err(|error| {
        AnalysisFailure::io(format!(
            "Не удалось начать хеширование ZIP-контейнера: {error}"
        ))
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        token.checkpoint()?;
        let read = file.read(&mut buffer).map_err(|error| {
            AnalysisFailure::io(format!("Ошибка чтения ZIP при вычислении SHA-256: {error}"))
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    file.seek(SeekFrom::Start(0)).map_err(|error| {
        AnalysisFailure::io(format!(
            "Не удалось вернуть ZIP к началу после SHA-256: {error}"
        ))
    })?;
    Ok(format!("{:x}", hasher.finalize()))
}

fn read_local_header_encryption_flag(file: &mut File, header_start: u64) -> Option<bool> {
    file.seek(SeekFrom::Start(header_start)).ok()?;
    let mut prefix = [0_u8; 8];
    file.read_exact(&mut prefix).ok()?;
    if prefix[..4] != ZIP_LOCAL_HEADER_SIGNATURE {
        return None;
    }
    let flags = u16::from_le_bytes([prefix[6], prefix[7]]);
    Some(flags & ZIP_FLAG_ENCRYPTED != 0)
}

fn classify_unix_entry(unix_mode: Option<u32>, is_directory: bool) -> (bool, bool) {
    let Some(mode) = unix_mode else {
        return (false, false);
    };
    let file_type = mode & UNIX_FILE_TYPE_MASK;
    if file_type == UNIX_SYMLINK {
        return (true, false);
    }
    if file_type == 0
        || file_type == UNIX_REGULAR_FILE
        || file_type == UNIX_DIRECTORY
        || (is_directory && file_type == 0)
    {
        return (false, false);
    }
    (false, true)
}

fn mark_windows_path_collisions(entries: &mut [ArchiveEntry]) {
    let mut groups: HashMap<String, Vec<usize>> = HashMap::new();
    for (index, entry) in entries.iter().enumerate() {
        groups
            .entry(entry.windows_path_key.clone())
            .or_default()
            .push(index);
    }

    for indexes in groups.values().filter(|indexes| indexes.len() > 1) {
        let contains_directory = indexes.iter().any(|index| entries[*index].is_directory);
        let contains_file = indexes.iter().any(|index| !entries[*index].is_directory);
        let file_directory_collision = contains_directory && contains_file;
        for index in indexes {
            entries[*index].path_collision = true;
            entries[*index].file_directory_collision = file_directory_collision;
            entries[*index].suspicious_path = true;
        }
    }
}

fn push_evidence(evidence: &mut Vec<String>, value: &str) {
    if evidence.len() < MAX_INDICATOR_EVIDENCE {
        evidence.push(value.to_string());
    }
}

fn append_truncated_summary(evidence: &mut Vec<String>, total: usize, label: &str) {
    if total > evidence.len() {
        evidence.push(format!("…и ещё {} {label}", total - evidence.len()));
    }
}

fn indicator_for_entries(
    entries: &[ArchiveEntry],
    predicate: impl Fn(&ArchiveEntry) -> bool,
    id: &str,
    title: &str,
    description: &str,
    severity: IndicatorSeverity,
    score: u16,
    recommendation: &str,
) -> ThreatIndicator {
    let total = entries.iter().filter(|entry| predicate(entry)).count();
    let mut evidence = entries
        .iter()
        .filter(|entry| predicate(entry))
        .take(MAX_INDICATOR_EVIDENCE)
        .map(|entry| entry.path.clone())
        .collect::<Vec<_>>();
    append_truncated_summary(&mut evidence, total, "записей");
    indicator(
        id,
        title,
        description,
        "archive-path",
        severity,
        score,
        evidence,
        recommendation,
    )
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
    use std::{fs::File, io::Write, path::PathBuf};

    use tempfile::TempDir;
    use zip::{write::FileOptions, CompressionMethod, ZipWriter};

    use super::*;
    use crate::analysis::jobs::JobRegistry;
    use crate::analysis::types::RiskLevel;

    struct ZipFixture {
        _directory: TempDir,
        path: PathBuf,
    }

    impl ZipFixture {
        fn path(&self) -> &Path {
            &self.path
        }
    }

    fn make_zip(entries: &[(&str, &[u8])]) -> ZipFixture {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("fixture.zip");
        {
            let writer_file = File::create(&path).unwrap();
            let mut writer = ZipWriter::new(writer_file);
            let options = FileOptions::default().compression_method(CompressionMethod::Deflated);
            for (name, contents) in entries {
                writer.start_file(*name, options).unwrap();
                writer.write_all(contents).unwrap();
            }
            writer.finish().unwrap();
        }
        ZipFixture {
            _directory: directory,
            path,
        }
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
        let archive = report.archive.unwrap();
        assert_eq!(archive.total_entries, 1);
        assert_eq!(archive.entries_scanned, 1);
        assert!(archive.summary_complete);
        assert_eq!(report.metadata["contentExtractedToDisk"], false);
        assert_eq!(report.metadata["openedOnce"], true);
        assert_eq!(report.metadata["hashAndStructureSameHandle"], true);
        assert_eq!(report.sha256.as_deref().map(str::len), Some(64));
    }

    #[test]
    fn preserves_raw_display_and_normalized_entry_names() {
        let source_name = r"folder\payload.txt";
        let file = make_zip(&[(source_name, b"hello")]);
        let registry = JobRegistry::default();
        let token = registry.start("zip-name-contract", 30_000).unwrap();
        let report = analyze_zip(
            file.path().to_string_lossy().to_string(),
            AnalysisLimits::default(),
            &token,
        )
        .unwrap();
        let archive = report.archive.as_ref().unwrap();
        let entry = &archive.entries[0];
        assert_eq!(entry.display_path, source_name);
        assert_eq!(entry.path, "folder/payload.txt");
        assert_eq!(entry.raw_name_hex, hex::encode(source_name.as_bytes()));
        assert!(entry.path_normalization_changed);
        assert_eq!(archive.normalization_changed_entries, 1);
        assert!(report
            .indicators
            .iter()
            .any(|item| item.id == "archive.path.normalized" && item.score == 0));
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
    fn windows_path_anomalies_and_collisions_are_reported() {
        let file = make_zip(&[
            ("docs/readme.txt", b"one"),
            ("Docs/README.TXT. ", b"two"),
            ("payload/readme.txt:payload.exe", b"three"),
            ("payload/CON.txt", b"four"),
        ]);
        let registry = JobRegistry::default();
        let token = registry.start("zip-windows-paths", 30_000).unwrap();
        let report = analyze_zip(
            file.path().to_string_lossy().to_string(),
            AnalysisLimits::default(),
            &token,
        )
        .unwrap();
        let archive = report.archive.as_ref().unwrap();
        assert_eq!(archive.ads_entries, 1);
        assert_eq!(archive.reserved_name_entries, 1);
        assert!(archive.path_collisions >= 2);
        assert!(report
            .indicators
            .iter()
            .any(|item| item.id == "archive.path.ads"));
        assert!(report
            .indicators
            .iter()
            .any(|item| item.id == "archive.path.windows-collision"));
    }

    #[test]
    fn unix_entry_classifier_distinguishes_symlink_and_special_types() {
        assert_eq!(classify_unix_entry(Some(0o120777), false), (true, false));
        assert_eq!(classify_unix_entry(Some(0o010666), false), (false, true));
        assert_eq!(classify_unix_entry(Some(0o100644), false), (false, false));
        assert_eq!(classify_unix_entry(Some(0o040755), true), (false, false));
    }

    #[test]
    fn repeated_double_extensions_are_aggregated_and_bounded() {
        let names = (0..64)
            .map(|index| format!("invoice-{index}.pdf.exe"))
            .collect::<Vec<_>>();
        let entries = names
            .iter()
            .map(|name| (name.as_str(), b"MZ".as_slice()))
            .collect::<Vec<_>>();
        let file = make_zip(&entries);
        let registry = JobRegistry::default();
        let token = registry.start("zip-bounded", 30_000).unwrap();
        let report = analyze_zip(
            file.path().to_string_lossy().to_string(),
            AnalysisLimits::default(),
            &token,
        )
        .unwrap();
        let matches = report
            .indicators
            .iter()
            .filter(|item| item.id == "archive.entry.double-extension")
            .collect::<Vec<_>>();
        assert_eq!(matches.len(), 1);
        assert!(matches[0].evidence.len() <= MAX_INDICATOR_EVIDENCE + 1);
        assert_eq!(report.metadata["doubleExtensionCount"], 64);
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
        let report =
            analyze_zip(file.path().to_string_lossy().to_string(), limits, &token).unwrap();
        assert_eq!(
            report.analysis_completeness,
            AnalysisCompleteness::StoppedByLimit
        );
        assert_eq!(report.archive.as_ref().unwrap().entries_scanned, 1);
        assert!(!report.archive.as_ref().unwrap().summary_complete);
        assert_eq!(report.risk_score, 0);
        assert_eq!(report.risk_level, RiskLevel::NoThreatsFound);
        assert!(report
            .indicators
            .iter()
            .any(|item| { item.id == "archive.entries.limit-exceeded" && item.score == 0 }));
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
