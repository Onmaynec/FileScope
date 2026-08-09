use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

mod analysis {
    use super::{Deserialize, Map, Serialize, Value};

    pub const REPORT_SCHEMA_VERSION: u16 = 1;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct AnalysisReport {
        pub schema_version: u16,
        pub id: String,
        #[serde(flatten)]
        pub extra: Map<String, Value>,
    }
}

#[path = "../src/history_protection.rs"]
mod history_protection;

mod history_storage {
    include!("../src/history_storage.rs");

    #[cfg(test)]
    mod fault_regressions {
        use std::{
            fs::{self, OpenOptions},
            io::Write,
        };

        use serde_json::json;
        use tempfile::TempDir;

        use super::*;

        #[test]
        fn crash_after_temp_sync_preserves_previous_generation_and_cleans_orphan_on_next_publish() {
            let temp = TempDir::new().unwrap();
            let store = HistoryStore::new(temp.path().join("history"));

            let committed = store.save_report(sample_report("committed"));
            assert_eq!(committed.status, HistoryStorageStatus::Ready);
            assert!(committed.persisted);
            let committed_generation = committed.generation.clone().unwrap();

            let interrupted_envelope = HistoryEnvelope {
                storage_version: HISTORY_STORAGE_VERSION,
                report_schema_version: REPORT_SCHEMA_VERSION,
                saved_at: Utc::now().to_rfc3339(),
                reports: vec![sample_report("interrupted")],
            };
            let raw = serde_json::to_vec(&interrupted_envelope).unwrap();
            let (stored, _) = protect_payload(&raw).unwrap();
            let orphan_name = format!(
                "{GENERATION_PREFIX}99999999999999999999-crash{GENERATION_SUFFIX}{TEMP_SUFFIX}"
            );
            let orphan_path = store.directory.join(orphan_name);

            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&orphan_path)
                .unwrap();
            file.write_all(&stored).unwrap();
            file.sync_all().unwrap();
            drop(file);

            // Simulate a fresh process after an abrupt stop before the atomic rename.
            let restarted = HistoryStore::new(store.directory.clone());
            let recovered = restarted.load();
            assert_eq!(recovered.status, HistoryStorageStatus::Ready);
            assert!(recovered.persisted);
            assert_eq!(recovered.reports.len(), 1);
            assert_eq!(recovered.reports[0].id, "committed");
            assert_eq!(
                recovered.generation.as_deref(),
                Some(committed_generation.as_str())
            );
            assert!(orphan_path.exists());

            let next = restarted.save_report(sample_report("after-restart"));
            assert_eq!(next.status, HistoryStorageStatus::Ready);
            assert!(next.persisted);
            assert_eq!(next.reports[0].id, "after-restart");
            assert_eq!(next.reports[1].id, "committed");
            assert!(!orphan_path.exists());
        }

        #[test]
        fn blocked_app_data_path_is_unavailable_and_preserves_existing_sentinel() {
            let temp = TempDir::new().unwrap();
            let blocked_app_data = temp.path().join("app-data-blocker");
            let sentinel = b"do-not-overwrite";
            fs::write(&blocked_app_data, sentinel).unwrap();

            let store = HistoryStore::new(blocked_app_data.join("history"));
            let loaded = store.load();
            assert_eq!(loaded.status, HistoryStorageStatus::Unavailable);
            assert!(!loaded.persisted);

            let saved = store.save_report(sample_report("must-stay-session-only"));
            assert_eq!(saved.status, HistoryStorageStatus::Unavailable);
            assert!(!saved.persisted);
            assert!(saved.generation.is_none());
            assert_eq!(fs::read(&blocked_app_data).unwrap(), sentinel);
        }

        #[test]
        fn readonly_blocker_is_reported_as_unavailable_without_false_persistence() {
            let temp = TempDir::new().unwrap();
            let blocked_history = temp.path().join("history");
            let sentinel = b"readonly-history-blocker";
            fs::write(&blocked_history, sentinel).unwrap();

            let mut permissions = fs::metadata(&blocked_history).unwrap().permissions();
            permissions.set_readonly(true);
            fs::set_permissions(&blocked_history, permissions).unwrap();

            let store = HistoryStore::new(blocked_history.clone());
            let saved = store.save_report(sample_report("not-persisted"));
            assert_eq!(saved.status, HistoryStorageStatus::Unavailable);
            assert!(!saved.persisted);
            assert!(saved.generation.is_none());
            assert_eq!(fs::read(&blocked_history).unwrap(), sentinel);

            let mut permissions = fs::metadata(&blocked_history).unwrap().permissions();
            permissions.set_readonly(false);
            fs::set_permissions(&blocked_history, permissions).unwrap();
        }

        #[test]
        fn clear_reports_unavailable_when_history_entry_cannot_be_removed() {
            let temp = TempDir::new().unwrap();
            let store = HistoryStore::new(temp.path().join("history"));
            fs::create_dir_all(&store.directory).unwrap();

            let blocked_entry = store
                .directory
                .join(format!("{GENERATION_PREFIX}blocked{GENERATION_SUFFIX}"));
            fs::create_dir(&blocked_entry).unwrap();

            let cleared = store.clear();
            assert_eq!(cleared.status, HistoryStorageStatus::Unavailable);
            assert!(!cleared.persisted);
            assert!(cleared
                .message
                .as_deref()
                .unwrap_or_default()
                .contains("Не удалось полностью удалить историю"));
            assert!(blocked_entry.exists());
        }

        fn sample_report(id: &str) -> AnalysisReport {
            serde_json::from_value(json!({
                "schemaVersion": REPORT_SCHEMA_VERSION,
                "appVersion": "0.4.0",
                "analyzerVersion": "fault-test",
                "ruleSetVersion": "fault-test",
                "createdBy": { "platform": "test", "architecture": "test", "runtime": "test" },
                "analysisCompleteness": "complete",
                "id": id,
                "objectKind": "file",
                "target": format!("C:/{id}.exe"),
                "displayName": format!("{id}.exe"),
                "startedAt": "2026-08-09T00:00:00Z",
                "completedAt": "2026-08-09T00:00:01Z",
                "durationMs": 1000,
                "riskLevel": "noThreatsFound",
                "riskScore": 0,
                "indicators": [],
                "metadata": {},
                "isDemo": false,
                "limitations": []
            }))
            .unwrap()
        }
    }
}
