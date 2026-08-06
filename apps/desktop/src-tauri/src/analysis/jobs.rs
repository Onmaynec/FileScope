use std::{
    collections::HashMap,
    fmt,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use serde::Serialize;
use tokio::sync::Notify;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum AnalysisFailureCode {
    Cancelled,
    Timeout,
    ReadLimit,
    MemoryLimit,
    EntryLimit,
    FileChanged,
    UnsupportedObject,
    SecurityBlocked,
    InvalidInput,
    Io,
    Parse,
    Network,
    Internal,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisFailure {
    pub code: AnalysisFailureCode,
    pub message: String,
}

impl AnalysisFailure {
    pub fn new(code: AnalysisFailureCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn cancelled() -> Self {
        Self::new(
            AnalysisFailureCode::Cancelled,
            "Анализ отменён пользователем и остановлен Rust backend.",
        )
    }

    pub fn timeout() -> Self {
        Self::new(
            AnalysisFailureCode::Timeout,
            "Анализ остановлен по максимальному времени выполнения задания.",
        )
    }

    pub fn io(message: impl Into<String>) -> Self {
        Self::new(AnalysisFailureCode::Io, message)
    }

    pub fn parse(message: impl Into<String>) -> Self {
        Self::new(AnalysisFailureCode::Parse, message)
    }

    pub fn network(message: impl Into<String>) -> Self {
        Self::new(AnalysisFailureCode::Network, message)
    }

    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(AnalysisFailureCode::InvalidInput, message)
    }

    pub fn security(message: impl Into<String>) -> Self {
        Self::new(AnalysisFailureCode::SecurityBlocked, message)
    }

    pub fn file_changed() -> Self {
        Self::new(
            AnalysisFailureCode::FileChanged,
            "Файл изменился во время проверки. Результат не сформирован, потому что SHA-256 и структура могли относиться к разным состояниям объекта.",
        )
    }
}

impl fmt::Display for AnalysisFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.message)
    }
}

pub struct JobToken {
    cancelled: AtomicBool,
    notify: Notify,
    deadline: Instant,
}

impl JobToken {
    fn new(timeout_ms: u64) -> Self {
        let timeout = Duration::from_millis(timeout_ms.clamp(1_000, 30 * 60 * 1_000));
        Self {
            cancelled: AtomicBool::new(false),
            notify: Notify::new(),
            deadline: Instant::now() + timeout,
        }
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    pub fn checkpoint(&self) -> Result<(), AnalysisFailure> {
        if self.is_cancelled() {
            return Err(AnalysisFailure::cancelled());
        }
        if Instant::now() >= self.deadline {
            return Err(AnalysisFailure::timeout());
        }
        Ok(())
    }

    pub fn remaining(&self) -> Duration {
        self.deadline.saturating_duration_since(Instant::now())
    }

    pub async fn cancelled(&self) {
        if self.is_cancelled() {
            return;
        }
        self.notify.notified().await;
    }
}

#[derive(Default)]
pub struct JobRegistry {
    jobs: Mutex<HashMap<String, Arc<JobToken>>>,
}

impl JobRegistry {
    pub fn start(&self, job_id: &str, timeout_ms: u64) -> Result<Arc<JobToken>, AnalysisFailure> {
        if job_id.trim().is_empty() || job_id.len() > 160 {
            return Err(AnalysisFailure::invalid("Некорректный идентификатор задания."));
        }
        let mut jobs = self
            .jobs
            .lock()
            .map_err(|_| AnalysisFailure::new(AnalysisFailureCode::Internal, "Registry заданий недоступен."))?;
        if jobs.contains_key(job_id) {
            return Err(AnalysisFailure::invalid("Задание с таким идентификатором уже выполняется."));
        }
        let token = Arc::new(JobToken::new(timeout_ms));
        jobs.insert(job_id.to_string(), token.clone());
        Ok(token)
    }

    pub fn cancel(&self, job_id: &str) -> bool {
        let Ok(jobs) = self.jobs.lock() else {
            return false;
        };
        let Some(token) = jobs.get(job_id) else {
            return false;
        };
        token.cancel();
        true
    }

    pub fn finish(&self, job_id: &str) {
        if let Ok(mut jobs) = self.jobs.lock() {
            jobs.remove(job_id);
        }
    }

    #[cfg(test)]
    pub fn active_count(&self) -> usize {
        self.jobs.lock().map(|jobs| jobs.len()).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_cleans_up_and_confirms_cancel() {
        let registry = JobRegistry::default();
        let token = registry.start("job-1", 5_000).unwrap();
        assert_eq!(registry.active_count(), 1);
        assert!(registry.cancel("job-1"));
        assert_eq!(token.checkpoint().unwrap_err().code, AnalysisFailureCode::Cancelled);
        registry.finish("job-1");
        assert_eq!(registry.active_count(), 0);
    }
}
