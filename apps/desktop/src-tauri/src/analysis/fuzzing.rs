//! Safe, bounded entry points used only by cargo-fuzz targets.

use super::{
    jobs::JobRegistry,
    rules::{calculate_risk, indicator},
    types::{AnalysisReport, IndicatorSeverity},
    url,
};

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
