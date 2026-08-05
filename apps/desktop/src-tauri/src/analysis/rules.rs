use super::types::{IndicatorSeverity, RiskLevel, ThreatIndicator};

pub fn indicator(
    id: &str,
    title: &str,
    description: &str,
    category: &str,
    severity: IndicatorSeverity,
    score: u16,
    evidence: Vec<String>,
    recommendation: &str,
) -> ThreatIndicator {
    ThreatIndicator {
        id: id.to_string(),
        title: title.to_string(),
        description: description.to_string(),
        category: category.to_string(),
        severity,
        score,
        evidence,
        recommendation: recommendation.to_string(),
    }
}

pub fn calculate_risk(indicators: &[ThreatIndicator]) -> (u16, RiskLevel) {
    let score = indicators
        .iter()
        .map(|indicator| indicator.score)
        .sum::<u16>()
        .min(100);

    let has_critical = indicators
        .iter()
        .any(|indicator| indicator.severity == IndicatorSeverity::Critical);
    let has_high = indicators
        .iter()
        .any(|indicator| indicator.severity == IndicatorSeverity::High);

    let level = if has_critical || score >= 80 {
        RiskLevel::Dangerous
    } else if has_high || score >= 45 {
        RiskLevel::HighRisk
    } else if score >= 15 {
        RiskLevel::Caution
    } else {
        RiskLevel::NoThreatsFound
    };

    (score, level)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn critical_indicator_always_produces_dangerous_risk() {
        let values = vec![indicator(
            "test.critical",
            "Критический признак",
            "Тест",
            "test",
            IndicatorSeverity::Critical,
            10,
            vec![],
            "Проверить объект",
        )];
        assert_eq!(calculate_risk(&values).1, RiskLevel::Dangerous);
    }

    #[test]
    fn low_score_remains_without_detected_threats() {
        let values = vec![indicator(
            "test.info",
            "Информация",
            "Тест",
            "test",
            IndicatorSeverity::Info,
            5,
            vec![],
            "Нет действий",
        )];
        assert_eq!(calculate_risk(&values).1, RiskLevel::NoThreatsFound);
    }
}
