use super::{
    jobs::JobRegistry,
    rules::{calculate_risk, indicator},
    types::{IndicatorSeverity, RiskLevel},
    url,
};

#[test]
fn risk_score_is_bounded_for_large_synthetic_sets() {
    let values = (0..10_000)
        .map(|index| {
            indicator(
                &format!("property.{index}"),
                "Synthetic",
                "Synthetic",
                "property",
                IndicatorSeverity::Low,
                u16::MAX,
                vec![format!("evidence-{index}")],
                "review",
            )
        })
        .collect::<Vec<_>>();
    let (score, level) = calculate_risk(&values);
    assert_eq!(score, 100);
    assert_eq!(level, RiskLevel::Dangerous);
}

#[test]
fn independent_indicator_order_does_not_change_result() {
    let mut values = (0..128)
        .map(|index| {
            indicator(
                &format!("property.{index}"),
                "Synthetic",
                "Synthetic",
                "property",
                IndicatorSeverity::Info,
                (index % 5) as u16,
                vec![format!("evidence-{index}")],
                "review",
            )
        })
        .collect::<Vec<_>>();
    let first = calculate_risk(&values);
    values.reverse();
    assert_eq!(calculate_risk(&values), first);
}

#[test]
fn duplicate_normalized_indicators_do_not_raise_score() {
    let value = indicator(
        "property.duplicate",
        "Synthetic",
        "Synthetic",
        "property",
        IndicatorSeverity::Medium,
        20,
        vec![
            "kernel32.dll!ExampleApi".to_string(),
            "ExampleApi".to_string(),
        ],
        "review",
    );
    assert_eq!(
        calculate_risk(&[value.clone(), value.clone()]),
        calculate_risk(&[value])
    );
}

#[test]
fn passive_url_never_returns_plaintext_password() {
    for index in 0..128 {
        let password = format!("secret-{index}-value");
        let input = format!("https://user:{password}@example.com/path?q={index}#fragment");
        let registry = JobRegistry::default();
        let token = registry
            .start(&format!("url-property-{index}"), 10_000)
            .unwrap();
        let report = url::analyze_url_passive(input, &token).unwrap();
        let serialized = serde_json::to_string(&report).unwrap();
        assert!(!serialized.contains(&password));
    }
}
