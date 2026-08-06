use std::collections::HashSet;

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
    let mut value = ThreatIndicator {
        id: id.to_string(),
        title: title.to_string(),
        description: description.to_string(),
        category: category.to_string(),
        severity,
        score,
        evidence,
        recommendation: recommendation.to_string(),
    };

    deduplicate_evidence(&mut value.evidence);
    normalize_pe_indicator(&mut value);
    normalize_analysis_status(&mut value);
    value
}

fn deduplicate_evidence(evidence: &mut Vec<String>) {
    let mut seen = HashSet::new();
    evidence.retain(|value| seen.insert(normalize_evidence_key(value)));
}

fn normalize_evidence_key(value: &str) -> String {
    value
        .trim()
        .rsplit('!')
        .next()
        .unwrap_or(value)
        .trim()
        .to_ascii_lowercase()
}

fn indicator_key(indicator: &ThreatIndicator) -> String {
    let mut evidence = indicator
        .evidence
        .iter()
        .map(|value| normalize_evidence_key(value))
        .collect::<Vec<_>>();
    evidence.sort();
    evidence.dedup();
    format!("{}|{}", indicator.id, evidence.join("|"))
}

fn normalize_pe_indicator(indicator: &mut ThreatIndicator) {
    match indicator.id.as_str() {
        "pe.signature.missing" => {
            indicator.severity = IndicatorSeverity::Low;
            indicator.score = 6;
            indicator.description = "Исполняемый PE-файл не содержит таблицу Authenticode. Это распространено у portable-приложений и небольших проектов и само по себе не является признаком вредоносности.".to_string();
            indicator.recommendation = "Проверьте официальный источник и SHA-256. Для публичных релизов предпочтительна подпись доверенного издателя.".to_string();
        }
        "pe.imports.suspicious" => normalize_sensitive_imports(indicator),
        _ => {}
    }
}

fn normalize_analysis_status(indicator: &mut ThreatIndicator) {
    if indicator.category == "limits" || indicator.category == "analysis-status" {
        indicator.category = "analysis-status".to_string();
        indicator.severity = IndicatorSeverity::Info;
        indicator.score = 0;
    }
}

fn normalize_sensitive_imports(indicator: &mut ThreatIndicator) {
    let names = indicator
        .evidence
        .iter()
        .map(|value| normalize_evidence_key(value))
        .collect::<Vec<_>>();

    let has = |candidates: &[&str]| {
        candidates.iter().any(|candidate| {
            names
                .iter()
                .any(|name| name == &candidate.to_ascii_lowercase())
        })
    };

    let allocation = has(&["VirtualAllocEx"]);
    let write = has(&["WriteProcessMemory", "NtWriteVirtualMemory"]);
    let remote_execution = has(&["CreateRemoteThread", "NtCreateThreadEx"]);
    let download = has(&[
        "URLDownloadToFileA",
        "URLDownloadToFileW",
        "InternetOpenUrlA",
        "InternetOpenUrlW",
    ]);
    let launch = has(&["WinExec", "ShellExecuteA", "ShellExecuteW"]);

    if allocation && write && remote_execution {
        indicator.title = "Обнаружена комбинация API внедрения в другой процесс".to_string();
        indicator.description = "Файл одновременно импортирует функции выделения памяти в другом процессе, записи в неё и удалённого запуска потока. Такая комбинация существенно сильнее одиночного импорта.".to_string();
        indicator.severity = IndicatorSeverity::High;
        indicator.score = 52;
        indicator.recommendation = "Не запускайте файл до проверки происхождения, подписи и поведения в изолированной среде.".to_string();
        return;
    }

    if download && launch {
        indicator.title = "Обнаружена комбинация загрузки и запуска".to_string();
        indicator.description = "Файл импортирует API получения данных из сети вместе с API запуска файлов или команд. Это требует повышенного внимания, хотя встречается у легитимных установщиков и обновляторов.".to_string();
        indicator.severity = IndicatorSeverity::High;
        indicator.score = 46;
        indicator.recommendation =
            "Проверьте цифровую подпись, официальный источник и назначение программы до запуска."
                .to_string();
        return;
    }

    let injection_parts = [allocation, write, remote_execution]
        .into_iter()
        .filter(|present| *present)
        .count();
    if injection_parts >= 2 {
        indicator.title = "Найдена неполная комбинация API работы с чужим процессом".to_string();
        indicator.description = "Несколько связанных API могут применяться для отладки, защиты, оверлеев и внедрения кода. Без полного набора и поведенческого анализа это не является доказательством угрозы.".to_string();
        indicator.severity = IndicatorSeverity::Medium;
        indicator.score = 16;
        indicator.recommendation =
            "Сопоставьте признак с подписью, происхождением файла и другими результатами."
                .to_string();
        return;
    }

    indicator.title = "Используются системные API повышенного внимания".to_string();
    indicator.description = "Одиночные импорты вроде VirtualAlloc или ShellExecute встречаются в браузерах, установщиках, мессенджерах и Tauri-приложениях. Без опасной комбинации они являются контекстом, а не доказательством вредоносности.".to_string();
    indicator.severity = IndicatorSeverity::Info;
    indicator.score = (indicator.evidence.len() as u16 * 2).clamp(2, 10);
    indicator.recommendation =
        "Учитывайте цифровую подпись, источник файла и сочетание с другими признаками.".to_string();
}

fn contributes_to_threat_score(indicator: &ThreatIndicator) -> bool {
    indicator.category != "analysis-status"
}

pub fn calculate_risk(indicators: &[ThreatIndicator]) -> (u16, RiskLevel) {
    let mut seen = HashSet::new();
    let unique = indicators
        .iter()
        .filter(|indicator| seen.insert(indicator_key(indicator)))
        .collect::<Vec<_>>();
    let scoring = unique
        .iter()
        .copied()
        .filter(|indicator| contributes_to_threat_score(indicator))
        .collect::<Vec<_>>();

    let score = scoring
        .iter()
        .fold(0_u16, |total, indicator| {
            total.saturating_add(indicator.score)
        })
        .min(100);

    let has_critical = scoring
        .iter()
        .any(|indicator| indicator.severity == IndicatorSeverity::Critical);
    let has_high = scoring
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

    fn test_indicator(
        id: &str,
        severity: IndicatorSeverity,
        score: u16,
        evidence: Vec<&str>,
    ) -> ThreatIndicator {
        indicator(
            id,
            "Исходный заголовок",
            "Исходное описание",
            "test",
            severity,
            score,
            evidence.into_iter().map(str::to_string).collect(),
            "Исходная рекомендация",
        )
    }

    #[test]
    fn critical_indicator_always_produces_dangerous_risk() {
        let values = vec![test_indicator(
            "test.critical",
            IndicatorSeverity::Critical,
            10,
            vec![],
        )];
        assert_eq!(calculate_risk(&values).1, RiskLevel::Dangerous);
    }

    #[test]
    fn low_score_remains_without_detected_threats() {
        let values = vec![test_indicator(
            "test.info",
            IndicatorSeverity::Info,
            5,
            vec![],
        )];
        assert_eq!(calculate_risk(&values).1, RiskLevel::NoThreatsFound);
    }

    #[test]
    fn operational_limit_is_normalized_and_does_not_become_threat_verdict() {
        let value = indicator(
            "file.size.limit-exceeded",
            "Limit",
            "Limit",
            "limits",
            IndicatorSeverity::High,
            45,
            vec!["size".to_string()],
            "review",
        );
        assert_eq!(value.category, "analysis-status");
        assert_eq!(value.severity, IndicatorSeverity::Info);
        assert_eq!(value.score, 0);
        assert_eq!(calculate_risk(&[value]), (0, RiskLevel::NoThreatsFound));
    }

    #[test]
    fn missing_signature_is_context_not_malware_verdict() {
        let value = test_indicator(
            "pe.signature.missing",
            IndicatorSeverity::Medium,
            16,
            vec!["Каталог сертификатов отсутствует"],
        );
        assert_eq!(value.severity, IndicatorSeverity::Low);
        assert_eq!(value.score, 6);
    }

    #[test]
    fn telegram_like_virtual_alloc_does_not_become_high_risk() {
        let values = vec![test_indicator(
            "pe.imports.suspicious",
            IndicatorSeverity::High,
            34,
            vec!["kernel32.dll!VirtualAlloc"],
        )];
        assert_eq!(values[0].severity, IndicatorSeverity::Info);
        assert!(values[0].score < 15);
        assert_eq!(calculate_risk(&values).1, RiskLevel::NoThreatsFound);
    }

    #[test]
    fn filescope_like_unsigned_shell_execute_does_not_become_high_risk() {
        let values = vec![
            test_indicator(
                "pe.signature.missing",
                IndicatorSeverity::Medium,
                16,
                vec!["Каталог сертификатов отсутствует"],
            ),
            test_indicator(
                "pe.imports.suspicious",
                IndicatorSeverity::High,
                34,
                vec!["shell32.dll!ShellExecuteW"],
            ),
        ];
        assert_eq!(calculate_risk(&values), (8, RiskLevel::NoThreatsFound));
    }

    #[test]
    fn duplicate_import_evidence_is_counted_once() {
        let value = test_indicator(
            "pe.imports.suspicious",
            IndicatorSeverity::High,
            34,
            vec![
                "kernel32.dll!VirtualAlloc",
                "KERNELBASE.dll!virtualalloc",
                "kernel32.dll!VirtualAlloc",
            ],
        );
        assert_eq!(value.evidence, vec!["kernel32.dll!VirtualAlloc"]);
        assert_eq!(value.score, 2);
        assert_eq!(value.severity, IndicatorSeverity::Info);
    }

    #[test]
    fn duplicate_indicators_do_not_inflate_total_score() {
        let value = test_indicator(
            "file.entropy.high",
            IndicatorSeverity::Medium,
            18,
            vec!["Энтропия: 7.90"],
        );
        assert_eq!(
            calculate_risk(&[value.clone(), value]),
            (18, RiskLevel::Caution)
        );
    }

    #[test]
    fn complete_injection_chain_remains_high_risk() {
        let values = vec![test_indicator(
            "pe.imports.suspicious",
            IndicatorSeverity::High,
            34,
            vec![
                "kernel32.dll!VirtualAllocEx",
                "kernel32.dll!WriteProcessMemory",
                "kernel32.dll!CreateRemoteThread",
                "KERNELBASE.dll!CreateRemoteThread",
            ],
        )];
        assert_eq!(values[0].severity, IndicatorSeverity::High);
        assert_eq!(values[0].score, 52);
        assert_eq!(values[0].evidence.len(), 3);
        assert_eq!(calculate_risk(&values).1, RiskLevel::HighRisk);
    }

    #[test]
    fn download_and_execute_chain_remains_high_risk() {
        let values = vec![test_indicator(
            "pe.imports.suspicious",
            IndicatorSeverity::High,
            34,
            vec!["urlmon.dll!URLDownloadToFileW", "shell32.dll!ShellExecuteW"],
        )];
        assert_eq!(values[0].severity, IndicatorSeverity::High);
        assert_eq!(values[0].score, 46);
        assert_eq!(calculate_risk(&values).1, RiskLevel::HighRisk);
    }
}
