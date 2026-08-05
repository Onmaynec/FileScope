use std::{net::IpAddr, time::Duration};

use chrono::Utc;
use reqwest::{header::HeaderMap, redirect::Policy, Client};
use serde_json::json;
use tokio::{net::lookup_host, time::timeout};
use url::{Host, Url};
use uuid::Uuid;

use super::{
    rules::{calculate_risk, indicator},
    types::{
        AnalysisLimits, AnalysisReport, IndicatorSeverity, ObjectKind, ThreatIndicator,
        UrlAnalysis,
    },
};

const SHORTENERS: &[&str] = &[
    "bit.ly",
    "t.co",
    "tinyurl.com",
    "goo.gl",
    "is.gd",
    "cutt.ly",
    "rb.gy",
    "clck.ru",
];
const SUSPICIOUS_TLDS: &[&str] = &[
    "zip", "mov", "top", "xyz", "click", "work", "gq", "tk", "ml", "cf",
];
const REDIRECT_KEYS: &[&str] = &[
    "url", "uri", "redirect", "redirect_url", "target", "next", "continue", "dest",
    "destination", "return", "return_to",
];
const DANGEROUS_PATH_EXTENSIONS: &[&str] = &[
    ".exe", ".scr", ".msi", ".bat", ".cmd", ".ps1", ".js", ".vbs", ".hta", ".lnk",
];

pub fn analyze_url_passive(input: String) -> Result<AnalysisReport, String> {
    let started = std::time::Instant::now();
    let started_at = Utc::now();
    let parsed = parse_http_url(&input)?;
    let mut indicators = Vec::new();
    let details = build_passive_details(&input, &parsed, &mut indicators);
    let (risk_score, risk_level) = calculate_risk(&indicators);

    Ok(AnalysisReport {
        id: Uuid::new_v4().to_string(),
        object_kind: ObjectKind::Url,
        target: input,
        display_name: details.host.clone(),
        started_at: started_at.to_rfc3339(),
        completed_at: Utc::now().to_rfc3339(),
        duration_ms: started.elapsed().as_millis(),
        sha256: None,
        detected_type: Some("HTTP URL".to_string()),
        size_bytes: None,
        risk_level,
        risk_score,
        indicators,
        metadata: json!({
            "networkAccess": false,
            "fragmentPresent": parsed.fragment().is_some(),
            "unicodeInput": !input.is_ascii(),
        }),
        pe: None,
        url: Some(details),
        archive: None,
        is_demo: false,
        limitations: vec![
            "Пассивный анализ не проверяет фактическое содержимое страницы".to_string(),
            "Домен мог измениться после формирования отчёта".to_string(),
        ],
    })
}

pub async fn analyze_url_active(
    input: String,
    limits: AnalysisLimits,
) -> Result<AnalysisReport, String> {
    let started = std::time::Instant::now();
    let started_at = Utc::now();
    let parsed = parse_http_url(&input)?;
    let mut indicators = Vec::new();
    let mut details = build_passive_details(&input, &parsed, &mut indicators);

    let host = details.host.clone();
    let port = parsed.port_or_known_default().unwrap_or(443);
    let lookup_duration = Duration::from_millis(limits.active_url_timeout_ms.min(15_000));
    let resolved = timeout(lookup_duration, lookup_host((host.as_str(), port)))
        .await
        .map_err(|_| "Превышен таймаут DNS-разрешения".to_string())?
        .map_err(|error| format!("DNS-разрешение завершилось ошибкой: {error}"))?;
    let mut addresses = resolved
        .map(|address| address.ip().to_string())
        .collect::<Vec<_>>();
    addresses.sort();
    addresses.dedup();
    details.resolved_addresses = addresses.clone();

    if addresses.is_empty() {
        indicators.push(indicator(
            "url.active.dns-empty",
            "Домен не разрешён в IP-адрес",
            "DNS не вернул адресов для указанного домена.",
            "network",
            IndicatorSeverity::Medium,
            20,
            vec![host.clone()],
            "Проверьте написание домена и повторите проверку позже.",
        ));
    }

    let client = Client::builder()
        .timeout(Duration::from_millis(
            limits.active_url_timeout_ms.clamp(1_000, 30_000),
        ))
        .redirect(Policy::limited(limits.active_url_redirect_limit.min(10)))
        .user_agent("FileScope/0.2.0 (+local-active-check)")
        .build()
        .map_err(|error| format!("Не удалось создать сетевой клиент: {error}"))?;

    let response = match client.head(parsed.clone()).send().await {
        Ok(value) if value.status().as_u16() != 405 => value,
        _ => client
            .get(parsed.clone())
            .header(reqwest::header::RANGE, "bytes=0-0")
            .send()
            .await
            .map_err(|error| format!("Активная проверка завершилась ошибкой: {error}"))?,
    };

    let final_url = response.url().clone();
    let status = response.status().as_u16();
    let headers = select_headers(response.headers());
    details.status_code = Some(status);
    details.final_url = Some(final_url.to_string());
    details.redirect_count = Some(usize::from(final_url.as_str() != parsed.as_str()));
    details.response_headers = headers.clone();
    details.active_check_performed = true;

    if parsed.scheme() == "http" {
        indicators.push(indicator(
            "url.active.unencrypted-http",
            "Соединение использует HTTP без шифрования",
            "Адрес не защищён TLS, поэтому содержимое и параметры могут быть перехвачены или изменены в сети.",
            "transport",
            IndicatorSeverity::High,
            35,
            vec![parsed.to_string()],
            "Не вводите пароли и не загружайте файлы через это соединение.",
        ));
    }
    if final_url.host_str() != parsed.host_str() {
        indicators.push(indicator(
            "url.active.cross-domain-redirect",
            "Перенаправление ведёт на другой домен",
            "Итоговый домен отличается от исходного адреса.",
            "redirect",
            IndicatorSeverity::Medium,
            24,
            vec![
                format!("Исходный: {}", parsed.host_str().unwrap_or("")),
                format!("Итоговый: {}", final_url.host_str().unwrap_or("")),
            ],
            "Проверьте итоговый домен до продолжения.",
        ));
    }
    if status >= 400 {
        indicators.push(indicator(
            "url.active.http-error",
            "Сервер вернул ошибку HTTP",
            "Статус ответа указывает на ошибку клиента или сервера.",
            "network",
            IndicatorSeverity::Low,
            10,
            vec![format!("HTTP {status}")],
            "Повторите проверку позже или уточните адрес.",
        ));
    }
    if final_url.scheme() == "https"
        && !headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("strict-transport-security"))
    {
        indicators.push(indicator(
            "url.active.hsts-missing",
            "HSTS не объявлен",
            "HTTPS-сервер не прислал заголовок Strict-Transport-Security.",
            "transport",
            IndicatorSeverity::Info,
            4,
            vec![final_url.to_string()],
            "Это дополнительный сигнал конфигурации, а не доказательство угрозы.",
        ));
    }

    let (risk_score, risk_level) = calculate_risk(&indicators);
    Ok(AnalysisReport {
        id: Uuid::new_v4().to_string(),
        object_kind: ObjectKind::Url,
        target: input,
        display_name: host,
        started_at: started_at.to_rfc3339(),
        completed_at: Utc::now().to_rfc3339(),
        duration_ms: started.elapsed().as_millis(),
        sha256: None,
        detected_type: Some("HTTP URL with active network check".to_string()),
        size_bytes: None,
        risk_level,
        risk_score,
        indicators,
        metadata: json!({
            "networkAccess": true,
            "dnsAddresses": addresses,
            "requestBodyDownloaded": false,
        }),
        pe: None,
        url: Some(details),
        archive: None,
        is_demo: false,
        limitations: vec![
            "Активная проверка не выполняет JavaScript и не загружает страницу целиком".to_string(),
            "Сервер увидел IP-адрес устройства, выполнившего проверку".to_string(),
        ],
    })
}

fn parse_http_url(input: &str) -> Result<Url, String> {
    let parsed = Url::parse(input.trim()).map_err(|error| format!("Некорректный URL: {error}"))?;
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return Err("Поддерживаются только HTTP- и HTTPS-ссылки".to_string());
    }
    if parsed.host().is_none() {
        return Err("URL не содержит домен или IP-адрес".to_string());
    }
    Ok(parsed)
}

fn build_passive_details(
    input: &str,
    parsed: &Url,
    indicators: &mut Vec<ThreatIndicator>,
) -> UrlAnalysis {
    let host = parsed.host_str().unwrap_or("").trim_end_matches('.').to_ascii_lowercase();
    let host_is_ip = match parsed.host() {
        Some(Host::Ipv4(_)) | Some(Host::Ipv6(_)) => true,
        _ => host.parse::<IpAddr>().is_ok(),
    };
    let contains_punycode = host.split('.').any(|part| part.starts_with("xn--"));
    let labels = host.split('.').filter(|part| !part.is_empty()).collect::<Vec<_>>();
    let subdomain_count = labels.len().saturating_sub(2);
    let has_credentials = !parsed.username().is_empty() || parsed.password().is_some();
    let query_pairs = parsed.query_pairs().collect::<Vec<_>>();
    let redirect_parameters = query_pairs
        .iter()
        .filter(|(key, value)| {
            REDIRECT_KEYS.contains(&key.to_ascii_lowercase().as_str())
                || value.starts_with("http://")
                || value.starts_with("https://")
        })
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>();

    if input.len() > 220 {
        indicators.push(indicator(
            "url.length.excessive",
            "Необычно длинный URL",
            "Очень длинные адреса усложняют визуальную проверку и могут скрывать важные параметры.",
            "structure",
            IndicatorSeverity::Medium,
            16,
            vec![format!("Длина: {} символов", input.len())],
            "Сократите адрес до основного домена и проверьте параметры отдельно.",
        ));
    }
    if contains_punycode || !input.is_ascii() {
        indicators.push(indicator(
            "url.host.idn",
            "Домен содержит IDN/Punycode",
            "Интернационализированный домен может быть легитимным, но также используется для визуальной подмены символов.",
            "hostname",
            IndicatorSeverity::Medium,
            22,
            vec![host.clone()],
            "Сравните домен с официальным адресом организации посимвольно.",
        ));
    }
    if host_is_ip {
        indicators.push(indicator(
            "url.host.ip-address",
            "Вместо домена используется IP-адрес",
            "Прямой IP-адрес затрудняет проверку владельца ресурса.",
            "hostname",
            IndicatorSeverity::Medium,
            18,
            vec![host.clone()],
            "Не вводите учётные данные, пока не подтвердите назначение адреса.",
        ));
    }
    if has_credentials {
        indicators.push(indicator(
            "url.credentials.embedded",
            "В URL встроены учётные данные",
            "Часть до символа @ может отвлекать от настоящего домена и раскрывать логин или пароль.",
            "structure",
            IndicatorSeverity::High,
            40,
            vec![parsed.as_str().to_string()],
            "Не открывайте адрес и удалите встроенные учётные данные.",
        ));
    }
    if subdomain_count >= 4 {
        indicators.push(indicator(
            "url.host.many-subdomains",
            "Необычно много поддоменов",
            "Длинная цепочка поддоменов может маскировать основной зарегистрированный домен.",
            "hostname",
            IndicatorSeverity::Medium,
            16,
            vec![format!("Поддоменов: {subdomain_count}"), host.clone()],
            "Проверяйте домен справа налево и найдите фактическую зону регистрации.",
        ));
    }
    if SHORTENERS.contains(&host.as_str()) {
        indicators.push(indicator(
            "url.host.shortener",
            "Использован сокращатель ссылок",
            "Короткий адрес скрывает итоговый домен до сетевого обращения.",
            "redirect",
            IndicatorSeverity::Medium,
            20,
            vec![host.clone()],
            "Запустите ручную активную проверку или запросите прямую ссылку.",
        ));
    }
    if let Some(tld) = labels.last() {
        if SUSPICIOUS_TLDS.contains(tld) {
            indicators.push(indicator(
                "url.host.unusual-tld",
                "Домен использует зону повышенного внимания",
                "Эта доменная зона часто встречается в краткоживущих или маскирующих адресах. Легитимные сайты также могут её использовать.",
                "hostname",
                IndicatorSeverity::Low,
                10,
                vec![format!("TLD: .{tld}")],
                "Оцените репутацию и происхождение ссылки.",
            ));
        }
    }
    if !redirect_parameters.is_empty() {
        indicators.push(indicator(
            "url.query.redirect-target",
            "В параметрах найден вложенный адрес",
            "Параметры могут перенаправить пользователя на другой ресурс.",
            "redirect",
            IndicatorSeverity::Medium,
            20,
            redirect_parameters.clone(),
            "Проверьте вложенный адрес отдельно до открытия ссылки.",
        ));
    }
    let lowercase_path = parsed.path().to_ascii_lowercase();
    if DANGEROUS_PATH_EXTENSIONS
        .iter()
        .any(|extension| lowercase_path.ends_with(extension))
    {
        indicators.push(indicator(
            "url.path.executable-download",
            "Ссылка похожа на прямую загрузку исполняемого файла",
            "Путь URL заканчивается расширением, которое может запускать код в Windows.",
            "download",
            IndicatorSeverity::High,
            32,
            vec![parsed.path().to_string()],
            "Скачивайте приложение только с официального сайта и затем проверьте сам файл.",
        ));
    }
    let encoded_count = input.matches('%').count();
    if encoded_count >= 6 {
        indicators.push(indicator(
            "url.encoding.excessive",
            "Много кодированных символов",
            "Процентное кодирование может скрывать читаемую структуру адреса.",
            "structure",
            IndicatorSeverity::Low,
            10,
            vec![format!("Последовательностей с %: {encoded_count}")],
            "Декодируйте и проверьте параметры адреса.",
        ));
    }

    UrlAnalysis {
        normalized_url: parsed.to_string(),
        scheme: parsed.scheme().to_string(),
        host,
        port: parsed.port_or_known_default(),
        path: parsed.path().to_string(),
        query_parameters: query_pairs.len(),
        contains_punycode,
        host_is_ip,
        has_credentials,
        subdomain_count,
        redirect_parameters,
        resolved_addresses: Vec::new(),
        final_url: None,
        status_code: None,
        response_headers: Vec::new(),
        redirect_count: None,
        active_check_performed: false,
    }
}

fn select_headers(headers: &HeaderMap) -> Vec<(String, String)> {
    [
        "content-type",
        "content-length",
        "location",
        "server",
        "strict-transport-security",
        "content-security-policy",
        "x-content-type-options",
        "referrer-policy",
    ]
    .iter()
    .filter_map(|name| {
        headers.get(*name).and_then(|value| {
            value
                .to_str()
                .ok()
                .map(|text| ((*name).to_string(), text.chars().take(512).collect()))
        })
    })
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passive_analysis_does_not_access_network() {
        let report = analyze_url_passive("https://example.com/path".to_string()).unwrap();
        assert_eq!(report.metadata["networkAccess"], false);
        assert_eq!(report.url.unwrap().active_check_performed, false);
    }

    #[test]
    fn detects_embedded_credentials_and_redirect_parameter() {
        let report = analyze_url_passive(
            "https://login@example.com/open?redirect=https%3A%2F%2Fevil.test".to_string(),
        )
        .unwrap();
        assert!(report
            .indicators
            .iter()
            .any(|item| item.id == "url.credentials.embedded"));
        assert!(report
            .indicators
            .iter()
            .any(|item| item.id == "url.query.redirect-target"));
    }

    #[test]
    fn rejects_non_http_protocols() {
        assert!(analyze_url_passive("file:///etc/passwd".to_string()).is_err());
    }
}
