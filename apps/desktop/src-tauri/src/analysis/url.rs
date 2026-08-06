use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use chrono::Utc;
use reqwest::{
    header::{HeaderMap, LOCATION},
    redirect::Policy,
    Client, Response, StatusCode,
};
use serde_json::json;
use tokio::{net::lookup_host, time::timeout};
use url::{Host, Url};
use uuid::Uuid;

use super::{
    jobs::{AnalysisFailure, AnalysisFailureCode, JobToken},
    rules::{calculate_risk, indicator},
    types::{
        app_version, report_created_by, AnalysisCompleteness, AnalysisLimits, AnalysisReport,
        IndicatorSeverity, ObjectKind, ThreatIndicator, UrlAnalysis, ANALYZER_VERSION,
        REPORT_SCHEMA_VERSION, RULE_SET_VERSION,
    },
};

const MAXIMUM_URL_LENGTH: usize = 4096;
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
    "url",
    "uri",
    "redirect",
    "redirect_url",
    "target",
    "next",
    "continue",
    "dest",
    "destination",
    "return",
    "return_to",
];
const DANGEROUS_PATH_EXTENSIONS: &[&str] = &[
    ".exe", ".scr", ".msi", ".bat", ".cmd", ".ps1", ".js", ".vbs", ".hta", ".lnk",
];
const MULTI_LABEL_PUBLIC_SUFFIXES: &[&str] = &[
    "co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "net.au", "org.au", "co.jp", "co.nz", "com.br",
    "com.cn", "com.sg", "com.tr", "co.in", "co.za", "com.mx", "com.ua", "com.pl",
];

pub fn analyze_url_passive(
    input: String,
    token: &JobToken,
) -> Result<AnalysisReport, AnalysisFailure> {
    token.checkpoint()?;
    let started = std::time::Instant::now();
    let started_at = Utc::now();
    let parsed = parse_http_url(&input)?;
    let redacted = redacted_url(&parsed);
    let unicode_input = !input.is_ascii();
    let mut indicators = Vec::new();
    let details = build_passive_details(&input, &parsed, &mut indicators);
    token.checkpoint()?;
    let (risk_score, risk_level) = calculate_risk(&indicators);

    Ok(AnalysisReport {
        schema_version: REPORT_SCHEMA_VERSION,
        app_version: app_version(),
        analyzer_version: ANALYZER_VERSION.to_string(),
        rule_set_version: RULE_SET_VERSION.to_string(),
        created_by: report_created_by(),
        analysis_completeness: AnalysisCompleteness::Complete,
        id: Uuid::new_v4().to_string(),
        object_kind: ObjectKind::Url,
        target: redacted,
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
            "unicodeInput": unicode_input,
            "credentialsRedacted": !parsed.username().is_empty() || parsed.password().is_some(),
            "canonicalRuntime": "rust"
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
    token: &JobToken,
) -> Result<AnalysisReport, AnalysisFailure> {
    token.checkpoint()?;
    let started = std::time::Instant::now();
    let started_at = Utc::now();
    let parsed = parse_http_url(&input)?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(AnalysisFailure::security(
            "FileScope не отправляет встроенные в URL логин или пароль. Удалите credentials и повторите активную проверку.",
        ));
    }
    validate_active_target(&parsed, None)?;

    let mut indicators = Vec::new();
    let mut details = build_passive_details(&input, &parsed, &mut indicators);
    let mut current = parsed.clone();
    current.set_fragment(None);
    let mut redirect_count = 0_usize;
    let mut resolved_addresses = Vec::<String>::new();
    let final_response = loop {
        token.checkpoint()?;
        validate_active_target(&current, Some(&parsed))?;
        let addresses = resolve_public_addresses(&current, &limits, token).await?;
        for address in &addresses {
            let text = address.to_string();
            if !resolved_addresses.contains(&text) {
                resolved_addresses.push(text);
            }
        }
        let client = pinned_client(&current, addresses[0], &limits, token)?;
        let response = send_probe(&client, &current, token).await?;
        if !response.status().is_redirection() {
            break response;
        }
        if redirect_count >= limits.active_url_redirect_limit.min(10) {
            return Err(AnalysisFailure::new(
                AnalysisFailureCode::Network,
                "Активная проверка остановлена: превышен защитный лимит redirect.",
            ));
        }
        let Some(location) = response.headers().get(LOCATION) else {
            break response;
        };
        let location = location.to_str().map_err(|_| {
            AnalysisFailure::network("Redirect содержит некорректный заголовок Location.")
        })?;
        let next = current.join(location).map_err(|error| {
            AnalysisFailure::network(format!("Некорректный redirect URL: {error}"))
        })?;
        validate_active_target(&next, Some(&current))?;
        redirect_count += 1;
        current = next;
    };

    token.checkpoint()?;
    let final_url = final_response.url().clone();
    let status = final_response.status().as_u16();
    let headers = select_headers(final_response.headers());
    details.resolved_addresses = resolved_addresses.clone();
    details.status_code = Some(status);
    details.final_url = Some(redacted_url(&final_url));
    details.redirect_count = Some(redirect_count);
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
            vec![redacted_url(&parsed)],
            "Не вводите пароли и не загружайте файлы через это соединение.",
        ));
    }
    if final_url.host_str() != parsed.host_str() {
        indicators.push(indicator(
            "url.active.cross-domain-redirect",
            "Перенаправление ведёт на другой домен",
            "Итоговый домен отличается от исходного адреса; каждый redirect был повторно проверен и закреплён за разрешённым IP.",
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
            vec![redacted_url(&final_url)],
            "Это дополнительный сигнал конфигурации, а не доказательство угрозы.",
        ));
    }

    let (risk_score, risk_level) = calculate_risk(&indicators);
    Ok(AnalysisReport {
        schema_version: REPORT_SCHEMA_VERSION,
        app_version: app_version(),
        analyzer_version: ANALYZER_VERSION.to_string(),
        rule_set_version: RULE_SET_VERSION.to_string(),
        created_by: report_created_by(),
        analysis_completeness: AnalysisCompleteness::Complete,
        id: Uuid::new_v4().to_string(),
        object_kind: ObjectKind::Url,
        target: redacted_url(&parsed),
        display_name: details.host.clone(),
        started_at: started_at.to_rfc3339(),
        completed_at: Utc::now().to_rfc3339(),
        duration_ms: started.elapsed().as_millis(),
        sha256: None,
        detected_type: Some("HTTP URL with protected active network check".to_string()),
        size_bytes: None,
        risk_level,
        risk_score,
        indicators,
        metadata: json!({
            "networkAccess": true,
            "dnsAddresses": resolved_addresses,
            "requestBodyDownloaded": false,
            "manualRedirectValidation": true,
            "dnsPinnedPerHop": true,
            "privateAddressBlocking": true,
            "credentialsSent": false
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

async fn resolve_public_addresses(
    target: &Url,
    limits: &AnalysisLimits,
    token: &JobToken,
) -> Result<Vec<IpAddr>, AnalysisFailure> {
    token.checkpoint()?;
    let host = target
        .host()
        .ok_or_else(|| AnalysisFailure::invalid("URL не содержит host."))?;
    let port = target.port_or_known_default().unwrap_or(443);
    let mut addresses = match host {
        Host::Ipv4(address) => vec![IpAddr::V4(address)],
        Host::Ipv6(address) => vec![IpAddr::V6(address)],
        Host::Domain(domain) => {
            if is_sensitive_hostname(domain) {
                return Err(AnalysisFailure::security(
                    "FileScope не выполняет активные запросы к локальным и служебным hostnames.",
                ));
            }
            let duration = Duration::from_millis(limits.active_url_timeout_ms.clamp(1_000, 15_000))
                .min(token.remaining());
            let lookup = timeout(duration, lookup_host((domain, port)));
            let resolved = tokio::select! {
                _ = token.cancelled() => return Err(AnalysisFailure::cancelled()),
                result = lookup => result
                    .map_err(|_| AnalysisFailure::timeout())?
                    .map_err(|error| AnalysisFailure::network(format!("DNS-разрешение завершилось ошибкой: {error}")))?,
            };
            resolved.map(|address| address.ip()).collect::<Vec<_>>()
        }
    };
    addresses.sort();
    addresses.dedup();
    if addresses.is_empty() {
        return Err(AnalysisFailure::network(
            "DNS не вернул ни одного IP-адреса.",
        ));
    }
    if addresses.iter().any(|address| is_forbidden_ip(*address)) {
        return Err(AnalysisFailure::security(
            "FileScope не выполняет активные запросы к localhost, private, link-local, multicast, metadata и другим служебным адресам.",
        ));
    }
    Ok(addresses)
}

fn pinned_client(
    target: &Url,
    address: IpAddr,
    limits: &AnalysisLimits,
    token: &JobToken,
) -> Result<Client, AnalysisFailure> {
    let host = target
        .host_str()
        .ok_or_else(|| AnalysisFailure::invalid("URL не содержит host."))?;
    let port = target.port_or_known_default().unwrap_or(443);
    let timeout = Duration::from_millis(limits.active_url_timeout_ms.clamp(1_000, 30_000))
        .min(token.remaining());
    let mut builder = Client::builder()
        .timeout(timeout)
        .redirect(Policy::none())
        .user_agent(format!("FileScope/{} (+local-active-check)", app_version()));
    if matches!(target.host(), Some(Host::Domain(_))) {
        builder = builder.resolve(host, SocketAddr::new(address, port));
    }
    builder.build().map_err(|error| {
        AnalysisFailure::network(format!(
            "Не удалось создать защищённый сетевой клиент: {error}"
        ))
    })
}

async fn send_probe(
    client: &Client,
    target: &Url,
    token: &JobToken,
) -> Result<Response, AnalysisFailure> {
    token.checkpoint()?;
    let head = tokio::select! {
        _ = token.cancelled() => return Err(AnalysisFailure::cancelled()),
        result = client.head(target.clone()).send() => result,
    };
    if let Ok(response) = head {
        if response.status() != StatusCode::METHOD_NOT_ALLOWED
            && response.status() != StatusCode::NOT_IMPLEMENTED
        {
            return Ok(response);
        }
    }
    token.checkpoint()?;
    tokio::select! {
        _ = token.cancelled() => Err(AnalysisFailure::cancelled()),
        result = client
            .get(target.clone())
            .header(reqwest::header::RANGE, "bytes=0-0")
            .send() => result.map_err(|error| AnalysisFailure::network(format!("Активная проверка завершилась ошибкой: {error}"))),
    }
}

fn validate_active_target(target: &Url, previous: Option<&Url>) -> Result<(), AnalysisFailure> {
    if target.scheme() != "http" && target.scheme() != "https" {
        return Err(AnalysisFailure::security(
            "Redirect на схему, отличную от HTTP/HTTPS, заблокирован.",
        ));
    }
    if !target.username().is_empty() || target.password().is_some() {
        return Err(AnalysisFailure::security(
            "Redirect со встроенными credentials заблокирован.",
        ));
    }
    if let Some(port) = target.port() {
        if port != 80 && port != 443 {
            return Err(AnalysisFailure::security(
                "Активная проверка разрешает только стандартные HTTP/HTTPS порты 80 и 443.",
            ));
        }
    }
    if let Some(previous) = previous {
        if previous.scheme() == "https" && target.scheme() == "http" {
            return Err(AnalysisFailure::security(
                "Redirect с HTTPS на незашифрованный HTTP заблокирован.",
            ));
        }
    }
    if let Some(host) = target.host_str() {
        if is_sensitive_hostname(host) {
            return Err(AnalysisFailure::security(
                "Локальный или служебный hostname заблокирован.",
            ));
        }
    }
    Ok(())
}

fn parse_http_url(input: &str) -> Result<Url, AnalysisFailure> {
    let input = input.trim();
    if input.is_empty() || input.len() > MAXIMUM_URL_LENGTH {
        return Err(AnalysisFailure::invalid(format!(
            "URL должен содержать от 1 до {MAXIMUM_URL_LENGTH} символов."
        )));
    }
    if input.chars().any(is_forbidden_url_character) {
        return Err(AnalysisFailure::invalid(
            "URL содержит управляющие или bidi-символы и не может быть безопасно отображён.",
        ));
    }
    let parsed = Url::parse(input)
        .map_err(|error| AnalysisFailure::invalid(format!("Некорректный URL: {error}")))?;
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return Err(AnalysisFailure::invalid(
            "Поддерживаются только HTTP- и HTTPS-ссылки.",
        ));
    }
    if parsed.host().is_none() {
        return Err(AnalysisFailure::invalid(
            "URL не содержит домен или IP-адрес.",
        ));
    }
    Ok(parsed)
}

fn is_forbidden_url_character(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{202A}'
                | '\u{202B}'
                | '\u{202C}'
                | '\u{202D}'
                | '\u{202E}'
                | '\u{2066}'
                | '\u{2067}'
                | '\u{2068}'
                | '\u{2069}'
        )
}

fn build_passive_details(
    input: &str,
    parsed: &Url,
    indicators: &mut Vec<ThreatIndicator>,
) -> UrlAnalysis {
    let ascii_host = parsed
        .host_str()
        .unwrap_or("")
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let unicode_host = idna::domain_to_unicode(&ascii_host).0;
    let host_is_ip = matches!(parsed.host(), Some(Host::Ipv4(_)) | Some(Host::Ipv6(_)))
        || ascii_host.parse::<IpAddr>().is_ok();
    let contains_punycode = ascii_host.split('.').any(|part| part.starts_with("xn--"));
    let registrable_domain = registrable_domain(&ascii_host, host_is_ip);
    let labels = ascii_host
        .split('.')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    let registrable_labels = registrable_domain
        .as_deref()
        .map(|domain| domain.split('.').count())
        .unwrap_or(labels.len());
    let subdomain_count = labels.len().saturating_sub(registrable_labels);
    let has_credentials = !parsed.username().is_empty() || parsed.password().is_some();
    let query_pairs = parsed.query_pairs().collect::<Vec<_>>();
    let redirect_parameters = query_pairs
        .iter()
        .filter(|(key, value)| {
            REDIRECT_KEYS.contains(&key.to_ascii_lowercase().as_str())
                || value.starts_with("http://")
                || value.starts_with("https://")
        })
        .map(|(key, value)| format!("{key}={}", redact_nested_url(value)))
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
            vec![format!("ASCII: {ascii_host}"), format!("Unicode: {unicode_host}")],
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
            vec![ascii_host.clone()],
            "Не вводите учётные данные, пока не подтвердите назначение адреса.",
        ));
    }
    if has_credentials {
        indicators.push(indicator(
            "url.credentials.embedded",
            "В URL встроены учётные данные",
            "Часть до символа @ может отвлекать от настоящего домена. Значение пароля удалено из evidence, истории и экспорта.",
            "structure",
            IndicatorSeverity::High,
            40,
            vec![redacted_url(parsed)],
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
            vec![
                format!("Поддоменов: {subdomain_count}"),
                format!(
                    "Registrable domain: {}",
                    registrable_domain.as_deref().unwrap_or("не определён")
                ),
            ],
            "Проверяйте registrable domain и источник ссылки.",
        ));
    }
    if SHORTENERS.contains(&ascii_host.as_str()) {
        indicators.push(indicator(
            "url.host.shortener",
            "Использован сокращатель ссылок",
            "Короткий адрес скрывает итоговый домен до сетевого обращения.",
            "redirect",
            IndicatorSeverity::Medium,
            20,
            vec![ascii_host.clone()],
            "Запустите ручную активную проверку или запросите прямую ссылку.",
        ));
    }
    if let Some(tld) = labels.last() {
        if SUSPICIOUS_TLDS.contains(tld) {
            indicators.push(indicator(
                "url.host.unusual-tld",
                "Домен использует зону повышенного внимания",
                "Доменная зона является только слабым контекстным сигналом и не означает вредоносность сайта.",
                "hostname",
                IndicatorSeverity::Low,
                6,
                vec![format!("TLD: .{tld}")],
                "Оцените происхождение ссылки вместе с другими независимыми признаками.",
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

    let mut normalized = parsed.clone();
    normalized.set_fragment(None);
    let _ = normalized.set_username("");
    let _ = normalized.set_password(None);
    UrlAnalysis {
        normalized_url: normalized.to_string(),
        scheme: parsed.scheme().to_string(),
        host: ascii_host.clone(),
        ascii_host,
        unicode_host,
        registrable_domain,
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

fn registrable_domain(host: &str, host_is_ip: bool) -> Option<String> {
    if host_is_ip {
        return None;
    }
    let labels = host
        .trim_end_matches('.')
        .split('.')
        .filter(|label| !label.is_empty())
        .collect::<Vec<_>>();
    if labels.len() < 2 {
        return None;
    }
    let last_two = labels[labels.len() - 2..].join(".");
    let take = if MULTI_LABEL_PUBLIC_SUFFIXES.contains(&last_two.as_str()) {
        3
    } else {
        2
    };
    if labels.len() < take {
        return None;
    }
    Some(labels[labels.len() - take..].join("."))
}

fn redacted_url(parsed: &Url) -> String {
    let mut value = parsed.clone();
    value.set_fragment(None);
    if !value.username().is_empty() || value.password().is_some() {
        let _ = value.set_username("redacted");
        let _ = value.set_password(None);
    }
    value.to_string()
}

fn redact_nested_url(value: &str) -> String {
    Url::parse(value)
        .map(|url| redacted_url(&url))
        .unwrap_or_else(|_| value.chars().take(512).collect())
}

fn is_sensitive_hostname(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    host == "localhost"
        || host.ends_with(".localhost")
        || host == "metadata.google.internal"
        || host.ends_with(".internal")
        || host.ends_with(".local")
}

fn is_forbidden_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_forbidden_ipv4(address),
        IpAddr::V6(address) => is_forbidden_ipv6(address),
    }
}

fn is_forbidden_ipv4(address: Ipv4Addr) -> bool {
    let [a, b, c, d] = address.octets();
    a == 0
        || a == 10
        || a == 127
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 0 && c == 2)
        || (a == 192 && b == 168)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || a >= 224
        || (a == 255 && b == 255 && c == 255 && d == 255)
}

fn is_forbidden_ipv6(address: Ipv6Addr) -> bool {
    if let Some(mapped) = address.to_ipv4_mapped() {
        return is_forbidden_ipv4(mapped);
    }
    let segments = address.segments();
    address.is_unspecified()
        || address.is_loopback()
        || address.is_multicast()
        || (segments[0] & 0xfe00) == 0xfc00
        || (segments[0] & 0xffc0) == 0xfe80
        || (segments[0] & 0xffc0) == 0xfec0
        || (segments[0] == 0x2001 && segments[1] == 0x0db8)
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
    use crate::analysis::jobs::JobRegistry;

    fn token() -> std::sync::Arc<JobToken> {
        JobRegistry::default().start("url-test", 30_000).unwrap()
    }

    #[test]
    fn passive_analysis_is_canonical_and_offline() {
        let report = analyze_url_passive("https://example.com/path".to_string(), &token()).unwrap();
        assert_eq!(report.metadata["networkAccess"], false);
        assert_eq!(report.metadata["canonicalRuntime"], "rust");
        assert!(!report.url.unwrap().active_check_performed);
    }

    #[test]
    fn credentials_are_detected_but_password_is_redacted() {
        let report = analyze_url_passive(
            "https://login:secret@example.com/open?redirect=https%3A%2F%2Fevil.test".to_string(),
            &token(),
        )
        .unwrap();
        let serialized = serde_json::to_string(&report).unwrap();
        assert!(!serialized.contains("secret"));
        assert!(report
            .indicators
            .iter()
            .any(|item| item.id == "url.credentials.embedded"));
    }

    #[test]
    fn registrable_domain_handles_multi_label_suffix() {
        assert_eq!(
            registrable_domain("deep.login.example.co.uk", false).as_deref(),
            Some("example.co.uk")
        );
    }

    #[test]
    fn blocks_private_and_metadata_ranges() {
        for address in [
            "127.0.0.1",
            "10.1.2.3",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "::1",
            "fc00::1",
            "fe80::1",
            "::ffff:127.0.0.1",
        ] {
            assert!(is_forbidden_ip(address.parse().unwrap()), "{address}");
        }
        assert!(!is_forbidden_ip("93.184.216.34".parse().unwrap()));
    }

    #[test]
    fn active_mode_rejects_credentials_and_non_standard_ports() {
        let credentials = parse_http_url("https://user:secret@example.com").unwrap();
        assert!(validate_active_target(&credentials, None).is_err());
        let port = parse_http_url("https://example.com:8443").unwrap();
        assert!(validate_active_target(&port, None).is_err());
    }

    #[test]
    fn rejects_non_http_and_bidi_urls() {
        assert!(parse_http_url("file:///etc/passwd").is_err());
        assert!(parse_http_url("https://example.com/\u{202e}exe").is_err());
    }
}
