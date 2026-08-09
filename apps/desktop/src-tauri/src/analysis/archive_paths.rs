#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchivePathAssessment {
    pub normalized_path: String,
    pub windows_comparison_key: String,
    pub suspicious: bool,
    pub has_parent_or_absolute_path: bool,
    pub has_ads: bool,
    pub has_reserved_name: bool,
    pub has_trailing_dot_or_space: bool,
    pub has_control_or_bidi: bool,
}

pub fn assess_archive_path(raw_name: &str, enclosed: bool) -> ArchivePathAssessment {
    let normalized_path = raw_name.replace('\\', "/");
    let components = normalized_path
        .split('/')
        .filter(|component| !component.is_empty())
        .collect::<Vec<_>>();

    let has_parent_component = components.iter().any(|component| *component == "..");
    let has_drive_prefix = components
        .first()
        .is_some_and(|component| is_windows_drive_component(component));
    let has_parent_or_absolute_path = !enclosed
        || normalized_path.starts_with('/')
        || normalized_path.starts_with("//")
        || has_parent_component
        || has_drive_prefix;

    let has_ads = components.iter().enumerate().any(|(index, component)| {
        component.char_indices().any(|(offset, ch)| {
            ch == ':' && !(index == 0 && offset == 1 && is_windows_drive_component(component))
        })
    });
    let has_reserved_name = components
        .iter()
        .any(|component| is_windows_reserved_component(component));
    let has_trailing_dot_or_space = components
        .iter()
        .any(|component| component.ends_with('.') || component.ends_with(' '));
    let has_control_or_bidi = normalized_path.chars().any(is_control_or_bidi);
    let windows_comparison_key = windows_comparison_key(&normalized_path);
    let suspicious = has_parent_or_absolute_path
        || has_ads
        || has_reserved_name
        || has_trailing_dot_or_space
        || has_control_or_bidi;

    ArchivePathAssessment {
        normalized_path,
        windows_comparison_key,
        suspicious,
        has_parent_or_absolute_path,
        has_ads,
        has_reserved_name,
        has_trailing_dot_or_space,
        has_control_or_bidi,
    }
}

pub fn windows_comparison_key(path: &str) -> String {
    path.replace('\\', "/")
        .split('/')
        .filter(|component| !component.is_empty() && *component != ".")
        .map(|component| {
            component
                .trim_end_matches(|ch| ch == ' ' || ch == '.')
                .to_lowercase()
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn is_windows_drive_component(component: &str) -> bool {
    let bytes = component.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

fn is_windows_reserved_component(component: &str) -> bool {
    let trimmed = component.trim_end_matches(|ch| ch == ' ' || ch == '.');
    let stem = trimmed
        .split('.')
        .next()
        .unwrap_or(trimmed)
        .to_ascii_uppercase();

    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || reserved_numbered_name(&stem, "COM")
        || reserved_numbered_name(&stem, "LPT")
}

fn reserved_numbered_name(value: &str, prefix: &str) -> bool {
    value
        .strip_prefix(prefix)
        .is_some_and(|suffix| suffix.len() == 1 && matches!(suffix.as_bytes()[0], b'1'..=b'9'))
}

fn is_control_or_bidi(ch: char) -> bool {
    ch.is_control()
        || matches!(
            ch,
            '\u{061c}'
                | '\u{200e}'
                | '\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_path_gets_stable_windows_key() {
        let value = assess_archive_path("Docs/Readme.TXT", true);
        assert!(!value.suspicious);
        assert_eq!(value.normalized_path, "Docs/Readme.TXT");
        assert_eq!(value.windows_comparison_key, "docs/readme.txt");
    }

    #[test]
    fn ads_reserved_and_trailing_names_are_detected() {
        let ads = assess_archive_path("docs/readme.txt:payload.exe", true);
        assert!(ads.has_ads);
        assert!(ads.suspicious);

        let reserved = assess_archive_path("payload/CON.txt", true);
        assert!(reserved.has_reserved_name);
        assert!(reserved.suspicious);

        let trailing = assess_archive_path("payload/name. ", true);
        assert!(trailing.has_trailing_dot_or_space);
        assert!(trailing.suspicious);
    }

    #[test]
    fn absolute_parent_and_drive_paths_are_detected() {
        assert!(assess_archive_path("../escape.exe", false).has_parent_or_absolute_path);
        assert!(assess_archive_path("/absolute.exe", false).has_parent_or_absolute_path);
        assert!(
            assess_archive_path("C:/Windows/System32/a.dll", false).has_parent_or_absolute_path
        );
    }

    #[test]
    fn bidi_and_control_characters_are_detected() {
        assert!(assess_archive_path("invoice\u{202e}exe.txt", true).has_control_or_bidi);
        assert!(assess_archive_path("folder/control\u{0007}.txt", true).has_control_or_bidi);
    }

    #[test]
    fn windows_key_collapses_case_and_trailing_dot_space() {
        assert_eq!(windows_comparison_key("Docs/Readme.txt"), "docs/readme.txt");
        assert_eq!(
            windows_comparison_key("docs/readme.TXT. "),
            "docs/readme.txt"
        );
    }
}
