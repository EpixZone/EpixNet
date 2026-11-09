//! Archived sidebar translations, selected with the node's interface language.
//! New labels deliberately fall back to English until a translation is supplied.
use serde_json::{Map, Value};
use std::{collections::HashMap, sync::OnceLock};

pub fn catalog(language: &str) -> &'static Map<String, Value> {
    static CATALOGS: OnceLock<HashMap<&'static str, Map<String, Value>>> = OnceLock::new();
    let catalogs = CATALOGS.get_or_init(|| {
        let mut catalogs = HashMap::new();
        macro_rules! add {
            ($($lang:literal),+) => { $(catalogs.insert($lang, serde_json::from_str::<Map<String, Value>>(
                include_str!(concat!("../media/sidebar/languages/", $lang, ".json"))
            ).expect("valid bundled sidebar translation"));)+ };
        }
        add!("ar", "da", "de", "es", "fa", "fr", "hu", "it", "jp", "kr", "nl", "pl", "pt", "pt-br", "ru", "sk", "sl", "tr", "uk", "zh", "zh-tw");
        let focused: HashMap<String, Map<String, Value>> = serde_json::from_str(
            include_str!("../media/sidebar/languages/focused.json")
        ).expect("valid focused sidebar translations");
        for (language, labels) in focused {
            if let Some(catalog) = catalogs.get_mut(language.as_str()) { catalog.extend(labels); }
        }
        catalogs.insert("en", Map::new());
        // Only equivalent labels reuse a legacy translation. Redesigned copy
        // with a different meaning is left in English, not mistranslated.
        for catalog in catalogs.values_mut() {
            for (new, old) in [
                ("Storage limit", "Size limit"), ("Save limit", "Set"),
                ("Images", "Image"), ("Available disk space", "free space"),
                ("Show directory", "Open site directory"),
                ("Auto-download maximum file size", "Auto download big file size limit"),
                ("Add saved private key", "add saved private key"),
                ("This is my xite", "This is my site"), ("Xite title", "Site title"),
                ("Xite description", "Site description"), ("Save xite settings", "Save site settings"),
                ("Delete xite", "Delete this site"), ("Reload schema", "Reload"),
                ("Rebuild database", "Rebuild"), ("Total optional", "Total size"),
                ("Search feeds", "search feeds"),
            ] {
                if !catalog.contains_key(new) {
                    if let Some(value) = catalog.get(old).cloned() { catalog.insert(new.into(), value); }
                }
            }
        }
        catalogs
    });
    let language = language.to_ascii_lowercase();
    let language = match language.as_str() {
        "ja" => "jp",
        "ko" => "kr",
        "zh-cn" => "zh",
        value => value,
    };
    catalogs
        .get(language)
        .or_else(|| catalogs.get(language.split('-').next().unwrap_or("en")))
        .unwrap_or(&catalogs["en"])
}

pub fn translate<'a>(language: &str, key: &'a str) -> &'a str {
    catalog(language)
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .unwrap_or(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn catalogs_follow_interface_locale_with_explicit_english_fallback() {
        assert_eq!(translate("de-DE", "Files"), "Dateien");
        assert_eq!(
            translate("de", "Storage limit"),
            translate("de", "Size limit")
        );
        assert_eq!(translate("unknown", "Files"), "Files");
        assert_eq!(translate("de", "A new label"), "A new label");
        assert!(!catalog("ja").is_empty());
        assert!(!catalog("ko").is_empty());
        assert!(!catalog("pt-BR").is_empty());
    }
}
