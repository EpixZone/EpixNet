use super::{esc, i18n};
use serde_json::Value;

fn t(language: &str, key: &str) -> String {
    esc(i18n::translate(language, key))
}

pub fn bytes(value: u64) -> String {
    if value >= 1_073_741_824 {
        format!("{:.2} GB", value as f64 / 1_073_741_824.0)
    } else if value >= 1_048_576 {
        format!("{:.2} MB", value as f64 / 1_048_576.0)
    } else if value >= 1024 {
        format!("{:.2} kB", value as f64 / 1024.0)
    } else {
        format!("{value} B")
    }
}

pub fn storage(details: &Value, language: &str) -> String {
    let Some(types) = details["storage"]["types"].as_array() else {
        return format!(
            "<p class='sidebar-help'>{}</p>",
            t(language, "Storage breakdown unavailable")
        );
    };
    let mut html = format!("<details class='sidebar-details'><summary>{}</summary><ul class='graph-legend sidebar-storage-types'>", t(language, "Storage breakdown"));
    for category in types {
        if let (Some(name), Some(size)) = (category["name"].as_str(), category["bytes"].as_u64()) {
            html.push_str(&format!(
                "<li><span>{}</span><b>{}</b></li>",
                t(language, name),
                bytes(size)
            ));
        }
    }
    html.push_str(&format!(
        "</ul><p class='sidebar-help'>{}</p></details>",
        t(
            language,
            "Required files from verified manifests. Optional files are shown separately."
        )
    ));
    html
}

pub fn free_space(details: &Value, language: &str) -> String {
    let size = details["free_bytes"]
        .as_u64()
        .map(bytes)
        .unwrap_or_else(|| t(language, "Unavailable"));
    format!(
        "<p class='sidebar-help'>{}: {size}</p>",
        t(language, "Available disk space")
    )
}

pub fn database(details: &Value, language: &str) -> String {
    let db = &details["database"];
    if !db.is_object() {
        let key = if details.is_object() {
            "No database found"
        } else {
            "Database information unavailable"
        };
        return format!("<p class='sidebar-help'>{}</p>", t(language, key));
    }
    let path = db["path"]
        .as_str()
        .map(|path| {
            if path == "In-memory database" {
                t(language, path)
            } else {
                esc(path)
            }
        })
        .unwrap_or_else(|| t(language, "Path unavailable"));
    let mut html = format!("<p class='sidebar-detail-path'>{path}</p><ul class='graph-legend'>");
    if let Some(size) = db["bytes"].as_u64() {
        html.push_str(&format!(
            "<li><span>{}</span><b>{}</b></li>",
            t(language, "Size"),
            bytes(size)
        ));
    }
    if let Some(feeds) = db["feeds"].as_u64() {
        html.push_str(&format!(
            "<li><span>{}</span><b>{feeds}</b></li>",
            t(language, "Search feeds")
        ));
    }
    html.push_str("</ul>");
    html
}

pub fn pending(files: &Value, language: &str) -> String {
    let Some(files) = files.as_object() else {
        return String::new();
    };
    let mut html = String::from("<ul class='sidebar-pending-files'>");
    for (path, retries) in files.iter().take(30) {
        let retry = retries
            .as_u64()
            .map(|count| {
                let key = if count == 1 { "{} try" } else { "{} tries" };
                esc(&i18n::translate(language, key).replace("{}", &count.to_string()))
            })
            .unwrap_or_else(|| t(language, "Retry count unavailable"));
        html.push_str(&format!(
            "<li><span class='sidebar-detail-path'>{}</span><small>{retry}</small></li>",
            esc(path)
        ));
    }
    html.push_str("</ul>");
    if files.len() > 30 {
        let more = i18n::translate(language, "+ {num_bad_files} more")
            .replace("{num_bad_files}", &(files.len() - 30).to_string());
        html.push_str(&format!("<p class='sidebar-help'>{}</p>", esc(&more)));
    }
    html
}

pub fn identity(info: &Value, language: &str) -> String {
    let mut html = String::new();
    if info["cert_user_id"].as_str().is_some() {
        if let Some(address) = info["auth_address"].as_str().filter(|s| !s.is_empty()) {
            html.push_str(&format!(
                "<p class='sidebar-help'>{}</p><p class='sidebar-detail-path'>{}</p>",
                t(language, "Identity address"),
                esc(address)
            ));
        }
        html.push_str(&format!(
            "<a href='#Disconnect' class='button' id='button-cert-disconnect'>{}</a>",
            t(language, "Disconnect")
        ));
    }
    let quota = &info["sidebar_details"]["identity_quota"];
    if let (Some(used), Some(limit)) = (quota["used"].as_u64(), quota["limit"].as_u64()) {
        html.push_str(&format!(
            "<p class='sidebar-help'>{}: {} / {}</p>",
            t(language, "Storage used"),
            bytes(used),
            bytes(limit)
        ));
    }
    html
}

pub fn saved_key(info: &Value, language: &str) -> String {
    if info["privatekey"].as_bool() == Some(true) {
        format!("<div class='sidebar-key-status'><span>{}</span><a href='#Forget' class='link-right' id='privatekey-forget'>{}</a></div>", t(language, "Private key saved."), t(language, "Forget"))
    } else {
        format!("<div class='sidebar-key-status'><span>{}</span><a href='#Add' class='link-right' id='privatekey-add'>{}</a></div>", t(language, "No saved private key"), t(language, "Add saved private key"))
    }
}
