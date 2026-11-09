//! The Sidebar plugin: the slide-out xite-info panel.
//!
//! Client side, its `all.js`/`all.css` are appended to `/uimedia/all.js|css`
//! (self-contained: morphdom, the drag handle, the WebGL globe loader) and its
//! globe assets are served under `/uimedia/globe/`. Server side, it answers
//! `sidebarGetHtmlTag` by rendering the panel HTML from the **real** xite
//! runtime - peer counts, transfer totals, file/size stats, size limit, and the
//! derived identity - plus the action commands the panel's buttons call.

use async_trait::async_trait;
use epix_peer::PeerCounts;
use epix_plugin::Plugin;
use epix_ui::{WsCommand, WsSession};
use serde_json::{json, Value};
use std::sync::Arc;

static ALL_JS: &[u8] = include_bytes!("../media/sidebar/all.js");
static ALL_CSS: &[u8] = include_bytes!("../media/sidebar/all.css");

/// The Sidebar plugin.
pub struct SidebarPlugin;

impl Plugin for SidebarPlugin {
    fn name(&self) -> &str {
        "Sidebar"
    }

    fn ws_commands(&self) -> Vec<Arc<dyn WsCommand>> {
        vec![Arc::new(SidebarGetHtmlTag), Arc::new(SidebarGetPeers), Arc::new(XiteSetSizeLimit)]
    }

    fn append_js(&self) -> Option<&'static [u8]> {
        Some(ALL_JS)
    }

    fn append_css(&self) -> Option<&'static [u8]> {
        Some(ALL_CSS)
    }

    fn media_files(&self) -> Vec<(&'static str, &'static [u8])> {
        vec![
            ("globe/all.js", include_bytes!("../media/sidebar/globe/all.js")),
            ("globe/three.min.js", include_bytes!("../media/sidebar/globe/three.min.js")),
            ("globe/globe.js", include_bytes!("../media/sidebar/globe/globe.js")),
            ("globe/Detector.js", include_bytes!("../media/sidebar/globe/Detector.js")),
            ("globe/Tween.js", include_bytes!("../media/sidebar/globe/Tween.js")),
            ("globe/world.jpg", include_bytes!("../media/sidebar/globe/world.jpg")),
        ]
    }
}

/// `sidebarGetHtmlTag` - render the panel for the current xite.
struct SidebarGetHtmlTag;

#[async_trait]
impl WsCommand for SidebarGetHtmlTag {
    fn name(&self) -> &'static str {
        "sidebarGetHtmlTag"
    }

    async fn handle(&self, s: &WsSession, _p: &Value) -> Result<Value, String> {
        let address = s.address()?.to_string();
        let info = s.state.xite_info(&address).await;
        let counts = s.state.peer_counts(&address).await;
        let (recv, sent) = s.state.transfer(&address).await;
        let map_open = s.state.global_settings().await["sidebar_peer_map_open"].as_bool().unwrap_or(true);
        // The signable content.json list: the root plus its includes
        // (data/users/content.json and friends). siteInfo trims `includes` to
        // a count, so read the names from the raw file.
        let includes = s
            .state
            .read_file(&address, "content.json")
            .await
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
            .and_then(|c| {
                c.get("includes")
                    .and_then(|v| v.as_object())
                    .map(|m| m.keys().cloned().collect::<Vec<_>>())
            })
            .unwrap_or_default();
        Ok(Value::String(render_sidebar(&address, &info, counts, recv, sent, &includes, map_open)))
    }
}

/// `sidebarGetPeers` - peer positions for the WebGL globe, as the flat
/// `[lat, lon, height, …]` array the globe's `magnitude` format expects.
struct SidebarGetPeers;

#[async_trait]
impl WsCommand for SidebarGetPeers {
    fn name(&self) -> &'static str {
        "sidebarGetPeers"
    }

    async fn handle(&self, s: &WsSession, _p: &Value) -> Result<Value, String> {
        let address = s.address()?; // globe is per-xite; require a bound xite
        let globe_data = s.state.peer_globe_data(address).await;
        Ok(Value::Array(globe_data.into_iter().map(|f| json!(f)).collect()))
    }
}

/// `siteSetLimit` - set the per-xite size limit (MB). The sidebar's "Set" button
/// sends the input value positionally, as a string.
struct XiteSetSizeLimit;

#[async_trait]
impl WsCommand for XiteSetSizeLimit {
    fn name(&self) -> &'static str {
        "siteSetLimit"
    }

    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let address = s.address()?.to_string();
        let raw = p
            .get("size_limit")
            .or_else(|| p.as_array().and_then(|a| a.first()))
            .or(Some(p))
            .ok_or("size_limit required")?;
        // Accept a number or a numeric string (the button posts a string).
        let limit = raw
            .as_i64()
            .or_else(|| raw.as_str().and_then(|s| s.trim().parse::<i64>().ok()))
            .ok_or("size_limit must be a number")?;
        s.state.set_size_limit(&address, limit).await;
        Ok(Value::String("ok".into()))
    }
}

// --- rendering ---------------------------------------------------------------

fn esc(s: &str) -> String {
    // The sidebar templates use single-quoted attributes throughout, so `'`
    // MUST be escaped too: a content.json-controlled path like
    // `x' onmouseover='...` would otherwise break out of `title='{path}'`
    // and run script in the privileged wrapper frame.
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Content choices fill the editable signing path. Their pressed state follows
/// that input in the sidebar JS, including a path entered without a shortcut.
fn signable_contents(includes: &[String]) -> String {
    let mut links = vec![
        "<button type='button' class='contents-content selected' data-content-path='content.json' aria-pressed='true'>content.json</button>".to_string(),
    ];
    for inc in includes {
        let e = esc(inc);
        links.push(format!(
            "<button type='button' class='contents-content' data-content-path='{e}' aria-pressed='false'>{e}</button>",
        ));
    }
    format!("<div class='contents' role='group' aria-label='Content file choices'>{}</div>", links.join(" "))
}

fn pct(part: f64, total: f64) -> String {
    let p = if total > 0.0 { part / total * 100.0 } else { 0.0 };
    format!("{p:.0}%")
}

/// Live progress panel for a running bulk optional-file download, from the
/// `optional_progress` snapshot in xite_info (absent/`null` when idle → ""). A
/// spinner + status line + overall bar, and a collapsible per-file list where
/// each file shows a state icon (spinner/check/dot/x). The list defaults
/// collapsed; `all.js` toggles the `.expanded` class on `#optional-file-list`
/// and re-applies it across the morphdom refresh so it survives live updates.
fn render_optional_progress(progress: &Value) -> String {
    let obj = match progress.as_object() {
        Some(o) => o,
        None => return String::new(),
    };
    let total = obj.get("total_files").and_then(|v| v.as_u64()).unwrap_or(0);
    let done = obj.get("done_files").and_then(|v| v.as_u64()).unwrap_or(0);
    let failed = obj.get("failed_files").and_then(|v| v.as_u64()).unwrap_or(0);
    let percent = obj.get("percent").and_then(|v| v.as_f64()).unwrap_or(0.0);
    let current = obj.get("current").and_then(|v| v.as_str()).unwrap_or("");
    // Just the file name for the status line - full inner paths are long.
    let current_name = current.rsplit('/').next().unwrap_or(current);
    // The sampled phase ("Waiting for peers…", "Downloading… 42%"); falls back
    // to the raw overall % if the sampler hasn't written one yet.
    let phase = obj.get("status").and_then(|v| v.as_str()).unwrap_or("");
    let phase = if phase.is_empty() { format!("{percent:.0}%") } else { esc(phase) };

    let status = if !current_name.is_empty() {
        format!("{phase} · {}", esc(current_name))
    } else {
        phase
    };
    let failed_note = if failed > 0 {
        format!(" · <span class='opt-failed'>{failed} failed</span>")
    } else {
        String::new()
    };

    let mut items = String::new();
    if let Some(files) = obj.get("files").and_then(|v| v.as_array()) {
        for f in files {
            let path = f.get("path").and_then(|v| v.as_str()).unwrap_or("");
            let name = path.rsplit('/').next().unwrap_or(path);
            let size = f.get("size").and_then(|v| v.as_u64()).unwrap_or(0);
            let state = f.get("state").and_then(|v| v.as_str()).unwrap_or("pending");
            let size_mb = size as f64 / 1024.0 / 1024.0;
            items.push_str(&format!(
                "<li class='opt-file state-{state}'>\
                  <span class='opt-file-icon'></span>\
                  <span class='opt-file-name' title='{full}'>{name}</span>\
                  <b>{size_mb:.2}MB</b></li>",
                full = esc(path),
                name = esc(name),
            ));
        }
    }

    // A <div>, not an <li>: nesting an <li> inside the section's <li> makes the
    // HTML parser auto-close the parent, so the panel would break out into its
    // own card (and shove the toggles out of theirs). A div keeps the legend,
    // this panel, and the toggles together in one block.
    format!(
        "<div class='optional-progress'>\
          <label><span class='opt-spinner'></span> Downloading optional files… {done} / {total}{failed_note}</label>\
          <ul class='graph graph-stacked'>\
           <li style='width: {bar_w}' class='downloaded back-green'></li>\
          </ul>\
          <div class='opt-status'>{status}</div>\
          <a href='#OptionalFiles' class='opt-toggle-files' id='optional-files-toggle'>Show files ({total})</a>\
          <ul class='opt-file-list' id='optional-file-list'>{items}</ul></div>",
        bar_w = format!("{:.0}%", percent.clamp(0.0, 100.0)),
    )
}

/// Build focused properties tabs from the current xite runtime. Existing
/// action IDs remain stable for the sidebar's command handlers.
fn render_sidebar(
    address: &str,
    info: &Value,
    counts: PeerCounts,
    recv: u64,
    sent: u64,
    includes: &[String],
    map_open: bool,
) -> String {
    let content = &info["content"];
    let title = content.get("title").and_then(|v| v.as_str())
        .filter(|title| !title.trim().is_empty()).unwrap_or(address);
    let files = content.get("files").and_then(|v| v.as_i64()).unwrap_or(0);
    let size_bytes = info["settings"]["size"].as_i64().unwrap_or(0);
    let size_mb = size_bytes as f64 / 1024.0 / 1024.0;
    let size_limit = info["size_limit"].as_i64().unwrap_or(epix_ui::DEFAULT_SIZE_LIMIT_MB);
    let auth_address = info["auth_address"].as_str().unwrap_or("");
    let cert_user_id = info["cert_user_id"].as_str();
    let serving = info["settings"]["serving"].as_bool().unwrap_or(true);
    let favorite = info["settings"]["favorite"].as_bool().unwrap_or(false);
    let autodownload = info["settings"]["autodownloadoptional"].as_bool().unwrap_or(false);
    // Help-distribute implies on-demand downloads, so its checkbox shows on.
    let download_optional =
        info["settings"]["download_optional"].as_bool().unwrap_or(false) || autodownload;
    let size_optional = info["settings"]["size_optional"].as_i64().unwrap_or(0);
    let optional_downloaded = info["settings"]["optional_downloaded"].as_i64().unwrap_or(0);
    let bad_files = info["settings"]["cache"]["bad_files"].as_object().map(|m| m.len()).unwrap_or(0);
    let hidden = |cond: bool| if cond { "hidden" } else { "" };

    let recv_mb = recv as f64 / 1024.0 / 1024.0;
    let sent_mb = sent as f64 / 1024.0 / 1024.0;

    let mut b = String::new();
    b.push_str("<div class='sidebar-properties'>");
    b.push_str(&format!(
        "<header class='sidebar-header'>\
          <div class='sidebar-heading'><div><p class='sidebar-kicker'>Xite properties</p><h1>{title}</h1></div>\
           <button type='button' class='close' aria-label='Close properties'>&times;</button></div>\
          <p class='sidebar-address'>{address}</p>\
          <p class='sidebar-serving {serving_class}'><span class='sidebar-status-dot' aria-hidden='true'></span>{serving_label}</p>\
          <div class='sidebar-actions' role='group' aria-label='Xite controls'>\
           <a href='#Update' class='button' id='button-update'>Update</a>\
           <a href='#Pause' class='button {pause_h}' id='button-pause'>Pause</a>\
           <a href='#Resume' class='button {resume_h}' id='button-resume'>Resume</a>\
           <a href='#Favourite' class='button {fav_h}' id='button-favourite'>Favourite</a>\
           <a href='#Unfavourite' class='button {unfav_h}' id='button-unfavourite'>Unfavourite</a>\
          </div></header>",
        title = esc(title),
        address = esc(address),
        serving_class = if serving { "" } else { "is-paused" },
        serving_label = if serving { "Sharing enabled" } else { "Sharing paused" },
        pause_h = hidden(!serving),
        resume_h = hidden(serving),
        fav_h = hidden(favorite),
        unfav_h = hidden(!favorite),
    ));
    b.push_str(&format!(
        "<section class='sidebar-peer-map' data-open='{map_open}'>\
          <button type='button' id='sidebar-peer-map-toggle' aria-expanded='{map_open}' aria-controls='sidebar-peer-map-panel'>\
           <span class='sidebar-peer-map-label'>Peer map</span><span class='sidebar-peer-map-state'>{map_action}</span><span class='sidebar-peer-map-chevron' aria-hidden='true'>&#9662;</span></button>\
          <div id='sidebar-peer-map-panel'{map_hidden}>\
           <div class='globe loading'></div>\
           <div class='sidebar-globe-controls' role='group' aria-label='Peer map controls'>\
            <button type='button' class='button' id='globe-zoom-in' aria-label='Zoom in on peer map'>+</button>\
            <button type='button' class='button' id='globe-zoom-out' aria-label='Zoom out of peer map'>&minus;</button>\
            <button type='button' class='button' id='globe-reset'>Reset view</button>\
           </div><p class='sidebar-help'>Drag to rotate. Pinch or use the controls to zoom.</p></div></section>",
        map_hidden = if map_open { "" } else { " hidden" },
        map_action = if map_open { "Hide" } else { "Show" },
    ));
    b.push_str(
        "<div class='sidebar-tabs' role='tablist' aria-label='Properties sections'>\
          <button type='button' class='sidebar-tab' id='sidebar-tab-overview' data-tab='overview' role='tab' aria-selected='true' aria-controls='sidebar-panel-overview' tabindex='0'>Overview</button>\
          <button type='button' class='sidebar-tab' id='sidebar-tab-files' data-tab='files' role='tab' aria-selected='false' aria-controls='sidebar-panel-files' tabindex='-1'>Files</button>\
          <button type='button' class='sidebar-tab' id='sidebar-tab-manage' data-tab='manage' role='tab' aria-selected='false' aria-controls='sidebar-panel-manage' tabindex='-1'>Manage</button>\
         </div>\
         <section class='sidebar-panel' id='sidebar-panel-overview' data-panel='overview' role='tabpanel' aria-labelledby='sidebar-tab-overview'><ul class='fields'>",
    );

    // Peer categories overlap, so show independent counts instead of a stack.
    b.push_str(&format!(
        "<li class='sidebar-section'><div class='sidebar-section-heading'><h2>Peers</h2>\
          <a href='#Copy' id='link-copypeers' class='link-right'>Copy to clipboard</a></div>\
         <div class='sidebar-peer-total'><b>{connected}</b><span>connected peers</span></div>\
         <ul class='graph-legend sidebar-peer-counts'>\
          <li><span>Connectable</span><b>{connectable}</b></li>\
          <li><span>Total peers</span><b>{total_n}</b></li>\
          <li><span>Onion</span><b>{onion}</b></li>\
          <li><span>Local</span><b>{local}</b></li>\
         </ul>\
         <form id='form-addpeer'>\
          <label for='peer-endpoint'>Peer address</label>\
          <div class='sidebar-form-row'><input id='peer-endpoint' class='text' type='text' maxlength='128' autocomplete='off' autocapitalize='none' spellcheck='false' \
            placeholder='IP:port or rns:destination' aria-describedby='peer-address-formats peer-add-status'>\
           <button type='submit' class='button'>Add peer</button></div>\
          <details class='sidebar-peer-formats'><summary>Accepted address formats</summary>\
           <p class='sidebar-help' id='peer-address-formats'>IPv4:port, [IPv6]:port, host.onion:port, an I2P host with optional port, or rns:destination.</p></details>\
          <p id='peer-add-status' class='sidebar-help' role='status' aria-live='polite'></p>\
         </form></li>",
        connected = counts.connected,
        connectable = counts.connectable,
        onion = counts.onion,
        local = counts.local,
        total_n = counts.total,
    ));

    // Data transfer
    b.push_str(&format!(
        "<li class='sidebar-section'><h2>Data transfer</h2>\
         <ul class='graph-legend sidebar-transfer'>\
          <li><span>Received</span><b>{recv_mb:.2}MB</b></li>\
          <li><span>Sent</span><b>{sent_mb:.2}MB</b></li>\
         </ul></li>",
    ));

    // Identity remains available to readers, independent of owner settings.
    let (identity, action) = match cert_user_id {
        Some(id) => (esc(id), "Change"),
        None if !auth_address.is_empty() => (esc(auth_address), "Change"),
        None => ("No identity selected".to_string(), "Select"),
    };
    b.push_str(&format!(
        "<li class='sidebar-section'><div class='sidebar-section-heading'><h2>Identity</h2>\
          <a href='#Change' id='button-identity' class='link-right'>{action}</a></div>\
         <span class='console-address'>{identity}</span>\
         <p class='sidebar-help'>Used when you interact with this xite.</p></li>\
         </ul></section>\
         <section class='sidebar-panel' id='sidebar-panel-files' data-panel='files' role='tabpanel' aria-labelledby='sidebar-tab-files' hidden><ul class='fields'>",
    ));

    // Files
    b.push_str(&format!(
        "<li class='sidebar-section'><h2>Files &amp; storage</h2>\
         <ul class='graph-legend'>\
          <li><span>Files</span><b>{files}</b></li>\
          <li><span>Stored</span><b>{size_mb:.2}MB</b></li>\
         </ul><div class='sidebar-file-actions'>\
          <a href='/list/{addr}' class='button' id='browse-files'>Browse files</a>\
          <a href='/EpixNet-Internal/Zip?address={addr}' id='link-zip' class='button' download='xite.zip'>Save as .zip</a>\
         </div></li>",
        addr = esc(address),
    ));

    // Size limit
    let percent_used = pct(size_mb, size_limit as f64);
    b.push_str(&format!(
        "<li class='sidebar-section'><label for='input-xitelimit'>Storage limit <small>({percent_used} used)</small></label>\
         <div class='sidebar-form-row'><div class='sidebar-limit-field'>\
          <input type='text' inputmode='numeric' class='text text-num' value='{size_limit}' id='input-xitelimit' aria-describedby='xitelimit-unit'/><span class='text-post' id='xitelimit-unit'>MB</span></div>\
          <a href='#Set' class='button' id='button-xitelimit'>Save limit</a></div></li>",
    ));

    // Optional files (only when the xite declares any).
    if size_optional > 0 {
        let opt_mb = size_optional as f64 / 1024.0 / 1024.0;
        let opt_dl_mb = optional_downloaded as f64 / 1024.0 / 1024.0;
        b.push_str(&format!(
            "<li class='sidebar-section'><h2>Optional files</h2>\
             <ul class='graph graph-stacked'>\
              <li style='width: {dl_w}' class='downloaded back-green' title='Downloaded'></li>\
             </ul>\
             <ul class='graph-legend'>\
              <li class='color-green'><span>Downloaded:</span><b>{opt_dl_mb:.2}MB</b></li>\
              <li class='color-black'><span>Total optional:</span><b>{opt_mb:.2}MB</b></li>\
             </ul>\
             {progress}\
             <label class='checkbox'><input type='checkbox' class='checkbox' id='checkbox-downloadoptional' {dl_checked}/>\
              <span class='checkbox-skin'></span><span class='sidebar-toggle-copy'><strong>Download files I open</strong><small>Fetch optional files when you view them.</small></span></label>\
             <label class='checkbox'><input type='checkbox' class='checkbox' id='checkbox-autodownloadoptional' {opt_checked}/>\
              <span class='checkbox-skin'></span><span class='sidebar-toggle-copy'><strong>Pre-download everything</strong><small>Also fetch files you have not opened.</small></span></label>\
             <p class='sidebar-help'>You already share the files you have downloaded.</p></li>",
            dl_w = pct(opt_dl_mb, opt_mb),
            progress = render_optional_progress(&info["optional_progress"]),
            dl_checked = if download_optional { "checked='checked'" } else { "" },
            opt_checked = if autodownload { "checked='checked'" } else { "" },
        ));
    }

    // Not-synced files (bad files awaiting retry).
    if bad_files > 0 {
        b.push_str(&format!(
            "<li class='sidebar-section'><h2>Needs to be updated</h2>\
             <span class='console-address'>{bad_files} file(s)</span></li>",
        ));
    }

    b.push_str(
        "</ul></section>\
         <section class='sidebar-panel' id='sidebar-panel-manage' data-panel='manage' role='tabpanel' aria-labelledby='sidebar-tab-manage' hidden><ul class='fields'>",
    );

    // "This is my xite" - claim ownership. The owner panel below is always in
    // the DOM; the checkbox reveals it via CSS (#checkbox-owned:checked ~
    // .settings-owned), matching EpixNet, so it shows the moment you check it.
    let owned = info["settings"]["own"].as_bool().unwrap_or(false);
    let checked = if owned { "checked='checked'" } else { "" };
    let description = content.get("description").and_then(|v| v.as_str()).unwrap_or("");
    let xid_name = content.get("domain").and_then(|v| v.as_str()).unwrap_or("");
    b.push_str(&format!(
        "<li class='sidebar-section sidebar-ownership'><label class='owned-title' for='checkbox-owned'>This is my xite</label>\
         <input type='checkbox' class='checkbox' id='checkbox-owned' {checked}/>\
         <div class='checkbox-skin'></div>\
         <p class='sidebar-help'>Show editing and publishing controls.</p>\
         <div class='settings-owned'><ul class='fields'>\
          <li><label for='settings-title'>Xite title</label>\
           <input type='text' class='text' value=\"{title}\" id='settings-title'/></li>\
          <li><label for='settings-description'>Xite description</label>\
           <input type='text' class='text' value=\"{desc}\" id='settings-description'/></li>\
          <li><label for='settings-xid-name'>xID name <small class='label-right'>e.g. mysite.epix</small></label>\
           <input type='text' class='text' value=\"{xid}\" id='settings-xid-name' placeholder='name.epix'/></li>\
          <li><a href='#Save' class='button' id='button-settings'>Save xite settings</a></li>\
          <li><h2>Content publishing</h2>\
           <label for='input-contents'>Content file</label>\
            <input type='text' class='text' value='content.json' id='input-contents'/>\
           {contents_list}\
           <div class='flex sidebar-publish-actions'>\
            <a href='#Sign-and-Publish' id='button-sign-publish' class='button'>Sign and publish</a>\
            <a href='#Sign-or-Publish' id='menu-sign-publish' role='button' aria-label='More publishing actions' aria-haspopup='menu'>\u{22EE}</a>\
           </div></li>\
         </ul></div></li>",
        title = esc(title),
        desc = esc(description),
        xid = esc(xid_name),
        contents_list = signable_contents(includes),
    ));

    b.push_str(
        "<li class='sidebar-section'><h2>Database</h2>\
         <p class='sidebar-help'>Reload the schema or rebuild the database from xite files.</p>\
         <div class='sidebar-file-actions'>\
          <a href='#DB-Reload' class='button' id='button-dbreload'>Reload schema</a>\
          <a href='#DB-Rebuild' class='button' id='button-dbrebuild'>Rebuild database</a></div></li>\
         <li class='sidebar-section'><h2>Xite files</h2>\
          <a href='#Directory' id='link-directory' class='button'>Show directory</a></li>\
         <li class='sidebar-section sidebar-danger'><h2>Remove xite</h2>\
          <p class='sidebar-help'>Remove this xite from your node.</p>\
          <a href='#Delete' class='button' id='button-delete'>Delete xite</a></li>\
         </ul></section></div>",
    );
    b.push_str(
        "<div class='menu template'>\
           <a href='#' class='menu-item template'>Template</a>\
         </div>",
    );
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn focused_tabs_keep_actions_in_their_sections_and_map_outside_tabs() {
        let info = json!({
            "settings": { "size_optional": 1024, "cache": { "bad_files": { "a.txt": 1 } } },
            "content": { "title": "Example" },
        });
        let html = render_sidebar("example.epix", &info, PeerCounts::default(), 0, 0, &[], true);
        let overview_start = html.find("<section class='sidebar-panel' id='sidebar-panel-overview'").unwrap();
        let files_start = html.find("<section class='sidebar-panel' id='sidebar-panel-files'").unwrap();
        let manage_start = html.find("<section class='sidebar-panel' id='sidebar-panel-manage'").unwrap();
        let header = &html[..overview_start];
        let overview = &html[overview_start..files_start];
        let files = &html[files_start..manage_start];
        let manage = &html[manage_start..];
        for id in ["button-update", "button-pause", "button-resume", "button-favourite", "button-unfavourite", "sidebar-peer-map-panel", "globe-zoom-in", "globe-zoom-out", "globe-reset"] {
            assert!(header.contains(&format!("id='{id}'")), "shared control {id}");
        }
        for id in ["link-copypeers", "form-addpeer", "peer-endpoint", "button-identity"] {
            assert!(overview.contains(&format!("id='{id}'")), "overview control {id}");
        }
        assert!(overview.contains("Data transfer"));
        for id in ["browse-files", "link-zip", "input-xitelimit", "button-xitelimit", "checkbox-downloadoptional", "checkbox-autodownloadoptional"] {
            assert!(files.contains(&format!("id='{id}'")), "files control {id}");
        }
        assert!(files.contains("1 file(s)"), "unsynced files stay with storage");
        for id in ["checkbox-owned", "settings-title", "settings-description", "settings-xid-name", "button-settings", "input-contents", "button-sign-publish", "menu-sign-publish", "button-dbreload", "button-dbrebuild", "link-directory", "button-delete"] {
            assert!(manage.contains(&format!("id='{id}'")), "manage control {id}");
            assert_eq!(html.matches(&format!("id='{id}'")).count(), 1, "unique action {id}");
        }
        for tab in ["overview", "files", "manage"] {
            assert!(header.contains(&format!("aria-controls='sidebar-panel-{tab}'")));
            assert!(html.contains(&format!("role='tabpanel' aria-labelledby='sidebar-tab-{tab}'")));
        }
        assert!(files.contains("aria-labelledby='sidebar-tab-files' hidden>"));
        assert!(manage.contains("aria-labelledby='sidebar-tab-manage' hidden>"));
        assert!(html.contains("id='peer-endpoint' class='text'"), "peer input uses the shared input treatment");
    }

    #[test]
    fn peer_map_initial_visibility_matches_saved_preference() {
        for map_open in [false, true] {
            let html = render_sidebar("example.epix", &json!({}), PeerCounts::default(), 0, 0, &[], map_open);
            assert!(html.contains(&format!("class='sidebar-peer-map' data-open='{map_open}'")));
            assert!(html.contains(&format!("id='sidebar-peer-map-toggle' aria-expanded='{map_open}'")));
            assert_eq!(html.contains("id='sidebar-peer-map-panel' hidden>"), !map_open);
            assert!(html.contains("class='globe loading'"), "collapsed map remains available to reopen");
        }
    }

    #[test]
    fn content_choices_have_one_initial_selection_and_escape_untrusted_paths() {
        let includes = vec!["data/users/content.json".into(), "a'\"<>&/content.json".into()];
        let html = signable_contents(&includes);
        assert_eq!(html.matches("aria-pressed='true'").count(), 1);
        assert_eq!(html.matches("aria-pressed='false'").count(), 2);
        assert!(html.contains("data-content-path='content.json' aria-pressed='true'"));
        assert!(html.contains("data-content-path='data/users/content.json' aria-pressed='false'"));
        assert!(html.contains("data-content-path='a&#39;&quot;&lt;&gt;&amp;/content.json'"));
        assert!(!html.contains("a'\"<>&/content.json"));
        assert_eq!(html.matches("type='button'").count(), 3, "choices never submit a form");
    }

    #[test]
    fn renders_real_values_into_the_panel() {
        let info = json!({
            "auth_address": "epix1abcauthaddress",
            "cert_user_id": Value::Null,
            "size_limit": 10,
            "settings": {
                "size": 2_097_152, "own": true, // 2 MB, owned
                "serving": true, "favorite": false, "autodownloadoptional": true,
                "size_optional": 4_194_304, "optional_downloaded": 1_048_576,
                "cache": { "bad_files": { "a.txt": 1, "b.txt": 2 } },
            },
            "content": { "title": "My Xite", "description": "desc", "files": 7 },
        });
        let counts = PeerCounts { total: 5, connected: 2, connectable: 4, onion: 1, local: 1 };
        let includes = vec!["data/users/content.json".to_string()];
        let html = render_sidebar("1abc.epix", &info, counts, 1_048_576, 524_288, &includes, true);

        assert!(html.contains("<h1>My Xite</h1>"));
        // A selected identity shows its address and a Change link.
        assert!(html.contains("epix1abcauthaddress"));
        assert!(html.contains("id='button-identity' class='link-right'>Change</a>"));
        // New sections/controls.
        assert!(html.contains("id='link-copypeers'"), "copy peers link");
        assert!(html.contains("id='checkbox-autodownloadoptional' checked"), "autodownload on");
        assert!(html.contains("id='button-dbreload'") && html.contains("id='button-dbrebuild'"), "db controls");
        assert!(html.contains("id='button-resume'") && html.contains("id='button-favourite'"), "resume + favourite");
        assert!(html.contains("id='link-directory'"), "show directory");
        assert!(html.contains("2 file(s)"), "bad-files count");
        // Serving + not-favourited -> resume/unfavourite start hidden.
        assert!(html.contains("class='button hidden' id='button-resume'"));
        assert!(html.contains("class='button hidden' id='button-unfavourite'"));
        assert!(html.contains("class='button ' id='button-favourite'"));
        assert!(html.contains("<b>2</b>"), "connected count"); // connected=2
        assert!(html.contains("<b>7</b>"), "files count");
        assert!(html.contains("2.00MB"), "total size in MB");
        assert!(html.contains("1.00MB"), "received MB");
        assert!(html.contains("value='10'"), "size limit");
        assert!(html.contains("epix1abcauthaddress"), "identity");
        assert!(html.contains("button-update"));
        // Owner sections (owned xite).
        assert!(html.contains("This is my xite"));
        assert!(html.contains("checkbox-owned"));
        assert!(html.contains("checked='checked'"));
        assert!(html.contains("id='settings-title'"));
        assert!(html.contains("button-sign-publish"), "sign + publish button");
        // The signable-contents list: root plus every include, clickable.
        assert!(html.contains("<button type='button' class='contents-content selected' data-content-path='content.json' aria-pressed='true'>content.json</button>"));
        assert!(html.contains(
            "<button type='button' class='contents-content' data-content-path='data/users/content.json' aria-pressed='false'>data/users/content.json</button>"
        ));
        assert!(html.contains("id='menu-sign-publish'"), "sign-or-publish menu");
        assert!(html.contains("class='menu template'"), "menu popup template");
        assert!(html.contains("class='menu-item template'"), "menu item template");

        // Not owned: the owner panel is still in the DOM (CSS hides it), but the
        // checkbox is unchecked.
        let mut info2 = info.clone();
        info2["settings"]["own"] = json!(false);
        let html2 = render_sidebar("1abc.epix", &info2, counts, 0, 0, &[], true);
        assert!(html2.contains("id='checkbox-owned' />"), "owned checkbox unchecked when not owned");
        assert!(html2.contains("button-sign-publish"), "owner panel always present; CSS toggles it");
        assert!(html2.contains("class='settings-owned'"));

        for title in ["", "  "] {
            info2["content"]["title"] = json!(title);
            let html = render_sidebar("1abc.epix", &info2, counts, 0, 0, &[], true);
            assert!(html.contains("<h1>1abc.epix</h1>"), "blank title keeps the address fallback");
        }
    }

    #[test]
    fn optional_progress_panel_renders_only_while_downloading() {
        // Idle (optional_progress null): no live panel, no spinner.
        let idle = json!({
            "auth_address": "", "cert_user_id": Value::Null, "size_limit": 10,
            "optional_progress": Value::Null,
            "settings": { "size": 0, "own": false, "serving": true,
                "size_optional": 4_194_304, "optional_downloaded": 0,
                "cache": { "bad_files": {} } },
            "content": { "title": "X", "files": 0 },
        });
        let counts = PeerCounts { total: 1, connected: 1, connectable: 1, onion: 0, local: 0 };
        let html = render_sidebar("1abc", &idle, counts, 0, 0, &[], true);
        // No identity on this xite: the panel says so and offers to select one.
        assert!(html.contains("No identity selected"), "{html}");
        assert!(html.contains("id='button-identity' class='link-right'>Select</a>"));
        assert!(!html.contains("optional-progress"), "no live panel when idle");
        assert!(!html.contains("opt-spinner"), "no spinner when idle");

        // Downloading: spinner, counts, overall %, and a per-file list with the
        // active file spinning and a finished file checked.
        let mut active = idle.clone();
        active["optional_progress"] = json!({
            "total_files": 2, "done_files": 1, "failed_files": 0,
            "bytes_total": 3_000_000, "bytes_done": 1_000_000, "percent": 33.0,
            "current": "data/users/alice/video.mp4",
            "status": "Waiting for peers…",
            "files": [
                { "path": "a.bin", "size": 1_000_000, "state": "done" },
                { "path": "data/users/alice/video.mp4", "size": 2_000_000, "state": "active" },
            ],
        });
        let html = render_sidebar("1abc", &active, counts, 0, 0, &[], true);
        assert!(html.contains("class='optional-progress'"), "live panel present");
        // Must be a <div>, not an <li>: an <li> would break out of the card.
        assert!(html.contains("<div class='optional-progress'>"), "panel is a div (one block)");
        assert!(!html.contains("<li class='optional-progress'>"), "panel is not an li");
        assert!(html.contains("opt-spinner"), "spinner present");
        assert!(html.contains("1 / 2"), "completed/total count");
        // The sampled phase drives the status line (not the raw %).
        assert!(html.contains("Waiting for peers… · video.mp4"), "phase + current file name");
        assert!(html.contains("width: 33%"), "overall bar sized by bytes");
        assert!(html.contains("id='optional-files-toggle'"), "collapsible toggle");
        assert!(html.contains("Show files (2)"), "toggle counts files");
        assert!(html.contains("opt-file state-done"), "finished file marked done");
        assert!(html.contains("opt-file state-active"), "current file marked active");
        assert!(html.contains(">video.mp4<"), "file list shows base names");

        // No sampled status yet -> falls back to the overall %.
        active["optional_progress"]["status"] = json!("");
        let html = render_sidebar("1abc", &active, counts, 0, 0, &[], true);
        assert!(html.contains("33% · video.mp4"), "falls back to % when no phase");
    }
}
