//! The Sidebar plugin: the slide-out site-info panel.
//!
//! Client side, its `all.js`/`all.css` are appended to `/uimedia/all.js|css`
//! (self-contained: morphdom, the drag handle, the WebGL globe loader) and its
//! globe assets are served under `/uimedia/globe/`. Server side, it answers
//! `sidebarGetHtmlTag` by rendering the panel HTML from the **real** site
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
        vec![Arc::new(SidebarGetHtmlTag), Arc::new(SidebarGetPeers), Arc::new(SiteSetSizeLimit)]
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
        let info = s.state.site_info(&address).await;
        let counts = s.state.peer_counts(&address).await;
        let (recv, sent) = s.state.transfer(&address).await;
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
        Ok(Value::String(render_sidebar(&address, &info, counts, recv, sent, &includes)))
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
        let address = s.address()?; // globe is per-site; require a bound xite
        let globe_data = s.state.peer_globe_data(address).await;
        Ok(Value::Array(globe_data.into_iter().map(|f| json!(f)).collect()))
    }
}

/// `siteSetLimit` - set the per-xite size limit (MB). The sidebar's "Set" button
/// sends the input value positionally, as a string.
struct SiteSetSizeLimit;

#[async_trait]
impl WsCommand for SiteSetSizeLimit {
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
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

/// The "Choose:" list under Content publishing: the root content.json plus
/// every include it declares, each clickable to fill the signing input (the
/// bundled sidebar JS wires `.contents-content` clicks to `#input-contents`).
fn signable_contents(includes: &[String]) -> String {
    let mut links = vec!["<a href='content.json' class='contents-content'>content.json</a>".to_string()];
    for inc in includes {
        let e = esc(inc);
        links.push(format!("<a href='{e}' class='contents-content'>{e}</a>"));
    }
    format!("<div class='contents'>Choose: {}</div>", links.join(" "))
}

fn pct(part: f64, total: f64) -> String {
    let p = if total > 0.0 { part / total * 100.0 } else { 0.0 };
    format!("{p:.0}%")
}

/// Build the sidebar panel HTML from the real site runtime. Mirrors EpixNet's
/// `sidebarGetHtmlTag` structure (the classes the bundled `all.js`/`all.css`
/// expect), populated with our data.
fn render_sidebar(
    address: &str,
    info: &Value,
    counts: PeerCounts,
    recv: u64,
    sent: u64,
    includes: &[String],
) -> String {
    let content = &info["content"];
    let title = content.get("title").and_then(|v| v.as_str()).unwrap_or(address);
    let files = content.get("files").and_then(|v| v.as_i64()).unwrap_or(0);
    let size_bytes = info["settings"]["size"].as_i64().unwrap_or(0);
    let size_mb = size_bytes as f64 / 1024.0 / 1024.0;
    let size_limit = info["size_limit"].as_i64().unwrap_or(epix_ui::DEFAULT_SIZE_LIMIT_MB);
    let auth_address = info["auth_address"].as_str().unwrap_or("");
    let cert_user_id = info["cert_user_id"].as_str();
    let serving = info["settings"]["serving"].as_bool().unwrap_or(true);
    let favorite = info["settings"]["favorite"].as_bool().unwrap_or(false);
    let autodownload = info["settings"]["autodownloadoptional"].as_bool().unwrap_or(false);
    let size_optional = info["settings"]["size_optional"].as_i64().unwrap_or(0);
    let optional_downloaded = info["settings"]["optional_downloaded"].as_i64().unwrap_or(0);
    let bad_files = info["settings"]["cache"]["bad_files"].as_object().map(|m| m.len()).unwrap_or(0);
    let hidden = |cond: bool| if cond { "hidden" } else { "" };

    let total = counts.total as f64;
    let recv_mb = recv as f64 / 1024.0 / 1024.0;
    let sent_mb = sent as f64 / 1024.0 / 1024.0;
    let transfer_total = recv_mb + sent_mb;

    let mut b = String::new();
    b.push_str("<div>");
    b.push_str("<a href='#Close' class='close'>&times;</a>");
    b.push_str(&format!("<h1>{}</h1>", esc(title)));
    b.push_str("<div class='globe loading'></div>");
    b.push_str("<ul class='fields'>");

    // Peers
    b.push_str(&format!(
        "<li><label>Peers \
          <a href='#Copy' id='link-copypeers' class='link-right'>Copy to clipboard</a></label>\
         <ul class='graph'>\
          <li style='width: 100%' class='total back-black' title='Total peers'></li>\
          <li style='width: {connectable_w}' class='connectable back-blue' title='Connectable peers'></li>\
          <li style='width: {onion_w}' class='connected back-purple' title='Onion'></li>\
          <li style='width: {connected_w}' class='connected back-green' title='Connected peers'></li>\
         </ul>\
         <ul class='graph-legend'>\
          <li class='color-green'><span>Connected:</span><b>{connected}</b></li>\
          <li class='color-blue'><span>Connectable:</span><b>{connectable}</b></li>\
          <li class='color-purple'><span>Onion:</span><b>{onion}</b></li>\
          <li class='color-yellow'><span>Local:</span><b>{local}</b></li>\
          <li class='color-black'><span>Total:</span><b>{total_n}</b></li>\
         </ul></li>",
        connectable_w = pct(counts.connectable as f64, total),
        onion_w = pct(counts.onion as f64, total),
        connected_w = pct(counts.connected as f64, total),
        connected = counts.connected,
        connectable = counts.connectable,
        onion = counts.onion,
        local = counts.local,
        total_n = counts.total,
    ));

    // Data transfer
    b.push_str(&format!(
        "<li><label>Data transfer</label>\
         <ul class='graph graph-stacked'>\
          <li style='width: {recv_w}' class='received back-yellow' title='Received bytes'></li>\
          <li style='width: {sent_w}' class='sent back-green' title='Sent bytes'></li>\
         </ul>\
         <ul class='graph-legend'>\
          <li class='color-yellow'><span>Received:</span><b>{recv_mb:.2}MB</b></li>\
          <li class='color-green'><span>Sent:</span><b>{sent_mb:.2}MB</b></li>\
         </ul></li>",
        recv_w = if transfer_total > 0.0 { pct(recv_mb, transfer_total) } else { "50%".into() },
        sent_w = if transfer_total > 0.0 { pct(sent_mb, transfer_total) } else { "50%".into() },
    ));

    // Files
    b.push_str(&format!(
        "<li><label>Files \
          <a href='/list/{addr}' class='link-right link-outline' id='browse-files'>Browse files</a>\
          <small class='label-right'>\
           <a href='/EpixNet-Internal/Zip?address={addr}' id='link-zip' class='link-right' download='site.zip'>Save as .zip</a>\
          </small></label>\
         <ul class='graph graph-stacked'>\
          <li style='width: 100%' class='total back-black' title='Total size'></li>\
         </ul>\
         <ul class='graph-legend'>\
          <li class='color-black'><span>Files:</span><b>{files}</b></li>\
          <li class='color-white'><span>Total:</span><b>{size_mb:.2}MB</b></li>\
         </ul></li>",
        addr = esc(address),
    ));

    // Size limit
    let percent_used = pct(size_mb, size_limit as f64);
    b.push_str(&format!(
        "<li><label>Size limit <small>(limit used: {percent_used})</small></label>\
         <input type='text' class='text text-num' value='{size_limit}' id='input-sitelimit'/><span class='text-post'>MB</span>\
         <a href='#Set' class='button' id='button-sitelimit'>Set</a></li>",
    ));

    // Optional files (only when the site declares any).
    if size_optional > 0 {
        let opt_mb = size_optional as f64 / 1024.0 / 1024.0;
        let opt_dl_mb = optional_downloaded as f64 / 1024.0 / 1024.0;
        b.push_str(&format!(
            "<li><label>Optional files</label>\
             <ul class='graph graph-stacked'>\
              <li style='width: {dl_w}' class='downloaded back-green' title='Downloaded'></li>\
             </ul>\
             <ul class='graph-legend'>\
              <li class='color-green'><span>Downloaded:</span><b>{opt_dl_mb:.2}MB</b></li>\
              <li class='color-black'><span>Total optional:</span><b>{opt_mb:.2}MB</b></li>\
             </ul>\
             <label class='checkbox'><input type='checkbox' class='checkbox' id='checkbox-autodownloadoptional' {opt_checked}/>\
              <div class='checkbox-skin'></div> Download and help distribute all files</label></li>",
            dl_w = pct(opt_dl_mb, opt_mb),
            opt_checked = if autodownload { "checked='checked'" } else { "" },
        ));
    }

    // Not-synced files (bad files awaiting retry).
    if bad_files > 0 {
        b.push_str(&format!(
            "<li><label>Needs to be updated</label>\
             <span class='console-address'>{bad_files} file(s)</span></li>",
        ));
    }

    // Database - reload/rebuild the site's db from its files.
    b.push_str(
        "<li><label>Database</label>\
         <a href='#DB-Reload' class='button' id='button-dbreload'>Reload</a>\
         <a href='#DB-Rebuild' class='button' id='button-dbrebuild'>Rebuild</a></li>",
    );

    // Identity
    let identity = match cert_user_id {
        Some(id) => esc(id),
        None => esc(auth_address),
    };
    b.push_str(&format!(
        "<li><label>Identity address \
          <a href='#Change' id='button-identity' class='link-right'>Change</a></label>\
         <span class='console-address'>{identity}</span></li>",
    ));

    // Controls - favourite/pause-resume shown by state; the sidebar JS toggles
    // the paired button's `hidden` class on click.
    b.push_str(&format!(
        "<li><label>Site control \
          <a href='#Directory' id='link-directory' class='link-right'>Show directory</a></label>\
         <a href='#Update' class='button' id='button-update'>Update</a>\
         <a href='#Pause' class='button {pause_h}' id='button-pause'>Pause</a>\
         <a href='#Resume' class='button {resume_h}' id='button-resume'>Resume</a>\
         <a href='#Favourite' class='button {fav_h}' id='button-favourite'>Favourite</a>\
         <a href='#Unfavourite' class='button {unfav_h}' id='button-unfavourite'>Unfavourite</a>\
         <a href='#Delete' class='button' id='button-delete'>Delete</a></li>",
        pause_h = hidden(!serving),
        resume_h = hidden(serving),
        fav_h = hidden(favorite),
        unfav_h = hidden(!favorite),
    ));

    // "This is my site" - claim ownership. The owner panel below is always in
    // the DOM; the checkbox reveals it via CSS (#checkbox-owned:checked ~
    // .settings-owned), matching EpixNet, so it shows the moment you check it.
    let owned = info["settings"]["own"].as_bool().unwrap_or(false);
    let checked = if owned { "checked='checked'" } else { "" };
    let description = content.get("description").and_then(|v| v.as_str()).unwrap_or("");
    let xid_name = content.get("domain").and_then(|v| v.as_str()).unwrap_or("");
    b.push_str(&format!(
        "<h2 class='owned-title'>This is my site</h2>\
         <input type='checkbox' class='checkbox' id='checkbox-owned' {checked}/>\
         <div class='checkbox-skin'></div>\
         <div class='settings-owned'>\
          <li><label for='settings-title'>Site title</label>\
           <input type='text' class='text' value=\"{title}\" id='settings-title'/></li>\
          <li><label for='settings-description'>Site description</label>\
           <input type='text' class='text' value=\"{desc}\" id='settings-description'/></li>\
          <li><label for='settings-xid-name'>xID name <small class='label-right'>e.g. mysite.epix</small></label>\
           <input type='text' class='text' value=\"{xid}\" id='settings-xid-name' placeholder='name.epix'/></li>\
          <li><a href='#Save' class='button' id='button-settings'>Save site settings</a></li>\
          <li><label>Content publishing</label>\
           <div class='flex'>\
            <input type='text' class='text' value='content.json' id='input-contents'/>\
            <a href='#Sign-and-Publish' id='button-sign-publish' class='button'>Sign and publish</a>\
            <a href='#Sign-or-Publish' id='menu-sign-publish'>\u{22EE}</a>\
           </div>\
           {contents_list}</li>\
         </div>",
        title = esc(title),
        desc = esc(description),
        xid = esc(xid_name),
        contents_list = signable_contents(includes),
    ));

    b.push_str("</ul></div>");
    b
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let html = render_sidebar("1abc.epix", &info, counts, 1_048_576, 524_288, &includes);

        assert!(html.contains("<h1>My Xite</h1>"));
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
        // Owner sections (owned site).
        assert!(html.contains("This is my site"));
        assert!(html.contains("checkbox-owned"));
        assert!(html.contains("checked='checked'"));
        assert!(html.contains("id='settings-title'"));
        assert!(html.contains("button-sign-publish"), "sign + publish button");
        // The signable-contents list: root plus every include, clickable.
        assert!(html.contains("<a href='content.json' class='contents-content'>content.json</a>"));
        assert!(html.contains(
            "<a href='data/users/content.json' class='contents-content'>data/users/content.json</a>"
        ));
        assert!(html.contains("id='menu-sign-publish'"), "sign-or-publish menu");

        // Not owned: the owner panel is still in the DOM (CSS hides it), but the
        // checkbox is unchecked.
        let mut info2 = info.clone();
        info2["settings"]["own"] = json!(false);
        let html2 = render_sidebar("1abc.epix", &info2, counts, 0, 0, &[]);
        assert!(html2.contains("id='checkbox-owned' />"), "owned checkbox unchecked when not owned");
        assert!(html2.contains("button-sign-publish"), "owner panel always present; CSS toggles it");
        assert!(html2.contains("class='settings-owned'"));
    }
}
