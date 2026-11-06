//! Choose the standalone server's desktop launch before it owns node data.
//!
//! The managed browser owns its own node. Starting it after acquiring the
//! server's data lease would start two nodes against the same profile.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Map, Value};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Browser {
    Epix,
    System,
}

impl Browser {
    fn parse(value: &str, source: &str) -> Result<Self, String> {
        match value.trim() {
            "epix" => Ok(Self::Epix),
            "system" => Ok(Self::System),
            _ => Err(format!("{source} must be epix or system")),
        }
    }
}

#[derive(Debug)]
pub struct Arguments {
    pub target: String,
    pub browser: Option<Browser>,
}

impl Arguments {
    /// Actions have already been dispatched by main. Only node-launch options
    /// are parsed here, so authoring action arguments keep their old meaning.
    pub fn parse(args: &[String], default_target: &str) -> Result<Self, String> {
        let mut target = None;
        let mut browser = None;
        let mut args = args.iter();
        while let Some(arg) = args.next() {
            let selected = if arg == "--browser" {
                Some(
                    args.next()
                        .ok_or("--browser requires epix or system")?
                        .as_str(),
                )
            } else {
                arg.strip_prefix("--browser=")
            };
            if let Some(value) = selected {
                if browser.is_some() {
                    return Err("Specify --browser only once".into());
                }
                browser = Some(Browser::parse(value, "--browser")?);
            } else if arg.starts_with('-') {
                return Err(format!("Unknown launch option: {arg}"));
            } else if target.replace(arg.clone()).is_some() {
                return Err("Specify only one xite target".into());
            }
        }
        Ok(Self {
            target: target.unwrap_or_else(|| default_target.into()),
            browser,
        })
    }
}

fn read_config(root: &Path) -> Result<Map<String, Value>, String> {
    let path = root.join("private/config.json");
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Map::new()),
        Err(error) => {
            return Err(format!(
                "Cannot read node config {}: {error}",
                path.display()
            ))
        }
    };
    let value: Value = serde_json::from_slice(&bytes)
        .map_err(|error| format!("Invalid node config {}: {error}", path.display()))?;
    match value {
        Value::Object(config) => Ok(config),
        _ => Err(format!(
            "Invalid node config {}: expected a JSON object",
            path.display()
        )),
    }
}

fn opens_browser(config: &Map<String, Value>) -> Result<bool, String> {
    match config.get("open_browser") {
        None => Ok(true),
        Some(Value::Bool(value)) => Ok(*value),
        Some(Value::String(value)) => match value.trim().to_ascii_lowercase().as_str() {
            "true" | "on" => Ok(true),
            "false" | "off" => Ok(false),
            _ => Err("Node config open_browser must be true or false".into()),
        },
        Some(_) => Err("Node config open_browser must be true or false".into()),
    }
}

/// Read current settings without acquiring a lease, applying a queued move,
/// restoring data, or starting the node. The selected process performs those
/// operations. Settings introduced by a restore/profile switch therefore apply
/// to browser selection on the following launch.
pub fn select(
    root: &Path,
    argument: Option<Browser>,
    environment: Option<&str>,
    headless: bool,
) -> Result<Option<Browser>, String> {
    let config = read_config(root)?;
    if headless || !opens_browser(&config)? {
        return Ok(None);
    }
    if let Some(browser) = argument {
        return Ok(Some(browser));
    }
    if let Some(value) = environment.filter(|value| !value.trim().is_empty()) {
        return Browser::parse(value, "EPIX_BROWSER").map(Some);
    }
    match config.get("browser") {
        None => Ok(Some(Browser::Epix)),
        Some(Value::String(value)) => Browser::parse(value, "Node config browser").map(Some),
        Some(_) => Err("Node config browser must be epix or system".into()),
    }
}

fn sibling_browser(server_exe: &Path) -> Result<PathBuf, String> {
    let directory = server_exe
        .parent()
        .ok_or("Cannot locate the EpixNet executable directory")?;
    Ok(directory.join(if cfg!(windows) {
        "epix-browser.exe"
    } else {
        "epix-browser"
    }))
}

/// Use only the executable installed beside this server. Never search the
/// working directory or PATH for a browser, and never silently change the
/// user's selected mode if the desktop installation is incomplete.
pub fn handoff(target: &str) -> Result<i32, String> {
    let executable = std::env::current_exe()
        .map_err(|error| format!("Cannot locate the EpixNet executable: {error}"))?;
    let browser = sibling_browser(&executable)?;
    let mut command = Command::new(&browser);
    command.arg(target);
    run_browser(&mut command).map_err(|error| {
        format!(
            "Cannot launch EpixNet Browser at {}: {error}. Install the full desktop bundle \
             or build it with scripts/run-browser.sh. Use --browser system for your system \
             browser, or EPIX_HEADLESS=1 to run without opening a browser.",
            browser.display()
        )
    })
}

#[cfg(unix)]
fn run_browser(command: &mut Command) -> std::io::Result<i32> {
    use std::os::unix::process::CommandExt;
    // Replace this process before it acquires node data. This preserves its PID,
    // terminal signals and the managed browser's exit status without a wrapper.
    Err(command.exec())
}

#[cfg(not(unix))]
fn run_browser(command: &mut Command) -> std::io::Result<i32> {
    command.status().map(|status| status.code().unwrap_or(1))
}

#[cfg(test)]
#[path = "../tests/launch/policy.rs"]
mod tests;
