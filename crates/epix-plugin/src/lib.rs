//! `epix-plugin` — the extension system.
//!
//! EpixNet extends the engine by monkeypatching Python classes at runtime. Here
//! that becomes an explicit, compile-time-checked hook system: a [`Plugin`]
//! contributes behavior at named seams, and a [`PluginRegistry`] collects
//! plugins and assembles their contributions.
//!
//! The first seam is the EpixFrame WebSocket API: a plugin can add commands that
//! xites call. Further seams (site lifecycle, content verification, peer
//! discovery, worker priority, new FileRequest commands) hang off the same
//! [`Plugin`] trait as additional methods.

use epix_ui::{CommandRegistry, WsCommand};
use std::sync::Arc;

/// A unit of extension. Every hook method defaults to a no-op; a plugin
/// overrides only the seams it uses.
pub trait Plugin: Send + Sync {
    /// A stable identifier, e.g. `"Sidebar"`.
    fn name(&self) -> &str;

    /// WebSocket commands this plugin adds to the EpixFrame API.
    fn ws_commands(&self) -> Vec<Arc<dyn WsCommand>> {
        Vec::new()
    }

    // Future seams (added as the subsystems grow):
    //   fn on_site_loaded(&self, ...) {}
    //   fn verify_content(&self, ...) -> HookOutcome { HookOutcome::Continue }
    //   fn priority_boost(&self, ...) -> i32 { 0 }
    //   fn file_request_handler(&self, cmd: &str, ...) -> Option<...> { None }
}

/// Collects the enabled plugins and assembles their contributions.
#[derive(Default)]
pub struct PluginRegistry {
    plugins: Vec<Arc<dyn Plugin>>,
}

impl PluginRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, plugin: Arc<dyn Plugin>) {
        self.plugins.push(plugin);
    }

    pub fn plugins(&self) -> &[Arc<dyn Plugin>] {
        &self.plugins
    }

    pub fn names(&self) -> Vec<&str> {
        self.plugins.iter().map(|p| p.name()).collect()
    }

    /// Build the UI command registry: built-in commands plus every plugin's
    /// commands. Later plugins override earlier ones on a name clash.
    pub fn command_registry(&self) -> CommandRegistry {
        let mut registry = CommandRegistry::with_defaults();
        for plugin in &self.plugins {
            for command in plugin.ws_commands() {
                registry.register(command);
            }
        }
        registry
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use epix_ui::{AppState, WsSession};
    use serde_json::{json, Value};

    /// An example plugin adding a `pluginList`-style command.
    struct HelloPlugin;

    struct HelloCommand;
    #[async_trait]
    impl WsCommand for HelloCommand {
        fn name(&self) -> &'static str {
            "helloPlugin"
        }
        async fn handle(&self, _s: &WsSession, params: &Value) -> Result<Value, String> {
            let who = params.get("name").and_then(|v| v.as_str()).unwrap_or("world");
            Ok(json!({ "greeting": format!("hello, {who}"), "from": "HelloPlugin" }))
        }
    }

    impl Plugin for HelloPlugin {
        fn name(&self) -> &str {
            "Hello"
        }
        fn ws_commands(&self) -> Vec<Arc<dyn WsCommand>> {
            vec![Arc::new(HelloCommand)]
        }
    }

    #[tokio::test]
    async fn plugin_command_is_registered_and_dispatched() {
        let mut registry = PluginRegistry::new();
        registry.register(Arc::new(HelloPlugin));
        assert_eq!(registry.names(), vec!["Hello"]);

        let commands = registry.command_registry();
        // Built-in commands are still present…
        assert!(commands.has("siteInfo"));
        // …and the plugin's command was added.
        assert!(commands.has("helloPlugin"));

        let session = WsSession {
            state: AppState::new("test"),
            xite: None,
        };
        let out = commands
            .dispatch(&session, "helloPlugin", &json!({ "name": "epix" }))
            .await
            .unwrap();
        assert_eq!(out["greeting"], "hello, epix");
        assert_eq!(out["from"], "HelloPlugin");
    }
}
