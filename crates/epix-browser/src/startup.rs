//! Main-thread startup presentation; node and profile work stays on Tokio.

use std::future::Future;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use tao::event::{ElementState, Event, WindowEvent};
use tao::event_loop::{ControlFlow, EventLoop};
use tao::keyboard::Key;
use tao::platform::run_return::EventLoopExtRunReturn;

use crate::splash_view::SplashView;

/// Progress counts completed startup stages, not an estimate of elapsed time.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Stage {
    Preparing,
    Sandbox,
    Settings,
    Xites,
    Databases,
    Services,
    Connecting,
    Profile,
    Wallet,
    Browser,
    Ready,
}

impl Stage {
    fn label(self) -> &'static str {
        match self {
            Self::Preparing => "Starting EpixNet",
            Self::Sandbox => "Approve browser setup",
            Self::Settings => "Loading your settings",
            Self::Xites => "Restoring your xites",
            Self::Databases => "Preparing local databases",
            Self::Services => "Starting network services",
            Self::Connecting => "Connecting your browser",
            Self::Profile => "Preparing secure browsing",
            Self::Wallet => "Preparing your wallet",
            Self::Browser => "Opening Epix Browser",
            Self::Ready => "Epix Browser is ready",
        }
    }

    fn detail(self) -> &'static str {
        match self {
            Self::Preparing => "Getting your local workspace ready.",
            Self::Sandbox => "Approve the system password prompt to enable the browser sandbox. This is only needed once.",
            Self::Settings => "Loading your saved preferences and identities.",
            Self::Xites => "Checking the xites saved on this device.",
            Self::Databases => "Preparing your saved content for browsing.",
            Self::Services => "Starting local services. Peers connect in the background.",
            Self::Connecting => "Checking that the local browser connection is ready.",
            Self::Profile => {
                "Setting up your browser profile. First launch can take a little longer."
            }
            Self::Wallet => "Installing your wallet and browser theme.",
            Self::Browser => "Waiting for the browser window to appear.",
            Self::Ready => "Enjoy browsing EpixNet.",
        }
    }
}

impl From<epix_node::BootStage> for Stage {
    fn from(stage: epix_node::BootStage) -> Self {
        match stage {
            epix_node::BootStage::PreparingData => Self::Preparing,
            epix_node::BootStage::LoadingSettings => Self::Settings,
            epix_node::BootStage::RestoringXites => Self::Xites,
            epix_node::BootStage::RebuildingDatabases => Self::Databases,
            epix_node::BootStage::StartingServices => Self::Services,
            epix_node::BootStage::Prepared => Self::Connecting,
        }
    }
}

#[derive(Clone, Default)]
pub struct Progress {
    sender: Option<mpsc::Sender<Stage>>,
}

impl Progress {
    pub fn visible(&self) -> bool {
        self.sender.is_some()
    }

    pub fn report(&self, stage: Stage) {
        if let Some(sender) = &self.sender {
            let _ = sender.send(stage);
        }
        println!("· startup: {}", stage.label());
    }
}

struct Presentation {
    stage: Stage,
    changed: Instant,
    error: Option<String>,
}

impl Presentation {
    fn new() -> Self {
        Self {
            stage: Stage::Preparing,
            changed: Instant::now(),
            error: None,
        }
    }

    fn advance(&mut self, stage: Stage) {
        if self.error.is_none() && stage > self.stage {
            self.stage = stage;
            self.changed = Instant::now();
        }
    }

    fn text(&self) -> (String, String, u32) {
        if let Some(error) = &self.error {
            return (
                "EpixNet couldn’t start".into(),
                format!("{error}\nPress Esc to exit."),
                self.stage as u32,
            );
        }
        let seconds = self.changed.elapsed().as_secs();
        let detail = if seconds >= 5 {
            format!("{}\nStill working · {seconds}s", self.stage.detail())
        } else {
            self.stage.detail().to_string()
        };
        (self.stage.label().to_string(), detail, self.stage as u32)
    }
}

fn enabled(foreground: bool, disabled: bool, display_available: bool) -> bool {
    foreground && !disabled && display_available
}

struct StartupState<T> {
    presentation: Presentation,
    progress: mpsc::Receiver<Stage>,
    result: mpsc::Receiver<Result<T, String>>,
    outcome: Option<Result<T, String>>,
}

impl<T> StartupState<T> {
    /// Returns true only when a new error should restore a minimized splash.
    fn poll(&mut self) -> bool {
        while let Ok(stage) = self.progress.try_recv() {
            self.presentation.advance(stage);
        }
        if self.outcome.is_some() {
            return false;
        }
        self.outcome = match self.result.try_recv() {
            Ok(result) => Some(result),
            Err(mpsc::TryRecvError::Disconnected) => Some(Err(
                "Startup stopped unexpectedly. Check the application log.".into(),
            )),
            Err(mpsc::TryRecvError::Empty) => None,
        };
        if let Some(Err(error)) = &self.outcome {
            eprintln!("· startup failed: {error}");
            self.presentation.error = Some(error.clone());
            return true;
        }
        false
    }

    fn finish(self) -> Result<T, String> {
        // A disconnected display can end run_return before boot completes.
        self.outcome.unwrap_or_else(|| {
            self.result
                .recv()
                .unwrap_or_else(|_| Err("Startup stopped unexpectedly.".into()))
        })
    }
}

pub enum Outcome {
    Finished,
    WithoutTray {
        child: Option<std::process::Child>,
        firefox: std::path::PathBuf,
    },
}

impl Outcome {
    fn without_tray(ctx: crate::tray::TrayContext) -> Self {
        Self::WithoutTray {
            child: ctx.child,
            firefox: ctx.ready.firefox,
        }
    }
}

fn boot_without_progress<T, F, B>(runtime: &tokio::runtime::Runtime, boot: F) -> Result<T, String>
where
    F: FnOnce(Progress) -> B,
    B: Future<Output = Result<T, String>>,
{
    runtime.block_on(boot(Progress::default()))
}

fn run_without_splash(ctx: crate::tray::TrayContext, event_loop: Option<EventLoop<()>>) -> Outcome {
    let firefox = ctx.ready.firefox.clone();
    match crate::tray::run(ctx, event_loop) {
        Ok(()) => Outcome::Finished,
        Err(child) => Outcome::WithoutTray { child, firefox },
    }
}

/// Startup and tray share one continuous native loop. Exiting run_return and
/// entering it again is not supported by Tao's macOS event-loop state.
pub fn run<F, B>(
    runtime: &tokio::runtime::Runtime,
    foreground: bool,
    boot: F,
) -> Result<Outcome, String>
where
    F: FnOnce(Progress) -> B,
    B: Future<Output = Result<crate::tray::TrayContext, String>> + Send + 'static,
{
    let disabled =
        std::env::var("EPIX_NO_SPLASH").is_ok_and(|value| !value.is_empty() && value != "0");
    if !enabled(foreground, disabled, crate::tray::display_available()) {
        return boot_without_progress(runtime, boot).map(|ctx| run_without_splash(ctx, None));
    }
    let Ok(mut event_loop) = std::panic::catch_unwind(crate::tray::create_event_loop) else {
        eprintln!("· startup window unavailable; continuing without it");
        return boot_without_progress(runtime, boot).map(|ctx| run_without_splash(ctx, None));
    };
    let view = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        SplashView::new(&event_loop)
    }));
    let view = match view {
        Ok(Ok(view)) => view,
        _ => {
            eprintln!("· startup window unavailable; continuing without it");
            return boot_without_progress(runtime, boot)
                .map(|ctx| run_without_splash(ctx, Some(event_loop)));
        }
    };
    let (progress_tx, progress_rx) = mpsc::channel();
    let (result_tx, result_rx) = mpsc::channel();
    let future = boot(Progress {
        sender: Some(progress_tx),
    });
    runtime.spawn(async move {
        let _ = result_tx.send(future.await);
    });
    let mut desktop = Desktop {
        startup: StartupState {
            presentation: Presentation::new(),
            progress: progress_rx,
            result: result_rx,
            outcome: None,
        },
        view: Some(view),
        tray: None,
        fallback: None,
        drawn: None,
    };
    event_loop.run_return(|event, _, flow| desktop.event(event, flow));
    desktop.finish()
}

struct Desktop {
    startup: StartupState<crate::tray::TrayContext>,
    view: Option<SplashView>,
    tray: Option<crate::tray::Session>,
    fallback: Option<Outcome>,
    drawn: Option<(String, String, u32)>,
}

impl Desktop {
    fn event(&mut self, event: Event<'_, ()>, flow: &mut ControlFlow) {
        if self.fallback.is_some() {
            *flow = ControlFlow::Exit;
            return;
        }
        if let Some(tray) = &mut self.tray {
            *flow = ControlFlow::WaitUntil(Instant::now() + Duration::from_secs(1));
            if tray.tick() {
                *flow = ControlFlow::Exit;
            }
            return;
        }
        *flow = ControlFlow::WaitUntil(Instant::now() + Duration::from_millis(16));
        let failed = self.startup.poll();
        if matches!(&self.startup.outcome, Some(Ok(_))) {
            self.activate_tray();
            if self.fallback.is_some() {
                *flow = ControlFlow::Exit;
            }
            return;
        }
        let Some(view) = &mut self.view else { return };
        view.animate();
        if failed {
            view.window().set_minimized(false);
            view.window().set_visible(true);
        }
        handle_window_event(view, event, self.startup.presentation.error.is_some(), flow);
        let next = self.startup.presentation.text();
        if self.drawn.as_ref() != Some(&next) {
            view.update(&next.0, &next.1, next.2, Stage::Ready as u32);
            self.drawn = Some(next);
        }
    }

    fn activate_tray(&mut self) {
        let Some(Ok(ctx)) = self.startup.outcome.take() else {
            return;
        };
        if let Some(view) = self.view.take() {
            view.window().set_visible(false);
        }
        // No ControlFlow::Exit here: only the presentation changes while the
        // app and node remain alive on the same native event loop.
        match crate::tray::Session::new(ctx) {
            Ok(tray) => self.tray = Some(tray),
            Err(ctx) => self.fallback = Some(Outcome::without_tray(ctx)),
        }
    }

    fn finish(self) -> Result<Outcome, String> {
        if let Some(fallback) = self.fallback {
            return Ok(fallback);
        }
        if self.tray.is_some() {
            return Ok(Outcome::Finished);
        }
        // If the display disconnected during boot, preserve the node/browser
        // and let main wait without trying to reenter the stopped event loop.
        self.startup.finish().map(Outcome::without_tray)
    }
}

fn handle_window_event(
    view: &SplashView,
    event: Event<'_, ()>,
    failed: bool,
    flow: &mut ControlFlow,
) {
    let Event::WindowEvent {
        window_id, event, ..
    } = event
    else {
        return;
    };
    if window_id != view.window().id() || !dismiss_requested(&event) {
        return;
    }
    if failed {
        *flow = ControlFlow::Exit;
    } else {
        view.window().set_minimized(true);
    }
}

fn dismiss_requested(event: &WindowEvent<'_>) -> bool {
    match event {
        WindowEvent::CloseRequested => true,
        WindowEvent::KeyboardInput { event, .. } => {
            event.state == ElementState::Pressed && event.logical_key == Key::Escape
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::{enabled, Presentation, Stage, StartupState};

    #[test]
    fn background_boot_completes_without_a_native_event_loop() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let value = super::boot_without_progress(&runtime, |progress| async move {
            assert!(!progress.visible());
            progress.report(Stage::Settings);
            Ok(42)
        })
        .unwrap();
        assert_eq!(value, 42);

        let failure = super::boot_without_progress::<(), _, _>(&runtime, |_| async {
            Err("Cannot open the data folder.".into())
        });
        assert!(matches!(failure, Err(error) if error == "Cannot open the data folder."));
    }

    #[test]
    fn worker_failure_is_presented_once_and_survives_late_progress() {
        let (progress_tx, progress) = std::sync::mpsc::channel();
        let (result_tx, result) = std::sync::mpsc::channel::<Result<(), String>>();
        let mut state = StartupState {
            presentation: Presentation::new(),
            progress,
            result,
            outcome: None,
        };
        progress_tx.send(Stage::Profile).unwrap();
        assert!(!state.poll());
        assert_eq!(state.presentation.stage, Stage::Profile);
        drop(result_tx);
        assert!(state.poll());
        progress_tx.send(Stage::Ready).unwrap();
        assert!(!state.poll());
        assert_eq!(state.presentation.stage, Stage::Profile);
        assert!(state.presentation.text().1.contains("Press Esc to exit."));
        assert!(state.finish().unwrap_err().contains("stopped unexpectedly"));
    }

    #[test]
    fn background_and_headless_launches_do_not_show_a_splash() {
        assert!(enabled(true, false, true));
        assert!(!enabled(false, false, true));
        assert!(!enabled(true, true, true));
        assert!(!enabled(true, false, false));
    }

    #[test]
    fn node_prepared_does_not_complete_browser_startup() {
        let mut state = Presentation::new();
        state.advance(epix_node::BootStage::Prepared.into());
        assert!(state.text().2 < Stage::Ready as u32);
        state.advance(Stage::Browser);
        assert!(state.text().2 < Stage::Ready as u32);
        state.advance(Stage::Ready);
        assert_eq!(state.text().2, Stage::Ready as u32);
    }

    #[test]
    fn late_progress_cannot_hide_an_error_or_move_backwards() {
        let mut state = Presentation::new();
        state.advance(Stage::Profile);
        state.advance(Stage::Xites);
        assert_eq!(state.stage, Stage::Profile);
        state.error = Some("Epix Browser could not open.".into());
        state.advance(Stage::Ready);
        let (label, detail, completed) = state.text();
        assert!(label.contains("couldn’t start"));
        assert!(detail.contains("Epix Browser could not open."));
        assert!(completed < Stage::Ready as u32);
    }
}
