//! Lets a shell hold the node's background work until its window is up.
//!
//! The desktop launcher opens a browser the moment the node is prepared. The
//! node starts Tor, I2P, the object store and every peer loop at that same
//! moment, and on a typical machine that burst doubled the time the browser
//! needed to show its window. A shell that opens a window calls [`hold_for`]
//! before boot and [`release`] once the window is up; the gated tasks wait in
//! [`released`]. Nothing is held unless a shell asks: servers, mobile shells
//! and background launches start their work at once, as before.
//!
//! Every hold carries a limit, so a window that never appears cannot keep the
//! node off the network.

use std::sync::OnceLock;
use std::time::Duration;

use tokio::sync::watch;
use tokio::time::Instant;

/// `Some(limit)` while held, `None` once released.
struct Hold(watch::Sender<Option<Instant>>);

impl Hold {
    fn new() -> Self {
        Self(watch::channel(None).0)
    }

    fn hold_for(&self, limit: Duration) {
        self.0.send_replace(Some(Instant::now() + limit));
    }

    fn release(&self) {
        self.0.send_replace(None);
    }

    async fn released(&self) {
        let mut state = self.0.subscribe();
        loop {
            let Some(limit) = *state.borrow_and_update() else {
                return;
            };
            tokio::select! {
                _ = tokio::time::sleep_until(limit) => return,
                changed = state.changed() => {
                    if changed.is_err() {
                        return;
                    }
                }
            }
        }
    }
}

static NODE: OnceLock<Hold> = OnceLock::new();

/// Hold background work for at most `limit` from now. A later call replaces
/// the limit, so a shell can start with a generous one and shorten it once its
/// window is visible.
pub fn hold_for(limit: Duration) {
    NODE.get_or_init(Hold::new).hold_for(limit);
}

/// Let held background work start now.
pub fn release() {
    if let Some(hold) = NODE.get() {
        hold.release();
    }
}

/// Resolves once background work may start: at once when no shell asked for
/// a hold, else on release or when the limit passes.
pub async fn released() {
    if let Some(hold) = NODE.get() {
        hold.released().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn settles(hold: &Hold, within: Duration) -> bool {
        tokio::time::timeout(within, hold.released()).await.is_ok()
    }

    #[tokio::test(start_paused = true)]
    async fn nothing_waits_unless_a_shell_asked_for_a_hold() {
        let hold = Hold::new();
        assert!(settles(&hold, Duration::ZERO).await);
    }

    #[tokio::test(start_paused = true)]
    async fn held_work_starts_on_release() {
        let hold = std::sync::Arc::new(Hold::new());
        hold.hold_for(Duration::from_secs(60));
        assert!(!settles(&hold, Duration::from_secs(5)).await);
        let waiter = tokio::spawn({
            let hold = hold.clone();
            async move { hold.released().await }
        });
        tokio::task::yield_now().await;
        hold.release();
        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("release must wake held work")
            .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn a_window_that_never_appears_cannot_hold_work_past_the_limit() {
        let hold = Hold::new();
        hold.hold_for(Duration::from_secs(10));
        assert!(!settles(&hold, Duration::from_secs(9)).await);
        assert!(settles(&hold, Duration::from_secs(2)).await);
    }

    #[tokio::test(start_paused = true)]
    async fn a_later_hold_replaces_the_limit_for_work_already_waiting() {
        let hold = std::sync::Arc::new(Hold::new());
        hold.hold_for(Duration::from_secs(60));
        let waiter = tokio::spawn({
            let hold = hold.clone();
            async move { hold.released().await }
        });
        tokio::task::yield_now().await;
        hold.hold_for(Duration::from_secs(3));
        tokio::time::timeout(Duration::from_secs(4), waiter)
            .await
            .expect("the shorter limit must apply to work already waiting")
            .unwrap();
    }
}
