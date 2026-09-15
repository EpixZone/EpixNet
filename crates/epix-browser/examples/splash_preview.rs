//! Native macOS splash regression/preview. Run with `--verify` for a bounded
//! check of real presentation-layer geometry; otherwise preview for 12 seconds.
#[cfg(target_os = "macos")]
#[path = "../src/splash_view.rs"]
mod splash_view;

#[cfg(target_os = "macos")]
mod macos {
    use super::splash_view;
    use objc2_app_kit::{NSView, NSWindow, NSWindowButton};
    use objc2_foundation::{NSPoint, NSString};
    use tao::event_loop::{ControlFlow, EventLoopBuilder};
    use tao::platform::macos::WindowExtMacOS;
    use tao::platform::run_return::EventLoopExtRunReturn;
    pub(super) fn run() {
        let mut event_loop = EventLoopBuilder::new().build();
        let mut view = splash_view::SplashView::new(&event_loop).unwrap();
        view.update(
            "Preparing secure browsing",
            "Setting up your browser profile. First launch can take a little longer.",
            6,
            9,
        );
        // SAFETY: Tao owns these native objects until `view` is dropped; all
        // inspection runs synchronously on the main thread.
        let ns = unsafe { &*(view.window().ns_window() as *const NSWindow) };
        let parent = unsafe { &*(view.window().ns_view() as *const NSView) };
        assert!(ns
            .standardWindowButton(NSWindowButton::CloseButton)
            .is_none_or(|b| b.isHidden()));
        assert!(ns
            .standardWindowButton(NSWindowButton::MiniaturizeButton)
            .is_some_and(|b| !b.isHidden() && b.isEnabled()));
        let host = parent.subviews().objectAtIndex(0);
        let host_layer = host.layer().unwrap();
        let layer = unsafe { host_layer.sublayers() }.unwrap().objectAtIndex(0);
        assert_eq!(layer.anchorPoint(), NSPoint::new(0.5, 0.5));
        let mut min_width = f64::MAX;
        let mut max_width = 0.0f64;
        let verify = std::env::args().any(|arg| arg == "--verify");
        let error = std::env::args().any(|arg| arg == "--error");
        if error {
            view.update("EpixNet couldn’t start","The configured data directory could not be opened because the device is unavailable. Long errors remain available as selectable text and in the tooltip.\nPress Esc to exit.",0,0);
        }
        let start = std::time::Instant::now();
        let mut samples = 0;
        event_loop.run_return(|_, _, flow| {
            view.animate();
            *flow = ControlFlow::WaitUntil(
                std::time::Instant::now() + std::time::Duration::from_millis(16),
            );
            if !error && samples < 18 && start.elapsed().as_millis() >= (samples + 1) * 80 {
                let shown = unsafe { layer.presentationLayer() }.unwrap();
                let rect = shown.frame();
                assert!(
                    (rect.origin.x + rect.size.width / 2.0 - 72.0).abs() < 0.01
                        && (rect.origin.y + rect.size.height / 2.0 - 72.0).abs() < 0.01,
                    "animated mark center moved: {rect:?}"
                );
                assert!(
                    rect.origin.x >= 0.0
                        && rect.origin.y >= 0.0
                        && rect.origin.x + rect.size.width <= 144.0
                        && rect.origin.y + rect.size.height <= 144.0,
                    "mark clipped: {rect:?}"
                );
                min_width = min_width.min(rect.size.width);
                max_width = max_width.max(rect.size.width);
                samples += 1;
            }
            if (verify && samples >= 18) || start.elapsed().as_secs() >= 12 {
                *flow = ControlFlow::Exit;
            }
        });
        if !error {
            assert!(max_width - min_width > 15.0, "rotation never advanced");
        }
        view.update(
            "EpixNet couldn’t start",
            "Long error details should never hide the dismissal instruction.\nPress Esc to exit.",
            0,
            0,
        );
        view.animate();
        assert!(
            unsafe { layer.animationForKey(&NSString::from_str("epix-startup-rotation")) }
                .is_none()
        );
        if error {
            println!("PASS: error preview, rotation stopped, close hidden and minimize enabled");
        } else {
            println!("PASS: 18 live animation frames kept center (72, 72), within the 144-point canvas; rotated width {min_width:.1}–{max_width:.1}; error stops rotation; close hidden and minimize enabled");
        }
    }
}
#[cfg(target_os = "macos")]
fn main() {
    macos::run();
}
#[cfg(not(target_os = "macos"))]
fn main() {
    println!("This regression inspects macOS Core Animation presentation layers.");
}
