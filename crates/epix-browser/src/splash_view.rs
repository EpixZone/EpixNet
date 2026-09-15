//! Native startup panel. The launcher owns the event loop and decides when
//! the panel closes; this module only presents the latest startup snapshot.

use tao::dpi::{LogicalSize, PhysicalPosition};
use tao::event_loop::EventLoopWindowTarget;
use tao::window::{Theme, Window, WindowBuilder};

#[cfg(target_os = "macos")]
#[path = "splash_view/macos.rs"]
mod native;
#[cfg(windows)]
#[path = "splash_view/windows.rs"]
mod native;
#[cfg(all(unix, not(target_os = "macos")))]
#[path = "splash_view/unix.rs"]
mod native;

const BRAND_PNG: &[u8] = include_bytes!("../../../shells/ios/EpixBrowser/epix-mark-white.png");

pub struct SplashView {
    // Native controls must be released while their Tao parent still exists.
    controls: native::Controls,
    window: Window,
}

impl SplashView {
    pub fn new(target: &EventLoopWindowTarget<()>) -> Result<Self, String> {
        let window = WindowBuilder::new()
            .with_title("Starting EpixNet")
            .with_inner_size(LogicalSize::new(460.0, 320.0))
            .with_resizable(false)
            // Windows cannot hide only Close in a standard caption. The native
            // renderer supplies a draggable strip and an accessible minimize button.
            .with_decorations(!cfg!(windows))
            .with_maximizable(false)
            .with_minimizable(true)
            .with_closable(false)
            .with_theme(Some(Theme::Dark))
            .with_background_color((11, 14, 20, 255))
            .with_visible(false)
            .build(target)
            .map_err(|e| format!("create startup window: {e}"))?;
        if let Some(monitor) = window
            .current_monitor()
            .or_else(|| target.primary_monitor())
        {
            let origin = monitor.position();
            let screen = monitor.size();
            let panel = window.outer_size();
            window.set_outer_position(PhysicalPosition::new(
                origin.x + (screen.width.saturating_sub(panel.width) / 2) as i32,
                origin.y + (screen.height.saturating_sub(panel.height) / 2) as i32,
            ));
        }
        let controls = native::Controls::new(&window, BRAND_PNG)?;
        let mut view = Self { controls, window };
        view.update("Starting EpixNet", "Preparing your browser…", 0, 0);
        view.window.set_visible(true);
        Ok(view)
    }

    pub fn window(&self) -> &Window {
        &self.window
    }

    pub fn animate(&mut self) {
        self.controls.animate(!self.window.is_minimized());
    }

    pub fn update(&mut self, status: &str, detail: &str, completed_steps: u32, total_steps: u32) {
        self.window.set_title(&format!("EpixNet — {status}"));
        self.controls
            .update(status, detail, completed_steps, total_steps);
    }
}

/// Keep the dismissal instruction independent of error length and wrapping.
fn detail_body(detail: &str) -> &str {
    detail
        .trim_end()
        .strip_suffix("\nPress Esc to exit.")
        .unwrap_or(detail)
}

const FAILED_STATUS: &str = "EpixNet couldn’t start";

#[cfg(any(not(target_os = "macos"), test))]
const ANIMATION_FRAMES: usize = 36;

#[cfg(any(not(target_os = "macos"), test))]
fn animation_frame(elapsed: std::time::Duration) -> usize {
    ((elapsed.as_millis() % 1200) * ANIMATION_FRAMES as u128 / 1200) as usize
}

/// Cache small native-image frames once; no PNG decoding or allocation per tick.
/// The 96-point mark has a 144-point canvas so its corners never clip as it turns.
#[cfg(any(not(target_os = "macos"), test))]
fn animation_frames(png: &[u8], size: u32) -> Result<Vec<Vec<u8>>, String> {
    let mark_size = size * 2 / 3;
    let mark = image::load_from_memory(png)
        .map_err(|e| format!("decode startup brand image: {e}"))?
        .resize_exact(mark_size, mark_size, image::imageops::FilterType::Lanczos3)
        .into_rgba8();
    let center = (f64::from(size) - 1.0) / 2.0;
    let mark_center = (f64::from(mark_size) - 1.0) / 2.0;
    let mut frames = Vec::with_capacity(ANIMATION_FRAMES);
    for frame in 0..ANIMATION_FRAMES {
        let angle = std::f64::consts::TAU * frame as f64 / ANIMATION_FRAMES as f64;
        let (sin, cos) = angle.sin_cos();
        let mut pixels = vec![0; (size * size * 4) as usize];
        for y in 0..size {
            for x in 0..size {
                let dx = f64::from(x) - center;
                let dy = f64::from(y) - center;
                let sx = cos * dx + sin * dy + mark_center;
                let sy = -sin * dx + cos * dy + mark_center;
                let alpha = sample_alpha(&mark, sx, sy);
                let offset = ((y * size + x) * 4) as usize;
                pixels[offset..offset + 4].copy_from_slice(&[255, 255, 255, alpha]);
            }
        }
        frames.push(pixels);
    }
    Ok(frames)
}

#[cfg(any(not(target_os = "macos"), test))]
fn sample_alpha(mark: &image::RgbaImage, x: f64, y: f64) -> u8 {
    let x0 = x.floor() as i32;
    let y0 = y.floor() as i32;
    let mut alpha = 0.0;
    // Bilinear sampling keeps diagonal edges smooth at native DPI.
    for (ox, wx) in [(0, 1.0 - (x - x.floor())), (1, x - x.floor())] {
        for (oy, wy) in [(0, 1.0 - (y - y.floor())), (1, y - y.floor())] {
            let px = x0 + ox;
            let py = y0 + oy;
            if px >= 0 && py >= 0 && px < mark.width() as i32 && py < mark.height() as i32 {
                alpha += f64::from(mark.get_pixel(px as u32, py as u32)[3]) * wx * wy;
            }
        }
    }
    alpha.round() as u8
}

#[cfg(test)]
mod tests {
    use super::{animation_frame, animation_frames, detail_body, ANIMATION_FRAMES, BRAND_PNG};

    #[test]
    fn mobile_animation_keeps_mark_centered_and_clear_of_canvas_edges() {
        let frames = animation_frames(BRAND_PNG, 144).unwrap();
        assert_eq!(frames.len(), ANIMATION_FRAMES);
        assert_ne!(frames[0], frames[3], "mark must visibly rotate");
        for frame in frames {
            let mut weight = 0.0;
            let mut center = (0.0, 0.0);
            for (index, pixel) in frame.chunks_exact(4).enumerate() {
                let (x, y) = (index % 144, index / 144);
                let alpha = f64::from(pixel[3]);
                weight += alpha;
                center.0 += x as f64 * alpha;
                center.1 += y as f64 * alpha;
                if x == 0 || y == 0 || x == 143 || y == 143 {
                    assert_eq!(pixel[3], 0, "rotating mark must not clip");
                }
            }
            assert!((center.0 / weight - 71.5).abs() < 0.5);
            assert!((center.1 / weight - 71.5).abs() < 0.5);
        }
        assert_eq!(animation_frame(std::time::Duration::from_millis(600)), 18);
        assert_eq!(animation_frame(std::time::Duration::from_millis(1200)), 0);
    }

    #[test]
    fn failure_instruction_has_a_separate_layout_slot() {
        assert_eq!(
            detail_body("Could not open data.\nPress Esc to exit."),
            "Could not open data."
        );
        assert_eq!(detail_body("Still preparing…"), "Still preparing…");
    }
}
