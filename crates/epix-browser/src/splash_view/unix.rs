use gtk::prelude::*;
use std::time::Instant;
use tao::platform::unix::WindowExtUnix;
use tao::window::Window;

pub(super) struct Controls {
    panel: gtk::Fixed,
    icon: gtk::Image,
    frames: Vec<gtk::gdk_pixbuf::Pixbuf>,
    status: gtk::Label,
    detail: gtk::Label,
    footer: gtk::Label,
    progress: gtk::ProgressBar,
    started: Instant,
    last_frame: usize,
    last_pulse: Instant,
    failed: bool,
    indeterminate: bool,
}

fn label(panel: &gtk::Fixed, y: i32, height: i32) -> gtk::Label {
    let label = gtk::Label::new(None);
    label.set_size_request(400, height);
    label.set_ellipsize(gtk::pango::EllipsizeMode::End);
    panel.put(&label, 30, y);
    label
}

impl Controls {
    pub(super) fn new(window: &Window, png: &[u8]) -> Result<Self, String> {
        let container = window
            .default_vbox()
            .ok_or("startup window has no native content box")?;
        let native_window = window.gtk_window();
        native_window.style_context().add_class("epix-startup");
        let css = gtk::CssProvider::new();
        css.load_from_data(b".epix-startup, .epix-startup headerbar { background: #0b0e14; color: white; } .epix-startup label { color: white; } .epix-startup label.detail { color: #aeb4c0; font-size: 12px; } .epix-startup label.footer { color: #aeb4c0; font-size: 11px; } .epix-startup progressbar trough { min-height: 8px; }")
            .map_err(|e| format!("style startup window: {e}"))?;
        if let Some(screen) = gtk::prelude::WidgetExt::screen(native_window) {
            gtk::StyleContext::add_provider_for_screen(
                &screen,
                &css,
                gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
            );
        }
        let panel = gtk::Fixed::new();
        panel.set_size_request(460, 320);
        let frames = super::animation_frames(png, 144)?
            .into_iter()
            .map(|pixels| {
                gtk::gdk_pixbuf::Pixbuf::from_mut_slice(
                    pixels,
                    gtk::gdk_pixbuf::Colorspace::Rgb,
                    true,
                    8,
                    144,
                    144,
                    144 * 4,
                )
            })
            .collect::<Vec<_>>();
        let icon = gtk::Image::from_pixbuf(frames.first());
        icon.set_tooltip_text(Some("EpixNet"));
        panel.put(&icon, 158, 2);
        let heading = label(&panel, 146, 34);
        heading.set_markup("<span size='26000' weight='bold'>EpixNet</span>");
        let status = label(&panel, 191, 24);
        let progress = gtk::ProgressBar::new();
        progress.set_size_request(352, 8);
        progress.set_pulse_step(0.08);
        progress.set_tooltip_text(Some("Startup progress"));
        panel.put(&progress, 54, 229);
        let detail = label(&panel, 250, 42);
        detail.set_line_wrap(true);
        detail.set_lines(3);
        detail.set_justify(gtk::Justification::Center);
        detail.set_selectable(true);
        detail.style_context().add_class("detail");
        let footer = label(&panel, 294, 18);
        footer.set_text("Press Esc to exit.");
        footer.style_context().add_class("footer");
        container.pack_start(&panel, true, true, 0);
        panel.show_all();
        footer.hide();
        Ok(Self {
            panel,
            icon,
            frames,
            status,
            detail,
            footer,
            progress,
            started: Instant::now(),
            last_frame: 0,
            last_pulse: Instant::now(),
            failed: false,
            indeterminate: true,
        })
    }

    pub(super) fn animate(&mut self, visible: bool) {
        if !visible || self.failed {
            return;
        }
        let frame = super::animation_frame(self.started.elapsed());
        if frame != self.last_frame {
            self.icon.set_from_pixbuf(Some(&self.frames[frame]));
            self.last_frame = frame;
        }
        if self.indeterminate && self.last_pulse.elapsed().as_millis() >= 100 {
            self.progress.pulse();
            self.last_pulse = Instant::now();
        }
    }

    pub(super) fn update(&mut self, status: &str, detail: &str, completed: u32, total: u32) {
        self.failed = status == super::FAILED_STATUS;
        self.status.set_text(status);
        self.status.set_tooltip_text(Some(status));
        let body = super::detail_body(detail);
        self.detail.set_text(body);
        self.detail.set_tooltip_text(Some(body));
        self.detail.set_lines(if self.failed { 4 } else { 3 });
        self.detail
            .set_size_request(400, if self.failed { 66 } else { 42 });
        self.panel
            .move_(&self.detail, 30, if self.failed { 223 } else { 250 });
        self.footer.set_visible(self.failed);
        self.progress.set_visible(!self.failed);
        self.indeterminate = total == 0;
        if total != 0 {
            self.progress
                .set_fraction(f64::from(completed.min(total)) / f64::from(total));
        }
        if self.failed {
            self.icon.set_from_pixbuf(self.frames.first());
            self.last_frame = 0;
        }
    }
}
