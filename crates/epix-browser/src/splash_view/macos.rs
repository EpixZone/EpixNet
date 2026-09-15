use objc2::rc::Retained;
use objc2::{AnyThread, MainThreadMarker, MainThreadOnly};
use objc2_app_kit::{
    NSAccessibility, NSAppearance, NSAppearanceCustomization, NSAppearanceNameDarkAqua, NSColor,
    NSFont, NSImage, NSImageView, NSLineBreakMode, NSProgressIndicator, NSProgressIndicatorStyle,
    NSTextAlignment, NSTextField, NSView, NSWindow, NSWindowButton,
};
use objc2_foundation::{NSData, NSNumber, NSPoint, NSRect, NSSize, NSString};
use objc2_quartz_core::{
    kCAMediaTimingFunctionLinear, CABasicAnimation, CALayer, CAMediaTiming, CAMediaTimingFunction,
};
use tao::platform::macos::WindowExtMacOS;
use tao::window::Window;

pub(super) struct Controls {
    icon: Retained<CALayer>,
    status: Retained<NSTextField>,
    detail: Retained<NSTextField>,
    footer: Retained<NSTextField>,
    progress: Retained<NSProgressIndicator>,
    failed: bool,
    spinning: bool,
}

fn frame(x: f64, y: f64, width: f64, height: f64) -> NSRect {
    NSRect::new(NSPoint::new(x, y), NSSize::new(width, height))
}

fn label(
    parent: &NSView,
    mtm: MainThreadMarker,
    value: &str,
    rect: NSRect,
    size: f64,
) -> Retained<NSTextField> {
    let label = NSTextField::labelWithString(&NSString::from_str(value), mtm);
    label.setFrame(rect);
    label.setAlignment(NSTextAlignment::Center);
    label.setFont(Some(&NSFont::systemFontOfSize(size)));
    label.setTextColor(Some(&NSColor::whiteColor()));
    label.setLineBreakMode(NSLineBreakMode::ByTruncatingTail);
    parent.addSubview(&label);
    label
}

impl Controls {
    pub(super) fn new(window: &Window, png: &[u8]) -> Result<Self, String> {
        let mtm = MainThreadMarker::new().ok_or("startup window must run on the main thread")?;
        // SAFETY: Tao owns these objects for the lifetime of `window`. All
        // access remains on the main thread, and controls are dropped first.
        let parent = unsafe { (window.ns_view() as *const NSView).as_ref() }
            .ok_or("startup window has no native content view")?;
        let native_window = unsafe { (window.ns_window() as *const NSWindow).as_ref() }
            .ok_or("startup window has no native window")?;
        native_window.setBackgroundColor(Some(&NSColor::colorWithSRGBRed_green_blue_alpha(
            11.0 / 255.0,
            14.0 / 255.0,
            20.0 / 255.0,
            1.0,
        )));
        native_window.setTitlebarAppearsTransparent(true);
        // SAFETY: AppKit's immutable named-appearance constant.
        let appearance = unsafe { NSAppearance::appearanceNamed(NSAppearanceNameDarkAqua) };
        native_window.setAppearance(appearance.as_deref());
        // Tao disables these controls; hide them as well so only minimize is shown.
        for button in [NSWindowButton::CloseButton, NSWindowButton::ZoomButton] {
            if let Some(button) = native_window.standardWindowButton(button) {
                button.setHidden(true);
            }
        }
        let image = NSImage::initWithData(NSImage::alloc(), &NSData::with_bytes(png))
            .ok_or("decode startup brand image")?;
        // AppKit owns the backing layer's anchor/position (normally 0,0).
        // Rotate a separate child layer so animation cannot move the host view.
        let host =
            NSImageView::initWithFrame(NSImageView::alloc(mtm), frame(158.0, 174.0, 144.0, 144.0));
        host.setAccessibilityLabel(Some(&NSString::from_str("EpixNet")));
        host.setWantsLayer(true);
        parent.addSubview(&host);
        let icon = CALayer::new();
        icon.setBounds(frame(0.0, 0.0, 96.0, 96.0));
        icon.setAnchorPoint(NSPoint::new(0.5, 0.5));
        icon.setPosition(NSPoint::new(72.0, 72.0));
        // SAFETY: macOS explicitly supports NSImage as standalone CALayer
        // contents; this is our child layer, not AppKit's view backing layer.
        unsafe {
            icon.setContents(Some(&image));
        }
        host.layer()
            .ok_or("startup image has no native layer")?
            .addSublayer(&icon);

        let title = label(
            parent,
            mtm,
            "EpixNet",
            frame(30.0, 140.0, 400.0, 34.0),
            26.0,
        );
        title.setFont(Some(&NSFont::boldSystemFontOfSize(26.0)));
        let status = label(parent, mtm, "", frame(30.0, 105.0, 400.0, 24.0), 14.0);
        let detail = label(parent, mtm, "", frame(30.0, 28.0, 400.0, 42.0), 12.0);
        detail.setTextColor(Some(&NSColor::secondaryLabelColor()));
        detail.setMaximumNumberOfLines(3);
        detail.setUsesSingleLineMode(false);
        detail.setSelectable(true);
        detail.setLineBreakMode(NSLineBreakMode::ByWordWrapping);
        let footer = label(
            parent,
            mtm,
            "Press Esc to exit.",
            frame(30.0, 8.0, 400.0, 18.0),
            11.0,
        );
        footer.setHidden(true);
        let progress = NSProgressIndicator::initWithFrame(
            NSProgressIndicator::alloc(mtm),
            frame(54.0, 83.0, 352.0, 8.0),
        );
        progress.setStyle(NSProgressIndicatorStyle::Bar);
        progress.setDisplayedWhenStopped(true);
        progress.setMinValue(0.0);
        progress.setMaxValue(1.0);
        progress.setAccessibilityLabel(Some(&NSString::from_str("Startup progress")));
        parent.addSubview(&progress);
        let mut controls = Self {
            icon,
            status,
            detail,
            footer,
            progress,
            failed: false,
            spinning: false,
        };
        controls.animate(true);
        Ok(controls)
    }

    pub(super) fn animate(&mut self, visible: bool) {
        let spinning = visible && !self.failed;
        if spinning == self.spinning {
            return;
        }
        {
            let layer = &self.icon;
            let key = NSString::from_str("epix-startup-rotation");
            if spinning {
                let animation = CABasicAnimation::animationWithKeyPath(Some(&NSString::from_str(
                    "transform.rotation.z",
                )));
                // SAFETY: this scalar transform property takes NSNumber values;
                // Core Animation retains the supplied objects and animation.
                unsafe {
                    animation.setFromValue(Some(&NSNumber::new_f64(0.0)));
                    animation.setToValue(Some(&NSNumber::new_f64(-std::f64::consts::TAU)));
                    animation.setTimingFunction(Some(&CAMediaTimingFunction::functionWithName(
                        kCAMediaTimingFunctionLinear,
                    )));
                }
                animation.setDuration(1.2);
                animation.setRepeatCount(f32::INFINITY);
                layer.addAnimation_forKey(&animation, Some(&key));
            } else {
                layer.removeAnimationForKey(&key);
            }
            self.spinning = spinning;
        }
    }

    pub(super) fn update(&mut self, status: &str, detail: &str, completed: u32, total: u32) {
        self.failed = status == super::FAILED_STATUS;
        self.status.setStringValue(&NSString::from_str(status));
        self.status.setToolTip(Some(&NSString::from_str(status)));
        let body = NSString::from_str(super::detail_body(detail));
        self.detail.setStringValue(&body);
        self.detail.setToolTip(Some(&body));
        self.detail.setFrame(if self.failed {
            frame(30.0, 31.0, 400.0, 66.0)
        } else {
            frame(30.0, 28.0, 400.0, 42.0)
        });
        self.detail
            .setMaximumNumberOfLines(if self.failed { 4 } else { 3 });
        self.footer.setHidden(!self.failed);
        self.progress.setHidden(self.failed);
        self.progress.setIndeterminate(total == 0 && !self.failed);
        if self.failed {
            self.animate(false);
        }
        // SAFETY: no sender is required; Cocoa owns animation scheduling.
        unsafe {
            if total == 0 && !self.failed {
                self.progress.startAnimation(None);
            } else {
                self.progress.stopAnimation(None);
                if total != 0 {
                    self.progress
                        .setDoubleValue(f64::from(completed.min(total)) / f64::from(total));
                }
            }
        }
    }
}
