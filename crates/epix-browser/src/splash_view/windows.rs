use std::ptr::{null, null_mut};
use std::time::Instant;

use tao::platform::windows::WindowExtWindows;
use tao::window::Window;
use windows_sys::core::w;
use windows_sys::Win32::Foundation::{HWND, RECT};
use windows_sys::Win32::Graphics::Gdi::{
    BeginPaint, CreateDIBSection, CreateFontIndirectW, CreateSolidBrush, DeleteObject, EndPaint,
    FillRect, GdiFlush, GetObjectW, GetStockObject, InvalidateRect, SetBkColor, SetDIBitsToDevice,
    SetTextColor, BITMAPINFO, BITMAPINFOHEADER, BI_RGB, DEFAULT_GUI_FONT, DIB_RGB_COLORS, HBITMAP,
    HBRUSH, HDC, HFONT, LOGFONTW, PAINTSTRUCT,
};
use windows_sys::Win32::System::SystemServices::{SS_BITMAP, SS_CENTER, SS_NOPREFIX};
use windows_sys::Win32::UI::Controls::{
    InitCommonControlsEx, ICC_PROGRESS_CLASS, INITCOMMONCONTROLSEX, PBM_SETPOS, PBM_SETRANGE32,
    PROGRESS_CLASSW, TOOLTIPS_CLASSW, TTF_IDISHWND, TTF_SUBCLASS, TTM_ADDTOOLW, TTM_SETMAXTIPWIDTH,
    TTM_UPDATETIPTEXTW, TTS_ALWAYSTIP, TTTOOLINFOW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DestroyWindow, GetClientRect, GetWindowRect, MoveWindow, SendMessageW,
    SetWindowTextW, ShowWindow, HTCAPTION, IMAGE_BITMAP, STM_SETIMAGE, SW_HIDE, SW_SHOW,
    WM_CTLCOLORSTATIC, WM_ERASEBKGND, WM_NCHITTEST, WM_PAINT, WM_SETFONT, WS_CHILD, WS_POPUP,
    WS_VISIBLE,
};

use windows_sys::Win32::UI::Shell::{DefSubclassProc, RemoveWindowSubclass, SetWindowSubclass};

const BACKGROUND: u32 = 0x0014_0e0b;
const SUBCLASS_ID: usize = 0x4550_4958;
const PROGRESS_SUBCLASS_ID: usize = SUBCLASS_ID + 1;

pub(super) struct Controls {
    parent: HWND,
    brush: HBRUSH,
    icon: HWND,
    frames: Vec<Vec<u32>>,
    bitmap_bits: *mut u32,
    started: Instant,
    last_frame: usize,
    failed: bool,
    scale: f64,
    footer: HWND,
    tooltip: HWND,
    tooltip_text: Vec<u16>,
    children: Vec<HWND>,
    fonts: Vec<HFONT>,
    bitmap: HBITMAP,
    status: HWND,
    detail: HWND,
    progress: HWND,
    progress_paint: Box<ProgressPaint>,
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(Some(0)).collect()
}

impl Controls {
    pub(super) fn new(window: &Window, png: &[u8]) -> Result<Self, String> {
        let init = INITCOMMONCONTROLSEX {
            dwSize: std::mem::size_of::<INITCOMMONCONTROLSEX>() as u32,
            dwICC: ICC_PROGRESS_CLASS,
        };
        // SAFETY: `init` is a fully initialized native descriptor and lives
        // through this synchronous call; the parent HWND belongs to Tao.
        if unsafe { InitCommonControlsEx(&init) } == 0 {
            return Err("initialize native progress control".into());
        }
        let mut controls = Self {
            parent: window.hwnd() as HWND,
            brush: null_mut(),
            icon: null_mut(),
            frames: Vec::new(),
            bitmap_bits: null_mut(),
            started: Instant::now(),
            last_frame: 0,
            failed: false,
            scale: window.scale_factor(),
            footer: null_mut(),
            tooltip: null_mut(),
            tooltip_text: wide(""),
            children: Vec::new(),
            fonts: Vec::new(),
            bitmap: null_mut(),
            status: null_mut(),
            detail: null_mut(),
            progress: null_mut(),
            progress_paint: Box::new(ProgressPaint::new()),
        };
        let scale = window.scale_factor();
        // SAFETY: our subclass uses only this brush handle and is removed before it is freed.
        unsafe {
            controls.brush = CreateSolidBrush(BACKGROUND);
            if controls.brush.is_null() {
                return Err("create startup background brush".into());
            }
            if SetWindowSubclass(
                controls.parent,
                Some(panel_proc),
                SUBCLASS_ID,
                controls.brush as usize,
            ) == 0
            {
                return Err("style native startup panel".into());
            }
        }
        let size = (144.0 * scale).round() as u32;
        controls.frames = super::animation_frames(png, size)?
            .into_iter()
            .map(|pixels| {
                pixels
                    .chunks_exact(4)
                    .map(|rgba| {
                        let alpha = u32::from(rgba[3]);
                        let blend =
                            |channel: u32| (255 * alpha + channel * (255 - alpha) + 127) / 255;
                        (blend(11) << 16) | (blend(14) << 8) | blend(20)
                    })
                    .collect()
            })
            .collect();
        (controls.bitmap, controls.bitmap_bits) = image_bitmap(size)?;
        let icon = controls.child(
            window,
            w!("STATIC"),
            "EpixNet",
            SS_BITMAP,
            [158, 2, 144, 144],
        )?;
        controls.icon = icon;
        let heading = controls.child(
            window,
            w!("STATIC"),
            "EpixNet",
            SS_CENTER | SS_NOPREFIX,
            [30, 146, 400, 36],
        )?;
        controls.status = controls.child(
            window,
            w!("STATIC"),
            "",
            SS_CENTER | SS_NOPREFIX,
            [30, 191, 400, 24],
        )?;
        controls.progress = controls.child(
            window,
            PROGRESS_CLASSW,
            "Startup progress",
            0,
            [54, 231, 352, 6],
        )?;
        controls.detail = controls.child(
            window,
            w!("STATIC"),
            "",
            SS_CENTER | SS_NOPREFIX,
            [30, 250, 400, 42],
        )?;
        controls.footer = controls.child(
            window,
            w!("STATIC"),
            "Press Esc to exit.",
            SS_CENTER | SS_NOPREFIX,
            [30, 294, 400, 18],
        )?;
        controls.font(controls.footer, 11.0 * scale, false)?;
        controls.font(heading, 26.0 * scale, true)?;
        controls.font(controls.status, 14.0 * scale, false)?;
        controls.font(controls.detail, 12.0 * scale, false)?;
        // SAFETY: these handles were created above on this thread; controls
        // retain the bitmap and fonts until after their child HWNDs are gone.
        unsafe {
            SendMessageW(
                icon,
                STM_SETIMAGE,
                IMAGE_BITMAP as usize,
                controls.bitmap as isize,
            );
            SendMessageW(controls.progress, PBM_SETRANGE32, 0, 1000);
            // The native control retains its accessibility range; only its
            // paint path changes. The boxed state stays at a stable address.
            if SetWindowSubclass(
                controls.progress,
                Some(progress_proc),
                PROGRESS_SUBCLASS_ID,
                &mut *controls.progress_paint as *mut ProgressPaint as usize,
            ) == 0
            {
                return Err("style startup progress bar".into());
            }
            ShowWindow(controls.footer, SW_HIDE);
            controls.tooltip = CreateWindowExW(
                0,
                TOOLTIPS_CLASSW,
                null(),
                WS_POPUP | TTS_ALWAYSTIP,
                0,
                0,
                0,
                0,
                controls.parent,
                null_mut(),
                window.hinstance() as _,
                null(),
            );
            if !controls.tooltip.is_null() {
                controls.children.push(controls.tooltip);
                let tool = controls.tooltip_info();
                SendMessageW(
                    controls.tooltip,
                    TTM_ADDTOOLW,
                    0,
                    &tool as *const _ as isize,
                );
                SendMessageW(
                    controls.tooltip,
                    TTM_SETMAXTIPWIDTH,
                    0,
                    (400.0 * scale) as isize,
                );
            }
        }
        controls.paint_frame(0);
        Ok(controls)
    }

    fn child(
        &mut self,
        window: &Window,
        class: *const u16,
        text: &str,
        style: u32,
        rect: [i32; 4],
    ) -> Result<HWND, String> {
        let text = wide(text);
        let pixels = rect.map(|value| (f64::from(value) * window.scale_factor()).round() as i32);
        // SAFETY: class/text are NUL-terminated and alive for the call; the
        // native parent remains alive for this Controls instance's lifetime.
        let child = unsafe {
            CreateWindowExW(
                0,
                class,
                text.as_ptr(),
                WS_CHILD | WS_VISIBLE | style,
                pixels[0],
                pixels[1],
                pixels[2],
                pixels[3],
                window.hwnd() as HWND,
                null_mut(),
                window.hinstance() as _,
                null(),
            )
        };
        if child.is_null() {
            return Err(format!(
                "create native startup control: {}",
                std::io::Error::last_os_error()
            ));
        }
        self.children.push(child);
        Ok(child)
    }

    fn font(&mut self, child: HWND, height: f64, bold: bool) -> Result<(), String> {
        let mut font = LOGFONTW::default();
        // SAFETY: GetObjectW receives an appropriately sized LOGFONTW. The
        // stock font is borrowed; only our newly created font is later freed.
        unsafe {
            if GetObjectW(
                GetStockObject(DEFAULT_GUI_FONT),
                std::mem::size_of::<LOGFONTW>() as i32,
                &mut font as *mut LOGFONTW as _,
            ) == 0
            {
                return Err("read native system font".into());
            }
            font.lfHeight = -(height.round() as i32);
            font.lfWeight = if bold { 600 } else { 400 };
            for (slot, character) in font.lfFaceName.iter_mut().zip(wide("Segoe UI")) {
                *slot = character;
            }
            let handle = CreateFontIndirectW(&font);
            if handle.is_null() {
                return Err("create startup system font".into());
            }
            self.fonts.push(handle);
            SendMessageW(child, WM_SETFONT, handle as usize, 1);
        }
        Ok(())
    }

    fn tooltip_info(&self) -> TTTOOLINFOW {
        TTTOOLINFOW {
            cbSize: std::mem::size_of::<TTTOOLINFOW>() as u32,
            uFlags: TTF_IDISHWND | TTF_SUBCLASS,
            hwnd: self.parent,
            uId: self.detail as usize,
            lpszText: self.tooltip_text.as_ptr() as *mut u16,
            ..Default::default()
        }
    }

    fn paint_frame(&mut self, frame: usize) {
        // SAFETY: this DIB owns exactly the pixel count of each cached frame;
        // native UI drawing and writes both run on this single window thread.
        unsafe {
            GdiFlush();
            std::ptr::copy_nonoverlapping(
                self.frames[frame].as_ptr(),
                self.bitmap_bits,
                self.frames[frame].len(),
            );
            InvalidateRect(self.icon, null(), 0);
        }
        self.last_frame = frame;
    }

    pub(super) fn animate(&mut self, visible: bool) {
        if !visible || self.failed {
            return;
        }
        self.progress_paint.animate();
        // SAFETY: invalidation schedules painting on this same UI thread.
        unsafe {
            InvalidateRect(self.progress, null(), 0);
        }
        let frame = super::animation_frame(self.started.elapsed());
        if frame != self.last_frame {
            self.paint_frame(frame);
        }
    }

    pub(super) fn update(&mut self, status: &str, detail: &str, completed: u32, total: u32) {
        self.failed = status == super::FAILED_STATUS;
        let status = wide(status);
        let detail = wide(super::detail_body(detail));
        let indeterminate = total == 0 && !self.failed;
        // SAFETY: HWNDs belong to this instance and updates run on Tao's main
        // thread. Native tooltip text remains allocated until its next update.
        unsafe {
            SetWindowTextW(self.status, status.as_ptr());
            SetWindowTextW(self.detail, detail.as_ptr());
            let previous_tooltip_text = std::mem::replace(&mut self.tooltip_text, detail);
            if !self.tooltip.is_null() {
                let tool = self.tooltip_info();
                SendMessageW(
                    self.tooltip,
                    TTM_UPDATETIPTEXTW,
                    0,
                    &tool as *const _ as isize,
                );
            }
            drop(previous_tooltip_text);
            let rect = [
                30.0,
                if self.failed { 223.0 } else { 250.0 },
                400.0,
                if self.failed { 66.0 } else { 42.0 },
            ]
            .map(|v| (v * self.scale).round() as i32);
            MoveWindow(self.detail, rect[0], rect[1], rect[2], rect[3], 1);
            ShowWindow(self.footer, if self.failed { SW_SHOW } else { SW_HIDE });
            ShowWindow(self.progress, if self.failed { SW_HIDE } else { SW_SHOW });
            self.progress_paint.indeterminate = indeterminate;
            if total != 0 {
                self.progress_paint.target = f64::from(completed.min(total)) / f64::from(total);
            }
            InvalidateRect(self.progress, null(), 0);
            if total != 0 {
                let progress = u64::from(completed.min(total)) * 1000 / u64::from(total);
                SendMessageW(self.progress, PBM_SETPOS, progress as usize, 0);
            }
        }
        if self.failed {
            self.paint_frame(0);
        }
    }
}

impl Drop for Controls {
    fn drop(&mut self) {
        // SAFETY: every object was allocated by this instance. Destroy child
        // windows first so no live native control can reference a freed image
        // or font. Tao destroys the parent after this destructor returns.
        unsafe {
            RemoveWindowSubclass(self.parent, Some(panel_proc), SUBCLASS_ID);
            if !self.progress.is_null() {
                RemoveWindowSubclass(self.progress, Some(progress_proc), PROGRESS_SUBCLASS_ID);
            }
            for child in self.children.drain(..).rev() {
                DestroyWindow(child);
            }
            for font in self.fonts.drain(..) {
                DeleteObject(font);
            }
            if !self.brush.is_null() {
                DeleteObject(self.brush);
            }
            if !self.bitmap.is_null() {
                DeleteObject(self.bitmap);
            }
        }
    }
}

// SAFETY: registered only on our own parent window. The brush outlives this
// callback; all messages not explicitly handled continue through Tao normally.
unsafe extern "system" fn panel_proc(
    hwnd: HWND,
    message: u32,
    wparam: usize,
    lparam: isize,
    _id: usize,
    brush: usize,
) -> isize {
    unsafe {
        match message {
            WM_CTLCOLORSTATIC => {
                SetTextColor(wparam as HDC, 0x00ff_ffff);
                SetBkColor(wparam as HDC, BACKGROUND);
                return brush as isize;
            }
            WM_ERASEBKGND => {
                let mut rect = RECT::default();
                GetClientRect(hwnd, &mut rect);
                FillRect(wparam as HDC, &rect, brush as HBRUSH);
                return 1;
            }
            WM_NCHITTEST => {
                let mut rect = RECT::default();
                GetWindowRect(hwnd, &mut rect);
                let y = ((lparam >> 16) as i16) as i32;
                if y >= rect.top && y < rect.top + (rect.right - rect.left) * 28 / 460 {
                    return HTCAPTION as isize;
                }
            }
            _ => {}
        }
        DefSubclassProc(hwnd, message, wparam, lparam)
    }
}

fn image_bitmap(size: u32) -> Result<(HBITMAP, *mut u32), String> {
    let info = BITMAPINFO {
        bmiHeader: BITMAPINFOHEADER {
            biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
            biWidth: size as i32,
            biHeight: -(size as i32),
            biPlanes: 1,
            biBitCount: 32,
            biCompression: BI_RGB,
            ..Default::default()
        },
        ..Default::default()
    };
    let mut bits = null_mut();
    // SAFETY: descriptor requests exactly size*size 32-bit pixels. Caller owns
    // the resulting bitmap and keeps its mapped storage alive until drop.
    unsafe {
        let bitmap = CreateDIBSection(null_mut(), &info, DIB_RGB_COLORS, &mut bits, null_mut(), 0);
        if bitmap.is_null() {
            return Err("create startup image bitmap".into());
        }
        if bits.is_null() {
            DeleteObject(bitmap);
            return Err("map startup image bitmap".into());
        }
        Ok((bitmap, bits.cast()))
    }
}

// Paint a thin antialiased capsule while retaining the native progress
// control's accessibility semantics. All state lives on the window thread.
struct ProgressPaint {
    started: Instant,
    last_tick: Instant,
    shown: f64,
    target: f64,
    indeterminate: bool,
    pixels: Vec<u32>,
}

impl ProgressPaint {
    fn new() -> Self {
        Self {
            started: Instant::now(),
            last_tick: Instant::now(),
            shown: 0.0,
            target: 0.0,
            indeterminate: true,
            pixels: Vec::new(),
        }
    }

    fn animate(&mut self) {
        let now = Instant::now();
        let dt = now.duration_since(self.last_tick).as_secs_f64();
        self.last_tick = now;
        self.shown += (self.target - self.shown) * (1.0 - (-dt * 12.0).exp());
    }

    fn render(&mut self, width: usize, height: usize) {
        self.pixels.resize(width * height, 0);
        let w = width as f64;
        let h = height as f64;
        let (left, right) = if self.indeterminate {
            let phase = self.started.elapsed().as_secs_f64() * std::f64::consts::TAU / 1.8;
            let left = (0.5 - 0.5 * phase.cos()) * w * 0.68;
            (left, left + w * 0.32)
        } else {
            (0.0, w * self.shown.clamp(0.0, 1.0))
        };
        let coverage = |x: f64, y: f64, left: f64, right: f64| {
            let radius = (h / 2.0).min((right - left) / 2.0);
            if radius <= 0.0 {
                return 0.0;
            }
            let center = x.clamp(left + radius, right - radius);
            (radius + 0.5 - ((x - center).powi(2) + (y - h / 2.0).powi(2)).sqrt()).clamp(0.0, 1.0)
        };
        for y in 0..height {
            for x in 0..width {
                let px = x as f64 + 0.5;
                let py = y as f64 + 0.5;
                let track = coverage(px, py, 0.0, w);
                let fill = coverage(px, py, left, right);
                let mix = |a: f64, b: f64, t: f64| a + (b - a) * t;
                let t = px / w;
                let channel = |background, rail, from, to| {
                    mix(mix(background, rail, track), mix(from, to, t), fill).round() as u32
                };
                let r = channel(11.0, 35.0, 84.0, 137.0);
                let g = channel(14.0, 43.0, 210.0, 156.0);
                let b = channel(20.0, 58.0, 244.0, 255.0);
                self.pixels[y * width + x] = (r << 16) | (g << 8) | b;
            }
        }
    }
}

// SAFETY: the boxed paint state outlives this subclass and is accessed only
// on the UI thread. RemoveWindowSubclass runs before that box is dropped.
unsafe extern "system" fn progress_proc(
    hwnd: HWND,
    message: u32,
    wparam: usize,
    lparam: isize,
    _id: usize,
    data: usize,
) -> isize {
    unsafe {
        match message {
            WM_ERASEBKGND => return 1,
            WM_PAINT => {
                let mut paint = PAINTSTRUCT::default();
                let dc = BeginPaint(hwnd, &mut paint);
                let mut rect = RECT::default();
                GetClientRect(hwnd, &mut rect);
                let width = rect.right.max(0) as usize;
                let height = rect.bottom.max(0) as usize;
                if !dc.is_null() && width > 0 && height > 0 {
                    let state = &mut *(data as *mut ProgressPaint);
                    state.render(width, height);
                    let info = BITMAPINFO {
                        bmiHeader: BITMAPINFOHEADER {
                            biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                            biWidth: width as i32,
                            biHeight: -(height as i32),
                            biPlanes: 1,
                            biBitCount: 32,
                            biCompression: BI_RGB,
                            ..Default::default()
                        },
                        ..Default::default()
                    };
                    SetDIBitsToDevice(
                        dc,
                        0,
                        0,
                        width as u32,
                        height as u32,
                        0,
                        0,
                        0,
                        height as u32,
                        state.pixels.as_ptr().cast(),
                        &info,
                        DIB_RGB_COLORS,
                    );
                }
                EndPaint(hwnd, &paint);
                return 0;
            }
            _ => {}
        }
        DefSubclassProc(hwnd, message, wparam, lparam)
    }
}
