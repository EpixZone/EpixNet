//! Blocking, bounded socket-byte API. Platform callers use their IO workers.
use crate::{EpixError, EpixNode};
use epix_ui::state::native_radio as core;
use std::sync::Arc;
use std::time::Duration;

#[derive(uniffi::Enum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeRadioState {
    FeatureUnavailable,
    Offline,
    MeshDisabled,
    Starting,
    Ready,
}

#[derive(uniffi::Enum, Clone, Copy)]
pub enum NativeRadioKind {
    Ble,
    WifiAware,
}

#[derive(uniffi::Record)]
pub struct NativeRadioStatus {
    pub state: NativeRadioState,
    pub max_links: u32,
    pub max_chunk_bytes: u32,
}

#[derive(uniffi::Record)]
pub struct NativeRadioRead {
    pub data: Vec<u8>,
    pub closed: bool,
}

#[derive(uniffi::Object)]
pub struct NativeRadioStream {
    node: Arc<EpixNode>,
    stream: Arc<dyn core::NativeRadioStream>,
}

#[uniffi::export]
impl NativeRadioStream {
    pub fn write(&self, bytes: Vec<u8>, timeout_ms: u32) -> Result<(), EpixError> {
        self.node
            .rt
            .block_on(
                self.stream
                    .write(bytes, Duration::from_millis(u64::from(timeout_ms))),
            )
            .map_err(EpixError::msg)
    }

    pub fn read(&self, max_bytes: u32, timeout_ms: u32) -> Result<NativeRadioRead, EpixError> {
        self.node
            .rt
            .block_on(self.stream.read(
                max_bytes as usize,
                Duration::from_millis(u64::from(timeout_ms)),
            ))
            .map(|read| NativeRadioRead {
                data: read.data,
                closed: read.closed,
            })
            .map_err(EpixError::msg)
    }

    pub fn disconnect(&self) {
        self.stream.close();
    }
}

impl Drop for NativeRadioStream {
    fn drop(&mut self) {
        self.stream.close();
    }
}

#[uniffi::export]
impl EpixNode {
    pub fn native_radio_status(&self) -> NativeRadioStatus {
        let state = self.inner.lock().unwrap().node.clone();
        let status = state.map(|state| self.rt.block_on(state.native_radio_state()));
        let state = match status {
            Some(core::NativeRadioState::FeatureUnavailable) => {
                NativeRadioState::FeatureUnavailable
            }
            Some(core::NativeRadioState::Offline) => NativeRadioState::Offline,
            Some(core::NativeRadioState::MeshDisabled) => NativeRadioState::MeshDisabled,
            Some(core::NativeRadioState::Starting) | None => NativeRadioState::Starting,
            Some(core::NativeRadioState::Ready) => NativeRadioState::Ready,
        };
        NativeRadioStatus {
            state,
            max_links: 8,
            max_chunk_bytes: 4096,
        }
    }

    pub fn set_native_mesh_enabled(&self, enabled: bool) -> Result<(), EpixError> {
        let state = self
            .inner
            .lock()
            .unwrap()
            .node
            .clone()
            .ok_or_else(|| EpixError::msg("node has not started"))?;
        self.rt
            .block_on(state.set_native_mesh_enabled(enabled))
            .map_err(EpixError::msg)
    }

    pub fn open_native_radio(
        self: Arc<Self>,
        kind: NativeRadioKind,
    ) -> Result<Arc<NativeRadioStream>, EpixError> {
        let state = self
            .inner
            .lock()
            .unwrap()
            .node
            .clone()
            .ok_or_else(|| EpixError::msg("node has not started"))?;
        let kind = match kind {
            NativeRadioKind::Ble => core::NativeRadioKind::Ble,
            NativeRadioKind::WifiAware => core::NativeRadioKind::WifiAware,
        };
        let stream = self
            .rt
            .block_on(state.open_native_radio(kind))
            .map_err(EpixError::msg)?;
        Ok(Arc::new(NativeRadioStream { node: self, stream }))
    }
}
