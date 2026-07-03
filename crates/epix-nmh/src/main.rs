//! The Epix native-messaging host binary.
//!
//! Firefox launches this and talks to it over stdio (4-byte LE length + JSON).
//! Each message is handled by [`epix_nmh::handle`]. Settings live next to the
//! node data so the launcher and the node see the same file.

use epix_nmh::{handle, read_frame, write_frame, Settings};
use std::io::{stdin, stdout};

const UI_PORT: u16 = 43110;

fn main() {
    let settings = Settings::new(&epix_node::data_root());
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    let mut input = stdin().lock();
    let mut output = stdout().lock();
    loop {
        match read_frame(&mut input) {
            Ok(Some(req)) => {
                let resp = rt.block_on(handle(&req, &settings, UI_PORT));
                if write_frame(&mut output, &resp).is_err() {
                    break;
                }
            }
            Ok(None) => break, // Firefox closed the pipe
            Err(_) => break,
        }
    }
}
