//! Export objects from an EDX store to plain files.
//!
//! Usage: export <store_dir>
//! Reads lines of `<b3hex> <output_path>` on stdin. Writes each complete
//! object to its path (8 MiB reads, so big files never fully materialize
//! in memory). Prints one status line per object.

use epix_blob::store::Store;
use epix_blob::ObjId;
use std::io::{BufRead, Write};

fn main() {
    let store_dir = std::env::args().nth(1).expect("usage: export <store_dir>");
    let store = Store::open(&store_dir).expect("open store");
    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let line = line.unwrap();
        let mut parts = line.splitn(2, ' ');
        let (Some(hex), Some(out)) = (parts.next(), parts.next()) else { continue };
        let Some(id) = ObjId::from_hex(hex) else {
            println!("BAD {hex}");
            continue;
        };
        match store.info(id) {
            Ok(Some((size, true))) => {
                let mut f = std::fs::File::create(out).expect("create output");
                let mut off = 0u64;
                let mut ok = true;
                while off < size {
                    let want = (size - off).min(8 << 20);
                    match store.read_range(id, off, want, 0) {
                        Ok(b) => {
                            f.write_all(&b).expect("write output");
                            off += b.len() as u64;
                        }
                        Err(e) => {
                            println!("ERR {hex} at {off}: {e}");
                            ok = false;
                            break;
                        }
                    }
                }
                if ok {
                    println!("OK {hex} {size} {out}");
                }
            }
            Ok(Some((size, false))) => println!("PARTIAL {hex} {size}"),
            Ok(None) => println!("MISSING {hex}"),
            Err(e) => println!("ERR {hex}: {e}"),
        }
    }
}
