//! Export objects from an EDX store to plain files.
//!
//! Usage: export <store_dir> [xite_root]
//! Reads lines of `<b3hex> <output_path>` on stdin. Writes each complete
//! object to its path (8 MiB reads, so big files never fully materialize
//! in memory). Prints one status line per object.
//!
//! `xite_root` is the node's `data/` directory, needed because a large
//! object's bytes live in the xite tree and the store only holds its
//! outboard (`Loc::Extern`). Without it every such object exports as an
//! error - which is the opposite of useful, since recovering big files is
//! what this tool is for. Defaults to `<store_dir>/../data`, the real
//! layout of a node's data directory.

use epix_blob::store::{Store, StoreConfig};
use epix_blob::ObjId;
use std::io::{BufRead, Write};

fn main() {
    let store_dir = std::env::args().nth(1).expect("usage: export <store_dir> [xite_root]");
    let xite_root = std::env::args()
        .nth(2)
        .map(std::path::PathBuf::from)
        .or_else(|| std::path::Path::new(&store_dir).parent().map(|p| p.join("data")));
    let store = Store::open_with(
        &store_dir,
        StoreConfig { xite_root: xite_root.clone(), ..Default::default() },
    )
    .expect("open store");
    if let Some(root) = &xite_root {
        if !root.is_dir() {
            eprintln!(
                "warning: xite root {} does not exist; objects whose bytes live in the \
                 xite tree will export as errors (pass the node's data/ directory)",
                root.display()
            );
        }
    }
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
