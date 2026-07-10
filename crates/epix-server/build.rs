//! Stamp the build with a version + short git commit (the dashboard shows them
//! next to each other). The logic is shared with epix-browser via epix-build.

fn main() {
    epix_build::emit_version_and_rev();
}
