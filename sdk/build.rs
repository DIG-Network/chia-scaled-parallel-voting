// build.rs
// Embeds the compiled Rue puzzle bytecode and tree hashes into the SDK
// at build time, sourced from ../puzzles/compiled/. Run `./build.ps1`
// (or `./build.sh`) at the project root to regenerate puzzles before
// building the SDK.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

const COMPILED_ROOT_FROM_SDK: &str = "../puzzles/compiled";

fn main() {
    let sdk_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    let compiled = PathBuf::from(&sdk_dir).join(COMPILED_ROOT_FROM_SDK);

    if !compiled.exists() {
        panic!(
            "Compiled puzzles not found at {}. Run `./build.ps1` (Windows) or `./build.sh` (Linux/macOS) at the CHIP project root first.",
            compiled.display()
        );
    }

    println!("cargo:rerun-if-changed={}", compiled.display());
    walk_for_rerun(&compiled);
}

fn walk_for_rerun(dir: &Path) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk_for_rerun(&path);
        } else if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if name.ends_with(".hex") || name.ends_with(".hash") {
                println!("cargo:rerun-if-changed={}", path.display());
            }
        }
    }
}
