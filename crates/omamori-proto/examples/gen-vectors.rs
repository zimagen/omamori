//! Generate public, deterministic interoperability fixtures (not real secrets).
#[path = "../support/vectors.rs"]
mod vectors;

fn main() {
    println!(
        "{}",
        serde_json::to_string_pretty(&vectors::generate()).unwrap()
    );
}
