//! End-to-end tests that drive the built binary the way a user would.
//!
//! Nothing here opens a radio or transmits. The flood is generated in memory
//! and, for the replay check, saved to a pcap of Bluetooth advertising packets.

use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_remoteid-demo"))
}

fn stdout(args: &[&str]) -> String {
    let out = bin().args(args).output().expect("run remoteid-demo");
    assert!(
        out.status.success(),
        "non-zero exit for {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).expect("utf8 stdout")
}

#[test]
fn generated_flood_is_flagged_and_names_the_genuine_drone() {
    let out = stdout(&["analyze", "--count", "200"]);
    assert!(out.contains("FLOODED"), "should call the flood:\n{out}");
    assert!(
        out.contains("fake identities broadcast from one source address"),
        "should report the fan-out:\n{out}"
    );
    // The embedded genuine track has this serial; it must be the one named.
    assert!(
        out.contains("Most likely real drone: 1581CREAL7A4F2C91"),
        "should name the genuine drone:\n{out}"
    );
}

#[test]
fn saved_capture_replays_to_the_same_verdict() {
    let dir = std::env::temp_dir().join("remoteid-demo-test");
    std::fs::create_dir_all(&dir).unwrap();
    let cap = dir.join("flood.pcap");
    let cap = cap.to_str().unwrap();

    let generated = stdout(&["analyze", "--count", "150", "--save", cap]);
    assert!(generated.contains("FLOODED"));

    // Re-analyzing the saved capture must reproduce the same call and the same
    // genuine drone: the generated path and the capture path agree.
    let replayed = stdout(&["analyze", cap]);
    assert!(
        replayed.contains("FLOODED"),
        "replay should flood:\n{replayed}"
    );
    assert!(
        replayed.contains("Most likely real drone: 1581CREAL7A4F2C91"),
        "replay should name the same genuine drone:\n{replayed}"
    );
}

#[test]
fn decode_pretty_prints_remote_id() {
    let dir = std::env::temp_dir().join("remoteid-demo-test");
    std::fs::create_dir_all(&dir).unwrap();
    let cap = dir.join("decode.pcap");
    let cap = cap.to_str().unwrap();

    stdout(&["analyze", "--count", "20", "--save", cap]);
    let out = stdout(&["decode", cap, "--limit", "4"]);
    assert!(out.contains("BasicId"), "should decode a Basic ID:\n{out}");
    assert!(out.contains("Location"), "should decode a Location:\n{out}");
    assert!(
        out.contains("via bt4"),
        "frames are Bluetooth 4 legacy:\n{out}"
    );
}

#[test]
fn tiny_field_still_produces_a_verdict() {
    // A one-fake field is degenerate, not a real flood. The run must still
    // finish cleanly and print a verdict rather than panic.
    let out = stdout(&["analyze", "--count", "1"]);
    assert!(
        out.contains("VERDICT:"),
        "should still produce a verdict:\n{out}"
    );
}
