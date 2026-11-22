//! `remoteid-demo`: a runnable tour of the Remote ID counter-UAS stack.
//!
//! Three things, all from one binary:
//!
//! 1. `analyze` with no file builds a flood scenario with
//!    [`remoteid-scenario`](https://crates.io/crates/remoteid-scenario) (one
//!    on-air source, hundreds of fake identities, one genuine moving track),
//!    runs [`remoteid-sentinel`](https://crates.io/crates/remoteid-sentinel)
//!    over it, and prints a plain report: is the airspace flooded, how many
//!    fakes from one source, and which track is most likely the one real drone.
//! 2. `analyze <FILE>` does the same over a real captured Remote ID file
//!    (pcap, pcapng or RIDF, the formats [`remoteid`] already reads).
//! 3. `decode <FILE>` just decodes and pretty-prints the Remote ID in a
//!    capture, DJI DroneID included.
//!
//! # Hard boundary
//!
//! This is analysis only. It never opens a radio and has no transmit path. The
//! generator writes test vectors to memory or a file, exactly the way an EICAR
//! string or a fuzzer corpus is data and not a virus. Nothing here broadcasts.

mod decode;
mod field;

use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};

/// Demo CLI for the Remote ID counter-UAS stack (analysis only, no radio).
#[derive(Parser)]
#[command(
    name = "remoteid-demo",
    version,
    about = "Tour of the Remote ID counter-UAS stack: flood/spoof detection and decode. Analysis only, no radio, no transmit path.",
    long_about = "remoteid-demo shows off the Remote ID counter-UAS stack end to end.\n\n\
        With no capture it generates a drone-flood scenario (one on-air source, \
        hundreds of fake identities, one genuine moving track) with remoteid-scenario, \
        runs the receive-only remoteid-sentinel over it, and prints a report that \
        calls the flood and names the single most-likely-real drone and why.\n\n\
        Point it at a real captured Remote ID file (pcap, pcapng or RIDF) for the \
        same report, or use `decode` to just pretty-print the Remote ID in a capture, \
        DJI DroneID included.\n\n\
        This tool is analysis only. It never opens a radio or transmits. The scenario \
        generator writes test vectors, the way a fuzzer corpus or an EICAR test string \
        is data and not a weapon."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the flood/spoof field report. With no FILE, generate a scenario.
    Analyze(AnalyzeArgs),
    /// Decode and pretty-print the Remote ID in a capture (DJI DroneID too).
    Decode(DecodeArgs),
}

#[derive(Args)]
struct AnalyzeArgs {
    /// Capture file to analyze (pcap, pcapng or RIDF). Omit to generate a
    /// flood scenario instead.
    file: Option<String>,

    /// Number of fake identities in the generated flood (ignored with FILE).
    #[arg(long, default_value_t = 300)]
    count: u32,

    /// Frames per second per unit in the generated flood (ignored with FILE).
    #[arg(long, default_value_t = 2)]
    fps: u32,

    /// Window length in seconds for the generated flood (ignored with FILE).
    #[arg(long, default_value_t = 10)]
    window: u32,

    /// Also write the generated scenario to this pcap file, so you can replay
    /// the exact capture the report was built from (ignored with FILE).
    #[arg(long, value_name = "PATH")]
    save: Option<String>,
}

#[derive(Args)]
struct DecodeArgs {
    /// Capture file to decode (pcap, pcapng or RIDF).
    file: String,

    /// Print at most this many frames (0 means all).
    #[arg(long, default_value_t = 0)]
    limit: usize,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Analyze(args) => run_analyze(args),
        Command::Decode(args) => decode::run(&args.file, args.limit),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run_analyze(args: AnalyzeArgs) -> Result<(), String> {
    match args.file {
        Some(path) => {
            let frames = field::load_capture(&path)?;
            if frames.is_empty() {
                return Err(format!("no Remote ID frames decoded from {path}"));
            }
            let source = field::Source::Capture(path);
            field::report(&frames, &source);
            Ok(())
        }
        None => {
            let generated = field::generate_flood(args.count, args.fps, args.window)?;
            if let Some(path) = &args.save {
                std::fs::write(path, &generated.pcap)
                    .map_err(|e| format!("could not write {path}: {e}"))?;
            }
            let source = field::Source::Generated {
                fakes: args.count,
                save: args.save,
            };
            field::report(&generated.frames, &source);
            Ok(())
        }
    }
}
