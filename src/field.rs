//! Loading captures, generating the flood scenario, and rendering the report.

use std::collections::BTreeMap;

use remoteid::capture::{self, CapturedFrame};
use remoteid::{Frame, Message, Transmitter};
use remoteid_scenario::{generate, Scenario, ScenarioKind, ScenarioWriter};
use remoteid_sentinel::{FieldAssessment, FloodLevel, Signature, TrackScore};

/// Where the analyzed frames came from, for the report header.
pub enum Source {
    /// A capture file at this path.
    Capture(String),
    /// A scenario generated in this process.
    Generated {
        /// Number of fake identities asked for.
        fakes: u32,
        /// pcap file the scenario was also saved to, if any.
        save: Option<String>,
    },
}

/// A generated scenario: the decoded frames plus the pcap bytes they came
/// from, so the same capture can be saved and replayed.
pub struct Generated {
    /// The frames, decoded back out of `pcap` so they match a real capture.
    pub frames: Vec<CapturedFrame>,
    /// The pcap-encoded capture (BLE advertising packets).
    pub pcap: Vec<u8>,
}

/// Reads a capture file (pcap, pcapng or RIDF) into decoded Remote ID frames.
pub fn load_capture(path: &str) -> Result<Vec<CapturedFrame>, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("could not read {path}: {e}"))?;
    capture::frames(&bytes).map_err(|e| format!("could not parse {path}: {e:?}"))
}

/// Builds a flood scenario (one on-air source, `fakes` fake identities, one
/// genuine moving track), serializes it to a pcap of Bluetooth LE advertising
/// packets, and decodes it back.
///
/// Running the generated stream through the real pcap encoder and decoder
/// means the report is built from exactly what a receiver would decode off a
/// capture file, not from in-memory shortcuts. The scenario models Bluetooth
/// broadcasts, so the pcap carries BLE advertising packets and no Wi-Fi
/// framing, which is why `analyze` on the saved file reproduces this report.
pub fn generate_flood(fakes: u32, fps: u32, window: u32) -> Result<Generated, String> {
    if fakes == 0 {
        return Err("need at least one fake identity (--count)".to_string());
    }
    let mut scenario = Scenario::new(ScenarioKind::Flood, fakes);
    scenario.timing.frames_per_s = fps.max(1);
    scenario.timing.window_s = window.max(1);

    let emitted = generate(&scenario);
    let writer = ScenarioWriter::new(emitted);
    let mut pcap = Vec::new();
    writer
        .to_pcap(&mut pcap)
        .map_err(|e| format!("could not encode scenario: {e}"))?;
    let frames = capture::frames(&pcap).map_err(|e| format!("could not decode scenario: {e:?}"))?;
    Ok(Generated { frames, pcap })
}

/// Per-source rollup computed straight from the decoded frames.
struct SourceStat {
    ids: std::collections::BTreeSet<String>,
    frames: u64,
}

/// Formats a transmitter address for the report.
fn fmt_transmitter(tx: &Transmitter) -> String {
    match tx {
        Transmitter::Ble(a) | Transmitter::Wifi(a) => a
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":"),
        Transmitter::Other(n) => format!("other:{n}"),
    }
}

/// A one-line human description of a flood/spoof signature.
fn signature_detail(s: Signature) -> &'static str {
    match s {
        Signature::OneSourceManyIds => {
            "one radio address broadcast many distinct identities (fan-out)"
        }
        Signature::TightRssiPositionCluster => {
            "many tracks sit in one tight signal and position cluster"
        }
        Signature::TemplatedSerial => "serials share a templated or sequential block",
        Signature::FrozenOrIdenticalCounter => {
            "many tracks share one frozen or lockstep message counter"
        }
        Signature::ImpossibleKinematics => "a track moved in a physically impossible way",
        Signature::SharedOperatorPosition => "many tracks claim one identical pilot position",
        Signature::PerUnitSpoofedOrSuspicious => "the library graded a unit spoofed or suspicious",
        Signature::KnownSpooferFingerprint => "a track matches a known spoofing-tool fingerprint",
        Signature::CountSpike => "a burst of new transmitters appeared at once (flood onset)",
    }
}

/// Builds the per-source rollup and the span of the capture in seconds.
fn roll_up(frames: &[CapturedFrame]) -> (BTreeMap<Transmitter, SourceStat>, f64) {
    let mut sources: BTreeMap<Transmitter, SourceStat> = BTreeMap::new();
    let (mut min_us, mut max_us) = (u64::MAX, 0u64);
    for f in frames {
        min_us = min_us.min(f.time_us);
        max_us = max_us.max(f.time_us);
        let entry = sources.entry(f.transmitter).or_insert_with(|| SourceStat {
            ids: Default::default(),
            frames: 0,
        });
        entry.frames += 1;
        if let Ok(frame) = Frame::decode(&f.payload) {
            frame.for_each_message(|m| {
                if let Message::BasicId(b) = m {
                    if let Some(id) = b.uas_id_str().filter(|s| !s.is_empty()) {
                        entry.ids.insert(id.to_string());
                    }
                }
            });
        }
    }
    let span_s = if max_us >= min_us && min_us != u64::MAX {
        (max_us - min_us) as f64 / 1_000_000.0
    } else {
        0.0
    };
    (sources, span_s)
}

/// Runs the sentinel over the frames and prints the field report.
pub fn report(frames: &[CapturedFrame], source: &Source) {
    let (sources, span_s) = roll_up(frames);
    let total_ids: usize = sources.values().map(|s| s.ids.len()).sum();

    // The sentinel drives remoteid's own tracker and trust state over the
    // already-decoded stream. Nothing here touches a radio.
    let now_ms = frames.iter().map(|f| f.time_us / 1000).max().unwrap_or(0) + 1;
    // Use the capture clock as a monotonic clock only, not as a UTC reference:
    // a sensor trusts its own wall clock for Remote ID time-of-week checks only
    // when it is disciplined, and a demo capture clock is not. The per-unit
    // trust grading matches the sentinel's own end-to-end tests this way.
    let obs = frames.iter().map(|f| (f.transmitter, f.observation(false)));
    let field = FieldAssessment::from_observations(obs, now_ms);

    println!("Remote ID field report");
    println!("======================");
    match source {
        Source::Capture(path) => println!("source:  capture {path}"),
        Source::Generated { fakes, save } => {
            println!(
                "source:  generated flood scenario ({fakes} fake identities, 1 genuine track)"
            );
            if let Some(p) = save {
                println!("saved:   {p} (pcap, replay with `remoteid-demo analyze {p}`)");
            }
        }
    }
    println!("frames:  {} decoded over {:.1} s", frames.len(), span_s);
    println!(
        "field:   {} on-air source{} carrying {} distinct Remote ID identit{}",
        sources.len(),
        if sources.len() == 1 { "" } else { "s" },
        total_ids,
        if total_ids == 1 { "y" } else { "ies" }
    );
    println!();

    // --- verdict ---
    let level = field.flood.level;
    let banner = match level {
        FloodLevel::Flooded => "FLOODED",
        FloodLevel::Elevated => "ELEVATED",
        FloodLevel::Clear => "CLEAR",
    };
    println!(
        "VERDICT: {banner}  (confidence {:.2})",
        field.flood.confidence
    );

    // The clearest flood tell: one address wearing many identities.
    if let Some((tx, stat)) = sources.iter().max_by_key(|(_, s)| s.ids.len()) {
        if stat.ids.len() > 1 {
            println!(
                "  {} fake identit{} broadcast from one source address [{}] (fan-out)",
                stat.ids.len(),
                if stat.ids.len() == 1 { "y" } else { "ies" },
                fmt_transmitter(tx)
            );
        }
    }

    // Every signature the field raised, once, with a plain description.
    let mut seen = Vec::new();
    for t in &field.tracks {
        for s in t.fake_signals.iter() {
            if !seen.contains(&s) {
                seen.push(s);
            }
        }
    }
    if !seen.is_empty() {
        println!("  fake signals in the field:");
        for s in &seen {
            println!("    - {}", signature_detail(*s));
        }
    }
    println!();

    // --- the one most likely real drone ---
    match &field.most_likely_real {
        Some(real) => print_real(real),
        None => {
            if level == FloodLevel::Clear {
                println!("Most likely real drone: no flood, grade each track on its own.");
            } else {
                println!(
                    "Most likely real drone: none survived. Every track carries a \
                     disqualifying flood or spoof tell."
                );
            }
        }
    }
}

/// Prints the chosen genuine track and the reasons it was chosen.
fn print_real(real: &TrackScore) {
    let id = real.uas_id.as_deref().unwrap_or("(no serial broadcast)");
    println!("Most likely real drone: {id}");
    println!("  source:     [{}]", fmt_transmitter(&real.transmitter));
    println!("  real score: {:.2} (0 fake, 1 genuine)", real.real_score);
    println!(
        "  per-unit library verdict: {}",
        real.per_unit.verdict.name()
    );
    if real.genuine_reasons.is_empty() {
        println!("  because:    chosen as the least-contradicted track in the field");
    } else {
        println!("  because:");
        for r in &real.genuine_reasons {
            println!("    - {r}");
        }
    }
}
