# remoteid-demo

A runnable tour of the open-source Remote ID counter-UAS stack, in one binary.

It generates a drone-flood scenario, runs the receive-only analyzer over it, and
prints a plain report: **is the airspace flooded, how many fakes come from one
source, and which track is most likely the one real drone, and why.** Point it at
a real captured Remote ID file for the same report, or use `decode` to just
pretty-print the Remote ID in a capture, DJI DroneID included.

It stitches three crates together:

- [`remoteid`](https://crates.io/crates/remoteid) decodes Remote ID (ASTM F3411,
  DJI DroneID) and grades every transmitter.
- [`remoteid-scenario`](https://crates.io/crates/remoteid-scenario) generates
  spec-compliant test vectors (flood, spoof, clean).
- [`remoteid-sentinel`](https://crates.io/crates/remoteid-sentinel) scores a whole
  field: how flooded it is, and which track is the likely genuine drone.

## Analysis only, no radio

This tool never opens a radio and has no transmit path. The scenario generator
writes test vectors, the way a fuzzer corpus or an EICAR test string is data and
not a weapon. Nothing here broadcasts into real airspace.

## Install

```sh
cargo install remoteid-demo
```

## 1. Generate a flood and call it

With no capture file, `analyze` builds a flood (one on-air source broadcasting
hundreds of fake identities, plus one genuine moving track) and analyzes it:

```sh
remoteid-demo analyze --count 300
```

```text
Remote ID field report
======================
source:  generated flood scenario (300 fake identities, 1 genuine track)
frames:  24080 decoded over 9.5 s
field:   2 on-air sources carrying 301 distinct Remote ID identities

VERDICT: FLOODED  (confidence 1.00)
  300 fake identities broadcast from one source address [02:00:00:00:f0:00] (fan-out)
  fake signals in the field:
    - one radio address broadcast many distinct identities (fan-out)
    - serials share a templated or sequential block
    - the library graded a unit spoofed or suspicious

Most likely real drone: 1581CREAL7A4F2C91
  source:     [02:00:00:00:77:77]
  real score: 0.90 (0 fake, 1 genuine)
  per-unit library verdict: suspicious
  because:
    - consistent moving track with sane kinematics
    - single stable identity, no per-source fan-out
    - serial sits outside the templated fake block
```

Save the exact capture to replay or share it:

```sh
remoteid-demo analyze --count 300 --save flood.pcap
remoteid-demo analyze flood.pcap          # same report, now from the file
```

The saved file is a standard pcap of Bluetooth LE advertising packets, so the
generated path and the capture path reach the same verdict.

## 2. Analyze a real capture

Point `analyze` at a real captured Remote ID file. It reads the formats
`remoteid` reads: pcap, pcapng and RIDF.

```sh
remoteid-demo analyze my-capture.pcap
```

A clean field is not called a flood:

```text
VERDICT: CLEAR  (confidence 0.00)

Most likely real drone: ...
  per-unit library verdict: plausible
  because:
    - consistent moving track with sane kinematics
    - library verdict plausible: nothing contradicts the broadcast
```

## 3. Decode and pretty-print

`decode` walks a capture and prints every Remote ID message in it, standard
ASTM F3411 and DJI DroneID alike.

```sh
remoteid-demo decode my-capture.pcap --limit 4
```

Standard Remote ID:

```text
[1621633931.162s] 84:cc:a8:60:43:24 via wifi_beacon
    BasicId     id=MFG1A0123456789  id_type=None  ua_type=None
    Location    lat=45.545747 lon=-122.968150 alt=237m speed=20.5m/s track=92deg status=Undeclared
    SelfId      Recreational
    System      operator_lat=45.544388 operator_lon=-122.972687 area_count=1
    OperatorId  GBR-OP-123ABCD
```

DJI DroneID (OcuSync / Wi-Fi):

```text
[1700000000.000s] 60:60:1f:11:22:33 via wifi (DJI DroneID)
    DJI FlightInfo  serial=1WNBH3900201N1  product=Mavic Air 2
    aircraft        lat=51.446356 lon=7.267219 alt=43m height=13m yaw=-133deg
    pilot           lat=51.446230 lon=7.267104
    home            lat=51.446281 lon=7.267357
```

## What the flood report means

A coordinated flood hides one real drone behind a wall of fakes. The sentinel
reads the whole field at once and raises cross-track signals no single track
shows on its own:

- **fan-out**: one radio address broadcasting many distinct identities
- **templated serials**: a sequential or templated block of serial numbers
- **frozen or lockstep counters**: many "different" drones sharing one counter
- **shared pilot position**: dozens of drones claiming one operator location
- **tight signal/position cluster**: one physical emitter wearing many identities

It then ranks the survivors and names the track that still looks like a real
aircraft: a consistent moving track, a single stable identity, a serial outside
the templated block, and (when present) a verified DRIP signature.

## Help

```sh
remoteid-demo --help
remoteid-demo analyze --help
remoteid-demo decode --help
```

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
