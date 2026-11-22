# Changelog

## 0.1.0

First release. A runnable demo of the Remote ID counter-UAS stack.

- `analyze` with no file generates a flood scenario (one on-air source, hundreds
  of fake identities, one genuine moving track) with `remoteid-scenario`, runs
  `remoteid-sentinel` over it, and prints a field report: the flood verdict, the
  fan-out from one source, the cross-track fake signals, and the single
  most-likely-real drone with reasons.
- `analyze <FILE>` runs the same report over a real capture (pcap, pcapng, RIDF).
- `--save` writes the generated scenario to a pcap of Bluetooth LE advertising
  packets, so the generated path and the capture path reach the same verdict.
- `decode <FILE>` pretty-prints the Remote ID in a capture, standard ASTM F3411
  and DJI DroneID alike.

Analysis only: no radio, no transmit path.
