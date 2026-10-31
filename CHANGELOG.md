# Changelog

Every change names the upstream work behind it. See [SOURCES.md](SOURCES.md)
for who those people are.

## 1.1.1

### Detection changes

- **Axon: Bluetooth names starting with `Axon-X` are now Axon, at
  Medium.** New `kBleNamePrefixes` table, matched without regard to case
  against the advertised name. On Wi-Fi the same name was already caught by
  the `AXON-` SSID prefix. From Kismet's default "bodycam" rule,
  [`f62be84`](https://github.com/kismetwireless/kismet/commit/f62be8498b4b668c8975c319b17dd73d04f92963).
  Medium, not High, because no capture is published. Upstream review R15b.
- **Axon: `12:20:13` added at Low.** From the same Kismet rule. The prefix
  is locally administered, so no vendor owns it and anyone can use it:
  logged, never an alert. Upstream review R15c.
- Kismet's rule also matches `00:25:DF`, Axon Enterprise's registered
  prefix, which this library already has at High. That gives it a second,
  independent source.

### Provenance

- Kismet added to `sources/registry.json` and `SOURCES.md` as a data-only
  source (GPL-2.0). Upstream review R15a.
- `test_sources` checks the new name table the same way as every other
  table.

## 1.1.0

### Detection changes

- **Flock: only Flock Safety's own prefix is High.** `B4:1E:52` is the one
  prefix the IEEE registry assigns to Flock Safety. The other 19 Flock
  prefixes that were High belong to module makers (9 Liteon, 8 Silicon
  Labs, 1 Spectra-Tek, 1 unassigned) and are now Low: logged, never an
  alert. Follows SquachWatch-CYD
  [`ca22d80`](https://github.com/skizzophrenic/SquachWatch-CYD/commit/ca22d80895505df0c61c650020ab32dedc2f5429)
  and [`10f4da6`](https://github.com/skizzophrenic/SquachWatch-CYD/commit/10f4da64d512513978fe13f34175f651efbc7225).
  Five of the Silicon Labs prefixes were dropped by
  [flock-you](https://github.com/colonelpanichacks/flock-you/commit/6704f011f3e6c9cfe94fe18c593f863032c9c954);
  they stay here at Low so nothing leaves the record. Upstream review R1.
- **Flock: 16 field-list prefixes added at Low.** 13 Liteon and 2 UGSI
  prefixes from
  [nite-oui-collection](https://github.com/nitekry/nite-oui-collection/blob/29501d51cbfb1657396ccd7a2bf1445c93e2ceb1/groups/flockers/my_tested_flock.md),
  and Atheros `00:03:7F`, the QCA9377 default address flock-you found in a
  Flock firmware dump
  ([`6704f01`](https://github.com/colonelpanichacks/flock-you/commit/6704f011f3e6c9cfe94fe18c593f863032c9c954)).
  Upstream review R1.
- **Flock: the 16 Espressif prefixes stay at Low.** SquachWatch-CYD removed
  them in `10f4da6`; they are kept here, log-only. Upstream review R2.

Expect fewer Flock alerts. That is the point: the alerts that went away were
laptops and gadgets with the same Wi-Fi module.

### Provenance

- Every signature row now records its source, the source commit, the
  version that added it, and an evidence grade (`src/lts/Provenance.h`).
- Every vendor identifier records who the IEEE or Bluetooth SIG says owns
  it.
- New `sources/registry.json`: every project used, checked, or credited,
  with the commits last seen, reviewed, and integrated.
- New `sources/snapshots/`: pinned registry owners for every identifier in
  use, built by `tools/refresh_registry_snapshots.py` from Wireshark
  [`98a6cfd`](https://github.com/wireshark/wireshark/commit/98a6cfdba1ab23f3c835b17df802004bc9429040).
- New `test_sources`: fails the build when a row names an unknown source or
  commit, records an owner the registry contradicts, claims RegistryVerified
  for the wrong vendor, or is High on a single source without being listed
  for review.
- New `SOURCES.md`: the thank-you page.
- New `API.md`: the full API, with NimBLE and ESP-IDF adapter examples. Its
  quick start is checked by the new `test_api_examples`, which also proves
  the address byte-order rule.
- The Pineapple prefix list moved from a switch statement into a table so
  each row can carry provenance. Matching is unchanged, and a test locks it
  to the 1.0.0 list.

### Found while doing this, not changed

These wait on a decision (upstream review R5 and R14):

- Axon `E4:05:40` is unassigned in the IEEE registry and `28:24:FF`
  belongs to WNC, a module maker. Both are High (R5).
- The Axon SSID prefixes `AB2-`, `AB3-`, `AB4-`, and `AXON-` are High.
  SquachWatch-CYD says that data was compiled with AI assistance and
  "expanded against public sources", with no captures published.
- `D4:AD:FC`, labelled "Flock? (ESP32)", belongs to Shenzhen Intellirocks,
  not Espressif.
- The Meta UUIDs `0xFEB7` and `0xFEB8` were marked unsourced. The Bluetooth
  SIG assigns both to Meta Platforms. They stay Low until someone shows what
  they mean on a device.
- The Flipper UUID reading (`0x3081` to `0x3083` as service UUIDs) was
  marked unverified. Wall of Flippers, wall-of-flipper, and Evil-M5Project
  all match them the same way, so it is now graded FieldCaptured.

## 1.0.0

First release, extracted from the LayerTime watch firmware.
