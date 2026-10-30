# Sources, and thank you

LayerTime-Sensors exists because a lot of people did the hard part first.
They drove around looking for cameras, pulled apart firmware, captured
packets, and then gave all of it away. This library collects their work in
one place, checks it, and gives it back. Every signature in it names the
project it came from. If you find your work here and the credit is wrong or
missing, open an issue and it gets fixed.

The machine-readable version of this page is
[`sources/registry.json`](sources/registry.json). Every row in
[`src/lts/Signatures.h`](src/lts/Signatures.h) names one of its sources, and
`test_sources` fails the build if a row names a source that is not listed.

## The projects

| Project | Author | License | What it gave this library |
|---|---|---|---|
| [SquachWatch-CYD](https://github.com/skizzophrenic/SquachWatch-CYD) | skizzophrenic | GPL-3.0 | Flock, Axon, AirTag, Tile, SmartTag, Google tag, and Meta signatures, and the deauth burst rule. Its October 2026 cleanup of the Flock and Pineapple lists drove release 1.1.0. |
| [flock-you](https://github.com/colonelpanichacks/flock-you) | colonelpanichacks | MIT | The original Flock prefixes, the XUNTONG battery-pack finding, and the QCA9377 address found in a Flock firmware dump. |
| [nite-oui-collection](https://github.com/nitekry/nite-oui-collection) | nitekry (@NitekryDPaul) | MIT | The field-tested Flock prefix list, including which ones turned out to be wrong. |
| [Wall of Flippers](https://github.com/k3yomi/Wall-of-Flippers) | k3yomi | MIT | The Flipper Zero service UUIDs. |
| [wall-of-flipper](https://github.com/7h30th3r0n3/wall-of-flipper) | 7h30th3r0n3 | None stated | Confirmed the Flipper UUIDs, and lists Flipper address prefixes. Data only. |
| [Evil-M5Project](https://github.com/7h30th3r0n3/Evil-M5Project) | 7h30th3r0n3 | None stated | Confirmed the Flipper UUIDs. Data only. |
| [nyanBOX](https://github.com/jbohack/nyanBOX) | jbohack | Custom | The AirTag payload check that SquachWatch-CYD ported, which is where our Find My rule comes from. Data only. |
| [GainSec](https://github.com/GainSec) | Jon "GainSec" Gaines | n/a | Credited by nite-oui-collection with the original Flock prefix list. |
| [Wireshark](https://github.com/wireshark/wireshark) | The Wireshark project | GPL-2.0 | Weekly copies of the IEEE and Bluetooth SIG registries, which is how every vendor claim here gets checked. Data only. |

The registries themselves belong to the
[IEEE Registration Authority](https://standards-oui.ieee.org/oui/oui.csv) and
the [Bluetooth SIG](https://bitbucket.org/bluetooth-SIG/public/src/main/assigned_numbers/).

A few rows came from the firmware this library was split out of, and nobody
wrote down where they came from. They are marked `legacy-firmware`. Each one
is a debt: if you know the real source, say so and it gets credited.

## The license rule

Decided 2026-10-29.

- **Code and data:** MIT, BSD, Apache-2.0, CC0, and GPL-3.0 projects.
  Their code may be adapted, with credit, under their terms.
- **Data only:** everything else, including AGPL, no license, a custom
  license, or one nobody can figure out. Facts like prefixes, UUIDs, names,
  and thresholds are used with credit. Code is never copied.

## Evidence grades

Every row carries one.

- **RegistryVerified:** the IEEE or the Bluetooth SIG says the identifier
  belongs to the vendor the row detects.
- **FieldCaptured:** a named source reports seeing it on real devices, or
  pulled it out of real firmware.
- **SingleSource:** one source lists it, and that is all there is.

A row that would raise an alert (High confidence) needs one of the first
two. The few that do not yet are listed by name in `test_sources`, waiting
on a decision, so they cannot hide.

## How this stays current

Once a week, every project above is checked for new commits. The changes
that matter to detection get written up for review. Nothing changes in the
library until a human approves it, the tests pass, and a new version ships
with a [changelog](CHANGELOG.md) entry that links the upstream commit behind
each change. Corrections found here go back upstream as issues, because a
thank-you that only goes one way is just taking.
