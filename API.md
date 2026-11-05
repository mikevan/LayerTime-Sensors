# LayerTime-Sensors API

LayerTime-Sensors turns radio traffic into named threats. Your radio catches a
Bluetooth advertisement or a Wi-Fi frame. You hand it to the library. The
library tells you whether it came from a Flock camera, an AirTag, a Flipper
Zero, an Axon body camera, a deauth attack, or one of the other detectors
below, and how sure it is.

That is the whole deal. The library never touches a radio, never allocates on
the Wi-Fi path, never stores anything, and never raises an alert. Those jobs
stay with you, because you know your hardware and your users. In exchange,
every detector in this library works on any device that can hand over the
bytes: an ESP32, a Raspberry Pi, a phone, a laptop, or a test bench.

Plain C++17. No Arduino, no ESP-IDF, no platform headers. If your compiler
handles C++17, it builds.

## Contents

1. [Quick start](#quick-start)
2. [Adding the library to a build](#adding-the-library-to-a-build)
3. [Detectors and their numbers](#detectors-and-their-numbers)
4. [Confidence: what to alert on](#confidence-what-to-alert-on)
5. [Choosing detectors: DetectorSet](#choosing-detectors-detectorset)
6. [Results: Candidate and the sink](#results-candidate-and-the-sink)
7. [Bluetooth: classifyBleAdvert](#bluetooth-classifybleadvert)
8. [Wi-Fi: WifiFrameClassifier](#wi-fi-wififrameclassifier)
9. [Threads and memory](#threads-and-memory)
10. [Signature tables and provenance](#signature-tables-and-provenance)
11. [What stays stable](#what-stays-stable)
12. [Adding a signature](#adding-a-signature)

## Quick start

This program classifies one AirTag advertisement and one Wi-Fi beacon from an
Axon body camera. It is checked by `test/test_api_examples`, so if it ever
stops printing this, the build fails.

```cpp
#include <cstdio>
#include <cstring>
#include <string>
#include <lts/BleAdvertClassifier.h>
#include <lts/WifiFrameClassifier.h>

static const char *name(lts::Confidence c) {
    return c == lts::Confidence::High ? "High" : c == lts::Confidence::Medium ? "Medium" : "Low";
}

// Called once per match. The text is only valid during this call; copy what you keep.
static void onCandidate(const lts::Candidate &c, void *) {
    std::printf("detector %u  %-6s  %s  %s  rssi %d  ch %u\n", unsigned(c.detector),
                name(c.confidence), c.address, c.detail, c.rssi, c.channel);
}

// Your BLE stack's advertisement, reduced to what the callbacks need.
struct Advert { std::string mfg; };
static void mfgAt(uint8_t, std::string &out, const void *ctx) { out = static_cast<const Advert *>(ctx)->mfg; }
static bool noUuid(uint8_t, uint16_t &, const void *) { return false; }

int main() {
    // Bluetooth: Apple's company ID (0x004C, little-endian), Find My subtype 0x12,
    // length 0x19 (away from its owner), and status 0x10 (device type 1, an AirTag).
    Advert tag{std::string("\x4C\x00\x12\x19\x10", 5)};
    const uint8_t addr[6] = {0xC4, 0x11, 0x22, 0x33, 0x44, 0x55};
    lts::BleAdvertSource a;
    a.printedAddress = "c4:11:22:33:44:55"; a.addressBytes = addr; a.rssi = -61;
    a.manufacturerCount = 1; a.manufacturer = mfgAt; a.uuidCount = 0; a.uuid16 = noUuid; a.context = &tag;
    lts::classifyBleAdvert(a, lts::DetectorSet::all(), onCandidate, nullptr);

    // Wi-Fi: a beacon from Axon's registered prefix, advertising an Axon pairing SSID.
    uint8_t f[64] = {0};
    f[0] = 0x80;                                     // management frame, beacon
    const uint8_t bssid[6] = {0x00, 0x25, 0xDF, 0x01, 0x02, 0x03};
    std::memset(f + 4, 0xFF, 6); std::memcpy(f + 10, bssid, 6); std::memcpy(f + 16, bssid, 6);
    f[36] = 0x00; f[37] = 8; std::memcpy(f + 38, "AB3-1234", 8);   // SSID element
    lts::WifiFrameClassifier wifi;
    wifi.classify(f, 46, -70, 6, 1000, lts::DetectorSet::all(), onCandidate, nullptr);
}
```

Build and run it from the library folder:

```
g++ -std=c++17 -Isrc quickstart.cpp src/lts/*.cpp -o quickstart && ./quickstart
```

Output:

```
detector 10  High    c4:11:22:33:44:55  AirTag away from its owner  rssi -61  ch 0
detector 13  High    00:25:DF:01:02:03  Axon (Taser)  rssi -70  ch 6
detector 13  High    00:25:DF:01:02:03  SSID AB3-1234  rssi -70  ch 6
```

## Adding the library to a build

- **pioarduino or PlatformIO:** add the repository to `lib_deps`, by git URL
  pinned to a commit, or with `symlink://` to a checked-out copy.
  `library.json` sets the source and include folders.
- **Anything else (CMake, Make, Arduino IDE, a desktop app):** put `src/` on
  the include path and compile every file in `src/lts/*.cpp`. There is
  nothing to configure.

Include what you use:

| Header | What it holds |
|---|---|
| `lts/Detectors.h` | `DetectorId`, `Confidence`, `DetectorSet`, `kAllDetectors`, `isKnownDetector()` |
| `lts/Candidate.h` | `Candidate`, `CandidateSink` |
| `lts/BleAdvertClassifier.h` | `BleAdvertSource`, `classifyBleAdvert()` |
| `lts/WifiFrameClassifier.h` | `WifiFrameClassifier` |
| `lts/Signatures.h` | The signature tables and small helpers (`formatMac()`, `lookupOui()`) |
| `lts/Provenance.h` | `Provenance`, `Evidence` |

Everything is in `namespace lts`.

## Detectors and their numbers

| Number | `DetectorId` | Radio | What it matches |
|---|---|---|---|
| 5 | `Deauth` | Wi-Fi | A burst of deauth or disassoc frames from one transmitter |
| 6 | `Pwnagotchi` | Wi-Fi | The published Pwnagotchi beacon address |
| 7 | `MultiSSID` | Wi-Fi | Two or more confirmed network names from one access point |
| 8 | `Flock` | BLE and Wi-Fi | Flock Safety's registered prefix, module prefixes seen on Flock units, and Flock's battery-pack radio |
| 9 | `Pineapple` | Wi-Fi | Hak5 Pineapple prefixes |
| 10 | `AirTag` | BLE | Apple Find My beacons, graded by device type: High only for an AirTag away from its owner, Medium for another Find My tag away from its owner, Low for everything else (iPhones, Macs, AirPods, tags near their owner) |
| 11 | `Flipper` | BLE | Flipper Zero service UUIDs |
| 12 | `Meta` | BLE | Meta Ray-Ban and Meta service UUIDs |
| 13 | `Axon` | BLE and Wi-Fi | Axon prefixes, body-camera pairing SSIDs, and body-camera Bluetooth names |
| 14 | `Tile` | BLE | Tile service UUIDs |
| 15 | `SamsungTag` | BLE | Samsung SmartTag service UUID |
| 16 | `GoogleTag` | BLE | Google Find My Device (Eddystone) UUID |
| 17 | `Eapol` | Wi-Fi | WPA/RSN 4-way handshake (EAPOL-Key) frames, M1 to M4; Medium, provisional |

The numbers are permanent. Store them, send them over a radio link, put them
in a database. A number is never reused or changed, and a retired detector
leaves a gap. They start at 5 and are not contiguous, so never loop over a
range. Loop over `kAllDetectors`, and check numbers you read from storage or a
link with `isKnownDetector()`.

## Confidence: what to alert on

Every match carries a `Confidence`. The library decides the grade per
signature row, not per detector, so one detector can report all three.

| Value | Number | Meaning | What to do with it |
|---|---|---|---|
| `Low` | 0 | Worth logging, not worth an alert. For example, a Wi-Fi module prefix that Flock uses and so does your laptop. | Log it and list it. Do not buzz, beep, or notify. |
| `Medium` | 1 | A real pattern that ordinary devices sometimes share. For example, a deauth burst, or Google's Eddystone UUID. | Alert, with wording that says "possible". |
| `High` | 2 | A specific signature, such as a registered vendor prefix or a vendor-exclusive UUID. | Alert. |

If you show only one thing, show High and Medium, and keep Low in the log.
Alerting on Low is how you train people to ignore your alerts. LayerTime's own
watch learned that the hard way.

## Choosing detectors: DetectorSet

A `DetectorSet` says which detectors run. A detector outside the set is not
evaluated and keeps no state, so turning detectors off also saves time and
memory.

```cpp
lts::DetectorSet enabled;                     // empty: nothing runs
enabled.add(lts::DetectorId::AirTag);
enabled.add(lts::DetectorId::Flock);
enabled.remove(lts::DetectorId::Flock);
bool on = enabled.contains(lts::DetectorId::AirTag);

auto everything = lts::DetectorSet::all();
auto nothing = lts::DetectorSet::none();
```

Adding a number that is not a known detector does nothing, so a corrupt
setting or a bad radio message cannot switch on something that does not exist.
It is `constexpr`, so a fixed set can be built at compile time.

## Results: Candidate and the sink

Every match is delivered as a `Candidate` to a function you supply:

```cpp
using CandidateSink = void (*)(const lts::Candidate &candidate, void *context);
```

| Field | Type | Meaning |
|---|---|---|
| `detector` | `DetectorId` | Which detector matched |
| `confidence` | `Confidence` | How sure the matching row is |
| `address` | `const char *` | Bluetooth: your `printedAddress`. Wi-Fi: the transmitter address as `AA:BB:CC:DD:EE:FF`. |
| `detail` | `const char *` | A short description, for example `"Find My tracker beacon"`, `"SSID AB3-1234"`, or the device's own name when it has one |
| `rssi` | `int8_t` | The signal strength you passed in |
| `channel` | `uint8_t` | The Wi-Fi channel you passed in; 0 for Bluetooth |

Rules:

- **`address` and `detail` are only valid during the call.** Copy anything you
  keep.
- **`context`** is whatever pointer you passed to the classifier. Use it to
  reach your queue, log, or object.
- **One frame can produce several candidates,** delivered in order. A Wi-Fi
  beacon from an Axon prefix with an Axon SSID produces two.
- **`detail` can contain text from the air.** Device names and network names
  are attacker-controlled. The multiple-SSID detector cleans the names it
  reports to printable ASCII, but other details, including Bluetooth names and
  the Axon SSID, are passed through as received. Escape `detail` before you put
  it in HTML, a CSV, a log line, or a terminal.
- The time and the radio that caught the frame are yours. They are not part of
  a candidate.

## Bluetooth: classifyBleAdvert

```cpp
void classifyBleAdvert(const lts::BleAdvertSource &advert, const lts::DetectorSet &enabled,
                       lts::CandidateSink sink, void *sinkContext);
```

You fill a `BleAdvertSource` from your stack's advertisement. Manufacturer
records and UUIDs are fetched through two callbacks, so you never copy them
all up front.

| Field | Meaning |
|---|---|
| `name`, `nameLength` | The device name; length 0 when there is none |
| `printedAddress` | The address as text. Returned unchanged as `Candidate::address`. |
| `addressBytes` | Six address bytes, **vendor prefix first** (see below) |
| `rssi` | Signal strength |
| `manufacturerCount` | How many manufacturer-specific data records the advertisement has |
| `manufacturer(index, out, context)` | Copies record `index`, company ID first (little-endian, as on the air), into `out` |
| `uuidCount` | How many service UUIDs it has |
| `uuid16(index, out, context)` | Writes UUID `index` as a 16-bit value and returns true; returns false when it is not a 16-bit UUID |
| `context` | Passed to both callbacks unchanged |

Matches are reported in this order: manufacturer records (Find My, Flock's
battery-pack radio), then the address prefix, then service UUIDs, then the
device name.

**Address byte order.** The library reads the vendor prefix from
`addressBytes[0]` to `addressBytes[2]`, the same order the address is printed
in. Some stacks store addresses the other way round. NimBLE's
`NimBLEAddress::getVal()` is least-significant byte first, so reverse it.
Hand it over unreversed and the Flock and Axon address checks will never
match. `test_api_examples` proves both cases.

### Example: NimBLE-Arduino 2.x

This is the same pattern the LayerWand runs on an ESP32-C5, with the address
reversed. It needs NimBLE, so the host tests do not compile it.

```cpp
#include <NimBLEDevice.h>
#include <lts/BleAdvertClassifier.h>
#include <lts/Signatures.h>

static void mfgThunk(uint8_t i, std::string &out, const void *ctx) {
    out = static_cast<const NimBLEAdvertisedDevice *>(ctx)->getManufacturerData(i);
}

static bool uuid16Thunk(uint8_t i, uint16_t &out, const void *ctx) {
    const NimBLEUUID uuid = static_cast<const NimBLEAdvertisedDevice *>(ctx)->getServiceUUID(i);
    if (uuid.bitSize() != 16) return false;
    for (const lts::BleUuidSignature &sig : lts::kBleUuidSignatures)
        if (uuid.equals(NimBLEUUID(sig.uuid))) { out = sig.uuid; return true; }
    return false;   // a 16-bit UUID no detector uses
}

void classify(const NimBLEAdvertisedDevice *d, const lts::DetectorSet &enabled,
              lts::CandidateSink sink, void *sinkContext) {
    const std::string name = d->haveName() ? d->getName() : std::string();
    const std::string printed = d->getAddress().toString();
    const uint8_t *le = d->getAddress().getVal();
    uint8_t addr[6];
    for (int i = 0; i < 6; ++i) addr[i] = le[5 - i];   // prefix first

    lts::BleAdvertSource a;
    a.name = name.data();
    a.nameLength = name.size();
    a.printedAddress = printed.c_str();
    a.addressBytes = addr;
    a.rssi = d->getRSSI();
    a.manufacturerCount = d->haveManufacturerData() ? d->getManufacturerDataCount() : 0;
    a.manufacturer = mfgThunk;
    a.uuidCount = d->haveServiceUUID() ? d->getServiceUUIDCount() : 0;
    a.uuid16 = uuid16Thunk;
    a.context = d;
    lts::classifyBleAdvert(a, enabled, sink, sinkContext);
}
```

Call `classify()` from your `NimBLEScanCallbacks::onResult()`.

## Wi-Fi: WifiFrameClassifier

```cpp
class WifiFrameClassifier {
public:
    void classify(const uint8_t *frame, uint16_t length, int8_t rssi, uint8_t channel,
                  uint32_t nowMs, const DetectorSet &enabled, CandidateSink sink,
                  void *sinkContext);
    void reset();
};
```

- **`frame`** is the raw 802.11 frame, starting at the frame control field,
  as a monitor-mode or promiscuous capture delivers it. A trailing checksum
  (FCS) is fine. Radiotap or other capture headers are not: strip them first.
- **`nowMs`** is any millisecond clock that only moves forward, for example
  `millis()`. It drives the deauth burst window and the multi-SSID timeouts.
  Wrapping after 49 days is handled by unsigned arithmetic.
- **Frames it reads:** beacons (vendor prefix, Pineapple, Pwnagotchi, Axon
  SSIDs, multiple SSIDs) and deauth and disassoc frames (bursts). Every other
  frame returns at once, so it is safe to feed it everything.
- **It keeps state.** Burst counts and SSID tracking live inside the object.
  Use one classifier per radio, and keep it alive between frames. `reset()`
  forgets everything, for example when a scan restarts.

Tuning constants, all public and `static constexpr`:

| Constant | Value | Meaning |
|---|---|---|
| `kDeauthBurstFrames` | 6 | Deauth or disassoc frames from one transmitter that make a burst |
| `kDeauthWindowMs` | 3000 | Inside this window |
| `kDeauthCooldownMs` | 15000 | Quiet time before the same transmitter can fire again |
| `kMultiSsidMinBeacons` | 3 | Beacons before a network name counts |
| `kMultiSsidStaleMs` | 60000 | A name not heard for this long is dropped |
| `kMultiSsidTrackers` | 16 | Access points tracked at once |

### Example: ESP-IDF promiscuous mode

The same pattern the LayerWand runs. It needs ESP-IDF, so the host tests do not
compile it.

```cpp
#include <esp_wifi.h>
#include <esp_timer.h>
#include <lts/WifiFrameClassifier.h>

static lts::WifiFrameClassifier gWifi;
static lts::DetectorSet gEnabled = lts::DetectorSet::all();

static void onCandidate(const lts::Candidate &c, void *) {
    // Runs on the Wi-Fi driver's task. Copy the fields into a queue and return.
}

static void onFrame(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT) return;
    auto *p = static_cast<wifi_promiscuous_pkt_t *>(buf);
    gWifi.classify(p->payload, p->rx_ctrl.sig_len, p->rx_ctrl.rssi, p->rx_ctrl.channel,
                   static_cast<uint32_t>(esp_timer_get_time() / 1000), gEnabled,
                   onCandidate, nullptr);
}

void startMonitoring(uint8_t channel) {
    wifi_promiscuous_filter_t filter = {.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT};
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(onFrame);
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    esp_wifi_set_promiscuous(true);
}
```

Hopping channels is your job. The classifier does not care which channel a
frame came from, except to report it.

## Threads and memory

- **Not thread-safe, on purpose.** Call each `WifiFrameClassifier` from one
  task only. If another task needs to clear it, set a flag and let the
  classifying task call `reset()` before its next frame. Calling `reset()`
  from another task races `classify()`. The LayerWand hit exactly that.
- **The sink runs on the classifying task,** inside the radio callback on most
  stacks. Copy the candidate into a queue and return. Do not log to flash,
  draw a screen, or block there.
- **No heap on the Wi-Fi path.** A `WifiFrameClassifier` is a fixed-size object
  (about 3 KB), so it can be a global or a member.
- **The Bluetooth path uses `std::string`** for the device name and each
  manufacturer record.
- The library throws no exceptions of its own, and keeps no global state apart
  from the read-only signature tables.

## Signature tables and provenance

The tables in `lts/Signatures.h` are public, read-only, and `constexpr`.
Display them, export them, or check your own data against them.

| Table | Row type | What it holds |
|---|---|---|
| `kOuiSignatures` | `OuiSignature` | Address prefixes for Flock and Axon |
| `kPineappleOuis` | `PineappleOuiSignature` | Pineapple prefixes |
| `kBleUuidSignatures` | `BleUuidSignature` | 16-bit service UUIDs |
| `kCompanyIdSignatures` | `CompanyIdSignature` | Bluetooth company IDs |
| `kSsidPrefixes` | `SsidPrefixSignature` | Network name prefixes |
| `kBleNamePrefixes` | `BleNamePrefixSignature` | Bluetooth device-name prefixes |

Every row carries a `Provenance`:

| Field | Meaning |
|---|---|
| `source` | The project it came from, an id in `sources/registry.json` |
| `commit` | The commit it was taken from |
| `since` | The library version that added it |
| `evidence` | `RegistryVerified`, `FieldCaptured`, or `SingleSource` |

Vendor rows also carry `registeredTo`, the owner the IEEE or Bluetooth SIG
registry gives. So you can show a user not just "Flock", but "Flock, Liteon
module, field-captured by nite-oui-collection". [SOURCES.md](SOURCES.md)
explains the grades and credits every source.

## What stays stable

| Promise | Kept by |
|---|---|
| Detector numbers never change and are never reused | `test_detectors` |
| `Confidence` values 0, 1, and 2 never change meaning | `test_detectors` |
| The function signatures above change only in a major version | The version number |
| Signature rows and their confidence grades can change in any minor version | The [changelog](CHANGELOG.md), which links the upstream commit behind each change |

In short: your code keeps compiling and your stored numbers keep their meaning.
What gets detected keeps getting better, and every change says why.

## Adding a signature

1. Add the row to the right table in `src/lts/Signatures.h`, with its
   `Provenance` and, for a vendor identifier, its `registeredTo`.
2. Add the source to `sources/registry.json` if it is new.
3. Run `tools/refresh_registry_snapshots.py` to record the registry owner.
4. Run `tools/run_tests.sh`. `test_sources` fails if the source or commit is
   unknown, the owner disagrees with the registry, or a High row rests on a
   single source.
5. Open a pull request, and say where the evidence came from.
