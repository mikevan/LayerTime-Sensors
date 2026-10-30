// LayerTime-Sensors - passive wireless threat detectors for small radios.
//
// Copyright (C) 2026 Michael Van Geertruy
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.


#pragma once

// Signature tables and the pure matchers that read them. Everything here
// works on plain values and bytes; capturing frames and advertisements is
// the caller's job.
//
// Every row records who it came from and how strong the evidence is (see
// Provenance.h), and every vendor identifier records who the official
// registry says owns it. Those owners are checked against pinned registry
// snapshots by test_sources, so a row cannot quietly claim a vendor the
// registry contradicts. Short commit ids below are expanded in
// sources/registry.json.

#include <stddef.h>
#include <stdint.h>
#include <string>

#include "Detectors.h"
#include "Provenance.h"

namespace lts {

// ---- BLE signature tables ----------------------------------------------
// Matching is done against PARSED advertisement fields - the manufacturer
// record's company ID, and the 16-bit service UUIDs - never by searching
// the raw payload for byte pairs. A two-byte pattern scanned across a
// 31-byte advertisement matches by coincidence often enough to make a
// wrist alert useless, which is what the previous implementation did.

inline constexpr uint16_t kAppleCompanyId = 0x004C;
inline constexpr uint16_t kXuntongCompanyId = 0x09C8;  // Flock's BLE radio supplier

struct CompanyIdSignature {
    uint16_t id;
    DetectorId detector;
    const char *registeredTo;  // Bluetooth SIG company identifier owner
    Provenance provenance;
};

inline constexpr CompanyIdSignature kCompanyIdSignatures[] = {
    {kAppleCompanyId, DetectorId::AirTag, "Apple, Inc.",
     {"squachwatch-cyd", "b3e96f7", "1.0.0", Evidence::RegistryVerified}},
    // XUNTONG is a module maker, not Flock. flock-you documents it as the
    // BLE chipset in Flock's "Penguin" battery packs, which is why the
    // classifier gates it on a Flock-shaped name.
    {kXuntongCompanyId, DetectorId::Flock, "XUNTONG",
     {"flock-you", "6704f01", "1.0.0", Evidence::FieldCaptured}},
};

// Apple Find My offline-finding subtypes: 0x12 near owner, 0x1E separated.
// The subtype check follows SquachWatch-CYD, which ported it from nyanBOX.
// SquachWatch-CYD additionally matches 0x07 ("proximity pairing"), which
// catches a tag earlier but also fires on AirPods and other Apple
// accessories. Off here on purpose: this drives a buzz on the wrist, and a
// detector that trips on the owner's own earbuds gets ignored. Flip to
// true to trade precision for earlier warning.
inline constexpr bool kMatchProximityPairing = false;

struct BleUuidSignature {
    uint16_t uuid;
    DetectorId detector;
    const char *label;
    Confidence confidence;
    const char *registeredTo;  // Bluetooth SIG 16-bit UUID owner
    Provenance provenance;
};

inline constexpr BleUuidSignature kBleUuidSignatures[] = {
    // Bluetooth SIG assigned, exclusive to one product line.
    {0xFD5F, DetectorId::Meta, "Meta Ray-Ban glasses", Confidence::High,
     "Meta Platforms Technologies, LLC",
     {"squachwatch-cyd", "b3e96f7", "1.0.0", Evidence::RegistryVerified}},
    {0xFEED, DetectorId::Tile, "Tile tracker", Confidence::High, "Tile, Inc.",
     {"squachwatch-cyd", "b3e96f7", "1.0.0", Evidence::RegistryVerified}},
    {0xFEEC, DetectorId::Tile, "Tile tracker", Confidence::High, "Tile, Inc.",
     {"squachwatch-cyd", "b3e96f7", "1.0.0", Evidence::RegistryVerified}},
    {0xFD5A, DetectorId::SamsungTag, "Samsung SmartTag", Confidence::High,
     "Samsung Electronics Co., Ltd.",
     {"squachwatch-cyd", "b3e96f7", "1.0.0", Evidence::RegistryVerified}},
    // Flipper Zero case colours. Carried over from the earlier firmware's
    // byte patterns {0x81,0x30}/{0x82,0x30}/{0x83,0x30}, read as
    // little-endian 16-bit UUIDs. That reading is now corroborated: Wall of
    // Flippers, 7h30th3r0n3's wall-of-flipper, and Evil-M5Project all
    // match 0x3081-0x3083 as advertised service UUIDs. Not SIG-assigned.
    {0x3081, DetectorId::Flipper, "Flipper Zero", Confidence::Medium, kUnassigned,
     {"wall-of-flippers", "26f627e", "1.0.0", Evidence::FieldCaptured}},
    {0x3082, DetectorId::Flipper, "Flipper Zero", Confidence::Medium, kUnassigned,
     {"wall-of-flippers", "26f627e", "1.0.0", Evidence::FieldCaptured}},
    {0x3083, DetectorId::Flipper, "Flipper Zero", Confidence::Medium, kUnassigned,
     {"wall-of-flippers", "26f627e", "1.0.0", Evidence::FieldCaptured}},
    // 0xFEAA is Google's general Eddystone UUID - shared with retail and
    // asset beacons that are not trackers, so a match means "Google
    // beacon-class device", not "Find My Device tracker".
    {0xFEAA, DetectorId::GoogleTag, "Google Find My Device", Confidence::Medium, "Google LLC",
     {"squachwatch-cyd", "b3e96f7", "1.0.0", Evidence::RegistryVerified}},
    // Meta service UUIDs carried over from the earlier firmware, where their
    // origin was not recorded. The SIG registry assigns both to Meta
    // Platforms, so the ownership is confirmed; what they mean on a device
    // is not, hence still Low. The three remaining old patterns
    // ({0xAB,0x01}, {0x8E,0x05}, {0x53,0x0D}) were dropped outright: two
    // bytes each, no provenance, and short enough to match noise constantly.
    {0xFEB7, DetectorId::Meta, "Meta service", Confidence::Low, "Meta Platforms, Inc.",
     {"legacy-firmware", "", "1.0.0", Evidence::RegistryVerified}},
    {0xFEB8, DetectorId::Meta, "Meta service", Confidence::Low, "Meta Platforms, Inc.",
     {"legacy-firmware", "", "1.0.0", Evidence::RegistryVerified}},
};

bool isFindMyBeacon(const uint8_t *mfg, size_t length);

bool allDigits(const std::string &value);

// Flock's BLE radio is a generic XUNTONG module, so the company ID alone is
// not enough - it is gated on a plausible device name. Kept from the
// previous implementation, which is stricter than SquachWatch's bare
// company-ID match and worth keeping.
bool isFlockName(const std::string &name);

void formatMac(char *out, size_t outSize, const uint8_t *mac);

uint16_t hashSsid(const uint8_t *ssid, size_t length);

// ---- Address prefix (OUI) tables ----------------------------------------

struct OuiSignature {
    uint8_t oui[3];
    DetectorId detector;
    Confidence confidence;
    const char *label;
    const char *registeredTo;  // IEEE registry owner of the prefix
    Provenance provenance;
};

// Flock. Since 1.1.0 only B4:1E:52, the one prefix the IEEE registry assigns
// to Flock Safety, is High. Every other Flock row is a module maker's
// block (Silicon Labs, Liteon, UGSI, Atheros, Espressif): those modules are
// in ordinary laptops and gadgets, so a match is worth logging but never
// worth a wrist alert. All rows are kept, at Low, by decision 2026-10-29
// (upstream review R1 and R2), so nothing drops out of the record.
//
// Deliberately NOT included: 82:6B:F2, which SquachWatch-CYD and flock-you
// list from DeFlockJoplin. Its first octet has the locally-administered bit
// set (0x82 = 1000 0010), so it is a randomised address someone observed,
// not a vendor prefix. Also left out, as SquachWatch-CYD does: 48:27:EA
// (Samsung) and 3C:71:BF (Espressif), both in nite-oui-collection's list.
inline constexpr OuiSignature kOuiSignatures[] = {
    // --- Flock Safety's own registered prefix ---
    {{0xB4,0x1E,0x52}, DetectorId::Flock, Confidence::High, "Flock", "Flock Safety",
     {"squachwatch-cyd", "b3e96f7", "1.0.0", Evidence::RegistryVerified}},
    // --- Flock, the earlier firmware's 8 prefixes (Silicon Labs) ---
    // From flock-you's WiGLE dataset of "FS Ext Battery" Bluetooth devices.
    // The first three are also in nite-oui-collection's field-tested list.
    // The last five are no longer in flock-you's list (dropped upstream by
    // 6704f01); kept here at Low.
    {{0x58,0x8E,0x81}, DetectorId::Flock, Confidence::Low, "Flock", "Silicon Laboratories",
     {"flock-you", "3515c5f", "1.0.0", Evidence::FieldCaptured}},
    {{0xEC,0x1B,0xBD}, DetectorId::Flock, Confidence::Low, "Flock", "Silicon Laboratories",
     {"flock-you", "3515c5f", "1.0.0", Evidence::FieldCaptured}},
    {{0x90,0x35,0xEA}, DetectorId::Flock, Confidence::Low, "Flock", "Silicon Laboratories",
     {"flock-you", "3515c5f", "1.0.0", Evidence::FieldCaptured}},
    {{0x04,0x0D,0x84}, DetectorId::Flock, Confidence::Low, "Flock", "Silicon Laboratories",
     {"flock-you", "3515c5f", "1.0.0", Evidence::FieldCaptured}},
    {{0xF0,0x82,0xC0}, DetectorId::Flock, Confidence::Low, "Flock", "Silicon Laboratories",
     {"flock-you", "3515c5f", "1.0.0", Evidence::FieldCaptured}},
    {{0x1C,0x34,0xF1}, DetectorId::Flock, Confidence::Low, "Flock", "Silicon Laboratories",
     {"flock-you", "3515c5f", "1.0.0", Evidence::FieldCaptured}},
    {{0x38,0x5B,0x44}, DetectorId::Flock, Confidence::Low, "Flock", "Silicon Laboratories",
     {"flock-you", "3515c5f", "1.0.0", Evidence::FieldCaptured}},
    {{0x94,0x34,0x69}, DetectorId::Flock, Confidence::Low, "Flock", "Silicon Laboratories",
     {"flock-you", "3515c5f", "1.0.0", Evidence::FieldCaptured}},
    // --- Flock, from SquachWatch-CYD (Liteon and others) ---
    // All but 00:A0:D8 are in nite-oui-collection's field-tested list.
    {{0x24,0xB2,0xB9}, DetectorId::Flock, Confidence::Low, "Flock Liteon", "Liteon Technology Corporation",
     {"squachwatch-cyd", "b3e96f7", "1.0.0", Evidence::FieldCaptured}},
    {{0xD0,0x39,0x57}, DetectorId::Flock, Confidence::Low, "Flock", "Liteon Technology Corporation",
     {"squachwatch-cyd", "b3e96f7", "1.0.0", Evidence::FieldCaptured}},
    {{0x00,0xF4,0x8D}, DetectorId::Flock, Confidence::Low, "Flock", "Liteon Technology Corporation",
     {"squachwatch-cyd", "b3e96f7", "1.0.0", Evidence::FieldCaptured}},
    {{0x14,0x5A,0xFC}, DetectorId::Flock, Confidence::Low, "Flock", "Liteon Technology Corporation",
     {"squachwatch-cyd", "b3e96f7", "1.0.0", Evidence::FieldCaptured}},
    {{0x80,0x30,0x49}, DetectorId::Flock, Confidence::Low, "Flock", "Liteon Technology Corporation",
     {"squachwatch-cyd", "b3e96f7", "1.0.0", Evidence::FieldCaptured}},
    {{0xE0,0x0A,0xF6}, DetectorId::Flock, Confidence::Low, "Flock", "Liteon Technology Corporation",
     {"squachwatch-cyd", "b3e96f7", "1.0.0", Evidence::FieldCaptured}},
    {{0x70,0xC9,0x4E}, DetectorId::Flock, Confidence::Low, "Flock", "Liteon Technology Corporation",
     {"squachwatch-cyd", "b3e96f7", "1.0.0", Evidence::FieldCaptured}},
    {{0x3C,0x91,0x80}, DetectorId::Flock, Confidence::Low, "Flock", "Liteon Technology Corporation",
     {"squachwatch-cyd", "b3e96f7", "1.0.0", Evidence::FieldCaptured}},
    {{0xD8,0xF3,0xBC}, DetectorId::Flock, Confidence::Low, "Flock", "Liteon Technology Corporation",
     {"squachwatch-cyd", "b3e96f7", "1.0.0", Evidence::FieldCaptured}},
    {{0xB8,0x35,0x32}, DetectorId::Flock, Confidence::Low, "Flock", kUnassigned,
     {"squachwatch-cyd", "b3e96f7", "1.0.0", Evidence::FieldCaptured}},
    {{0x00,0xA0,0xD8}, DetectorId::Flock, Confidence::Low, "Flock Sierra", "Spectra - Tek",
     {"squachwatch-cyd", "b3e96f7", "1.0.0", Evidence::SingleSource}},
    // --- Flock, nite-oui-collection's field-tested list (new in 1.1.0) ---
    // Taken from @NitekryDPaul's list, which flock-you 6704f01 also carries.
    // nite-oui-collection marks several as "possible" or "still verifying".
    // It calls 08:3A:88 an Espressif Falcon V2 module; the IEEE registry
    // gives the prefix to UGSI. Both claims are recorded; the registry's
    // is the one checked.
    {{0x74,0x4C,0xA1}, DetectorId::Flock, Confidence::Low, "Flock Liteon", "Liteon Technology Corporation",
     {"nite-oui-collection", "29501d5", "1.1.0", Evidence::FieldCaptured}},
    {{0x9C,0x2F,0x9D}, DetectorId::Flock, Confidence::Low, "Flock Liteon", "Liteon Technology Corporation",
     {"nite-oui-collection", "29501d5", "1.1.0", Evidence::FieldCaptured}},
    {{0xC0,0x35,0x32}, DetectorId::Flock, Confidence::Low, "Flock Liteon", "Liteon Technology Corporation",
     {"nite-oui-collection", "29501d5", "1.1.0", Evidence::FieldCaptured}},
    {{0x94,0x08,0x53}, DetectorId::Flock, Confidence::Low, "Flock Liteon", "Liteon Technology Corporation",
     {"nite-oui-collection", "29501d5", "1.1.0", Evidence::FieldCaptured}},
    {{0xE4,0xAA,0xEA}, DetectorId::Flock, Confidence::Low, "Flock Liteon", "Liteon Technology Corporation",
     {"nite-oui-collection", "29501d5", "1.1.0", Evidence::FieldCaptured}},
    {{0xF4,0x6A,0xDD}, DetectorId::Flock, Confidence::Low, "Flock Liteon", "Liteon Technology Corporation",
     {"nite-oui-collection", "29501d5", "1.1.0", Evidence::FieldCaptured}},
    {{0xE8,0xD0,0xFC}, DetectorId::Flock, Confidence::Low, "Flock Liteon", "Liteon Technology Corporation",
     {"nite-oui-collection", "29501d5", "1.1.0", Evidence::FieldCaptured}},
    {{0xB8,0x1E,0xA4}, DetectorId::Flock, Confidence::Low, "Flock Liteon", "Liteon Technology Corporation",
     {"nite-oui-collection", "29501d5", "1.1.0", Evidence::FieldCaptured}},
    {{0x70,0x08,0x94}, DetectorId::Flock, Confidence::Low, "Flock Liteon", "Liteon Technology Corporation",
     {"nite-oui-collection", "29501d5", "1.1.0", Evidence::FieldCaptured}},
    {{0x58,0x00,0xE3}, DetectorId::Flock, Confidence::Low, "Flock Liteon", "Liteon Technology Corporation",
     {"nite-oui-collection", "29501d5", "1.1.0", Evidence::FieldCaptured}},
    {{0x5C,0x93,0xA2}, DetectorId::Flock, Confidence::Low, "Flock Liteon", "Liteon Technology Corporation",
     {"nite-oui-collection", "29501d5", "1.1.0", Evidence::FieldCaptured}},
    {{0x64,0x6E,0x69}, DetectorId::Flock, Confidence::Low, "Flock Liteon", "Liteon Technology Corporation",
     {"nite-oui-collection", "29501d5", "1.1.0", Evidence::FieldCaptured}},
    {{0x14,0xB5,0xCD}, DetectorId::Flock, Confidence::Low, "Flock Liteon", "Liteon Technology Corporation",
     {"nite-oui-collection", "29501d5", "1.1.0", Evidence::FieldCaptured}},
    {{0x08,0x3A,0x88}, DetectorId::Flock, Confidence::Low, "Flock UGSI", "Universal Global Scientific Industrial., Ltd",
     {"nite-oui-collection", "29501d5", "1.1.0", Evidence::FieldCaptured}},
    {{0xE0,0x4F,0x43}, DetectorId::Flock, Confidence::Low, "Flock UGSI", "Universal Global Scientific Industrial., Ltd",
     {"nite-oui-collection", "29501d5", "1.1.0", Evidence::FieldCaptured}},
    // --- Flock, firmware-derived (new in 1.1.0) ---
    // flock-you found the camera's QCA9377 radio ships with Atheros default
    // addresses (00:03:7F:50:00:01 and 00:03:7F:4F:00:16) in a Flock
    // firmware dump. Every QCA9377 shares the block, hence Low.
    {{0x00,0x03,0x7F}, DetectorId::Flock, Confidence::Low, "Flock QCA9377", "Atheros Communications, Inc.",
     {"flock-you", "6704f01", "1.1.0", Evidence::FieldCaptured}},
    // --- Axon / Taser body cameras ---
    // Only 00:25:DF is registered to Axon. E4:05:40 is unassigned and
    // 28:24:FF belongs to WNC, a module maker; both are High on a single
    // source and are listed for review in test_sources (upstream review R5).
    {{0x00,0x25,0xDF}, DetectorId::Axon, Confidence::High, "Axon (Taser)", "Axon Enterprise, Inc.",
     {"squachwatch-cyd", "b3e96f7", "1.0.0", Evidence::RegistryVerified}},
    {{0xE4,0x05,0x40}, DetectorId::Axon, Confidence::High, "Axon body cam", kUnassigned,
     {"squachwatch-cyd", "b3e96f7", "1.0.0", Evidence::SingleSource}},
    {{0x28,0x24,0xFF}, DetectorId::Axon, Confidence::High, "Axon Signal", "WNC Corporation",
     {"squachwatch-cyd", "b3e96f7", "1.0.0", Evidence::SingleSource}},
    // --- Flock, generic Espressif blocks: LOW, log-only, no alert ---
    // SquachWatch-CYD labelled these Flock-ESP32/-S3/-C6 and removed them
    // in 10f4da6; kept here at Low by decision 2026-10-29 (review R2).
    // D4:AD:FC is not Espressif: the registry gives it to Shenzhen
    // Intellirocks. The label is unchanged until that is reviewed.
    {{0x24,0x0A,0xC4}, DetectorId::Flock, Confidence::Low, "Flock? (ESP32)", "Espressif Inc.",
     {"squachwatch-cyd", "b3e96f7", "1.0.0", Evidence::SingleSource}},
    {{0x30,0xAE,0xA4}, DetectorId::Flock, Confidence::Low, "Flock? (ESP32)", "Espressif Inc.",
     {"squachwatch-cyd", "b3e96f7", "1.0.0", Evidence::SingleSource}},
    {{0x24,0x6F,0x28}, DetectorId::Flock, Confidence::Low, "Flock? (ESP32)", "Espressif Inc.",
     {"squachwatch-cyd", "b3e96f7", "1.0.0", Evidence::SingleSource}},
    {{0xCC,0x50,0xE3}, DetectorId::Flock, Confidence::Low, "Flock? (ESP32)", "Espressif Inc.",
     {"squachwatch-cyd", "b3e96f7", "1.0.0", Evidence::SingleSource}},
    {{0xDC,0x54,0x75}, DetectorId::Flock, Confidence::Low, "Flock? (ESP32)", "Espressif Inc.",
     {"squachwatch-cyd", "b3e96f7", "1.0.0", Evidence::SingleSource}},
    {{0xE8,0x9F,0x6D}, DetectorId::Flock, Confidence::Low, "Flock? (ESP32)", "Espressif Inc.",
     {"squachwatch-cyd", "b3e96f7", "1.0.0", Evidence::SingleSource}},
    {{0x8C,0xAA,0xB5}, DetectorId::Flock, Confidence::Low, "Flock? (ESP-S3)", "Espressif Inc.",
     {"squachwatch-cyd", "b3e96f7", "1.0.0", Evidence::SingleSource}},
    {{0x34,0x85,0x18}, DetectorId::Flock, Confidence::Low, "Flock? (ESP-S3)", "Espressif Inc.",
     {"squachwatch-cyd", "b3e96f7", "1.0.0", Evidence::SingleSource}},
    {{0xD4,0xAD,0xFC}, DetectorId::Flock, Confidence::Low, "Flock? (ESP32)", "Shenzhen Intellirocks Tech. Co. Ltd.",
     {"squachwatch-cyd", "b3e96f7", "1.0.0", Evidence::SingleSource}},
    {{0xAC,0x67,0xB2}, DetectorId::Flock, Confidence::Low, "Flock? (ESP32)", "Espressif Inc.",
     {"squachwatch-cyd", "b3e96f7", "1.0.0", Evidence::SingleSource}},
    {{0x84,0xF3,0xEB}, DetectorId::Flock, Confidence::Low, "Flock? (ESP-S3)", "Espressif Inc.",
     {"squachwatch-cyd", "b3e96f7", "1.0.0", Evidence::SingleSource}},
    {{0xB4,0xE6,0x2D}, DetectorId::Flock, Confidence::Low, "Flock? (ESP32)", "Espressif Inc.",
     {"squachwatch-cyd", "b3e96f7", "1.0.0", Evidence::SingleSource}},
    {{0xCC,0xDB,0xA7}, DetectorId::Flock, Confidence::Low, "Flock? (ESP32)", "Espressif Inc.",
     {"squachwatch-cyd", "b3e96f7", "1.0.0", Evidence::SingleSource}},
    {{0x94,0xB9,0x7E}, DetectorId::Flock, Confidence::Low, "Flock? (ESP32)", "Espressif Inc.",
     {"squachwatch-cyd", "b3e96f7", "1.0.0", Evidence::SingleSource}},
    {{0xA4,0xCF,0x12}, DetectorId::Flock, Confidence::Low, "Flock? (ESP-S2)", "Espressif Inc.",
     {"squachwatch-cyd", "b3e96f7", "1.0.0", Evidence::SingleSource}},
    {{0xC0,0x49,0xEF}, DetectorId::Flock, Confidence::Low, "Flock? (ESP-C6)", "Espressif Inc.",
     {"squachwatch-cyd", "b3e96f7", "1.0.0", Evidence::SingleSource}},
};

const OuiSignature *lookupOui(const uint8_t *mac);

// Pineapple. Carried over unchanged from the earlier firmware, where the
// origin of the list was not recorded. The registry owners below show the
// problem the upstream review (R4) raises: most of these blocks belong to
// chipset and adapter makers, not Hak5. Matching is unchanged until that
// decision is made. openNetworkOnly rows match only on an open network.
struct PineappleOuiSignature {
    uint8_t oui[3];
    bool openNetworkOnly;
    const char *registeredTo;  // IEEE registry owner of the prefix
    Provenance provenance;
};

inline constexpr PineappleOuiSignature kPineappleOuis[] = {
    {{0x00,0x13,0x37}, false, "Orient Power Home Network Ltd.",
     {"legacy-firmware", "", "1.0.0", Evidence::SingleSource}},
    {{0x02,0xC0,0xCA}, false, kLocallyAdministered,
     {"legacy-firmware", "", "1.0.0", Evidence::SingleSource}},
    {{0x02,0x13,0x37}, false, kLocallyAdministered,
     {"legacy-firmware", "", "1.0.0", Evidence::SingleSource}},
    {{0x00,0x0A,0x00}, false, "MediaTek Inc",
     {"legacy-firmware", "", "1.0.0", Evidence::SingleSource}},
    {{0x00,0x0C,0x43}, false, "MediaTek Inc",
     {"legacy-firmware", "", "1.0.0", Evidence::SingleSource}},
    {{0x00,0x0C,0xE7}, false, "MediaTek Inc",
     {"legacy-firmware", "", "1.0.0", Evidence::SingleSource}},
    {{0x00,0x17,0xA5}, false, "MediaTek Inc",
     {"legacy-firmware", "", "1.0.0", Evidence::SingleSource}},
    {{0x9C,0xEF,0xD5}, false, "Panda Wireless, Inc.",
     {"legacy-firmware", "", "1.0.0", Evidence::SingleSource}},
    {{0x9C,0xE5,0xD5}, false, kUnassigned,
     {"legacy-firmware", "", "1.0.0", Evidence::SingleSource}},
    {{0xDE,0xAD,0xBE}, false, kLocallyAdministered,
     {"legacy-firmware", "", "1.0.0", Evidence::SingleSource}},
    {{0x00,0xC0,0xCA}, true, "Alfa, Inc.",
     {"legacy-firmware", "", "1.0.0", Evidence::SingleSource}},
    {{0x1C,0xBF,0xCE}, true, "Shenzhen Century Xinyang Technology Co., Ltd",
     {"legacy-firmware", "", "1.0.0", Evidence::SingleSource}},
    {{0x0C,0xEF,0xAF}, true, kMediumBlock,
     {"legacy-firmware", "", "1.0.0", Evidence::SingleSource}},
};

bool isPineappleOui(const uint8_t *mac, bool openNetwork);

// Axon body cameras advertise these SSID prefixes while in pairing mode.
// SquachWatch-CYD credits this data to an AI-assisted compilation
// "expanded against public sources", with no captures published, so the
// rows are SingleSource and listed for review in test_sources (R14).
struct SsidPrefixSignature {
    const char *prefix;
    DetectorId detector;
    Confidence confidence;
    Provenance provenance;
};

inline constexpr SsidPrefixSignature kSsidPrefixes[] = {
    {"AB2-", DetectorId::Axon, Confidence::High,
     {"squachwatch-cyd", "b3e96f7", "1.0.0", Evidence::SingleSource}},
    {"AB3-", DetectorId::Axon, Confidence::High,
     {"squachwatch-cyd", "b3e96f7", "1.0.0", Evidence::SingleSource}},
    {"AB4-", DetectorId::Axon, Confidence::High,
     {"squachwatch-cyd", "b3e96f7", "1.0.0", Evidence::SingleSource}},
    {"AXON-", DetectorId::Axon, Confidence::High,
     {"squachwatch-cyd", "b3e96f7", "1.0.0", Evidence::SingleSource}},
};

// The SSID in a beacon is not null-terminated, so this compares against the
// raw bytes and length rather than reaching for strncasecmp.
bool ssidHasPrefix(const uint8_t *ssid, uint8_t ssidLength, const char *prefix);

} // namespace lts
