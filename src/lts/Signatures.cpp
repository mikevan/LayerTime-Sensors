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

#include "Signatures.h"

#include <stdio.h>
#include <string.h>

namespace lts {

FindMyBeacon parseFindMy(const uint8_t *mfg, size_t length)
{
    FindMyBeacon b;
    if (mfg == nullptr || length < 3) return b;
    const uint8_t subtype = mfg[2];
    if (subtype == kFindMySubtype) {
        if (length < 5) {
            b.kind = FindMyKind::Unknown;
            return b;
        }
        b.separated = mfg[3] == kFindMySeparatedLength;
        switch ((mfg[4] & kFindMyTypeMask) >> kFindMyTypeShift) {
        case 0: b.kind = FindMyKind::AppleDevice; break;
        case 1: b.kind = FindMyKind::AirTag; break;
        case 2: b.kind = FindMyKind::Accessory; break;
        default: b.kind = FindMyKind::AirPods; break;
        }
        return b;
    }
    if (kMatchProximityPairing && subtype == 0x07) b.kind = FindMyKind::Unknown;
    return b;
}

bool isFindMyBeacon(const uint8_t *mfg, size_t length)
{
    return parseFindMy(mfg, length).kind != FindMyKind::NotFindMy;
}

FindMyGrade gradeFindMy(const FindMyBeacon &b)
{
    // Only a tag away from its owner is a tracking concern; a tag whose
    // owner is in range is someone's keys. Low is logged, never an alert.
    switch (b.kind) {
    case FindMyKind::AirTag:
        return b.separated ? FindMyGrade{Confidence::High, "AirTag away from its owner"}
                           : FindMyGrade{Confidence::Low, "AirTag near its owner"};
    case FindMyKind::Accessory:
        return b.separated ? FindMyGrade{Confidence::Medium, "Find My tag away from owner"}
                           : FindMyGrade{Confidence::Low, "Find My tag near its owner"};
    case FindMyKind::AirPods:
        return {Confidence::Low, "AirPods (Find My)"};
    case FindMyKind::AppleDevice:
        return {Confidence::Low, "Apple device (Find My)"};
    default:
        return {Confidence::Low, "Find My beacon, type unknown"};
    }
}

bool allDigits(const std::string &value)
{
    if (value.empty()) return false;
    for (char c : value) if (c < '0' || c > '9') return false;
    return true;
}

bool isFlockName(const std::string &name)
{
    return name.empty() || name.rfind("Penguin-", 0) == 0 ||
           name == "FS Ext Battery" || (name.length() == 10 && allDigits(name));
}

void formatMac(char *out, size_t outSize, const uint8_t *mac)
{
    if (!out || outSize < 18 || !mac) return;
    snprintf(out, outSize, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

uint16_t hashSsid(const uint8_t *ssid, size_t length)
{
    uint16_t hash = 5381;
    for (size_t i = 0; i < length; ++i)
        hash = static_cast<uint16_t>(((hash << 5) + hash) + ssid[i]);
    return hash;
}

bool isPineappleOui(const uint8_t *mac, bool openNetwork)
{
    if (mac == nullptr) return false;
    for (const PineappleOuiSignature &sig : kPineappleOuis)
        if (memcmp(mac, sig.oui, 3) == 0) return !sig.openNetworkOnly || openNetwork;
    return false;
}

const OuiSignature *lookupOui(const uint8_t *mac)
{
    if (mac == nullptr) return nullptr;
    for (const OuiSignature &sig : kOuiSignatures)
        if (memcmp(mac, sig.oui, 3) == 0) return &sig;
    return nullptr;
}

bool ssidHasPrefix(const uint8_t *ssid, uint8_t ssidLength, const char *prefix)
{
    const size_t n = strlen(prefix);
    if (ssidLength < n) return false;
    for (size_t i = 0; i < n; ++i) {
        char a = static_cast<char>(ssid[i]);
        char b = prefix[i];
        if (a >= 'a' && a <= 'z') a = static_cast<char>(a - 32);
        if (b >= 'a' && b <= 'z') b = static_cast<char>(b - 32);
        if (a != b) return false;
    }
    return true;
}

bool nameHasPrefix(const std::string &name, const char *prefix)
{
    if (prefix == nullptr) return false;
    const size_t n = strlen(prefix);
    if (name.size() < n) return false;
    for (size_t i = 0; i < n; ++i) {
        char a = name[i];
        char b = prefix[i];
        if (a >= 'a' && a <= 'z') a = static_cast<char>(a - 32);
        if (b >= 'a' && b <= 'z') b = static_cast<char>(b - 32);
        if (a != b) return false;
    }
    return true;
}

} // namespace lts
