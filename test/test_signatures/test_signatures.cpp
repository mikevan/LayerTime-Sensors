// Unit tests for lts/Signatures. Built with no stubs at all: the signature
// code needs nothing from any platform.

#include "check.h"

#include <set>
#include <string>

#include <lts/Signatures.h>

using namespace lts;

void company_ids_and_proximity_pairing_switch()
{
    CHECK_INT(0x004C, kAppleCompanyId);
    CHECK_INT(0x09C8, kXuntongCompanyId);
    CHECK_FALSE(kMatchProximityPairing);
}

void oui_table_has_no_duplicate_prefixes()
{
    std::set<uint32_t> seen;
    for (const OuiSignature &s : kOuiSignatures) {
        const uint32_t oui = (uint32_t(s.oui[0]) << 16) | (uint32_t(s.oui[1]) << 8) | s.oui[2];
        CHECK_TRUE(seen.insert(oui).second);
    }
    CHECK_INT(56, seen.size());
}

// Since 1.1.0 (upstream review R1, decided 2026-10-29): only Flock Safety's
// own registered prefix is High; the 19 module-maker rows that were High
// are Low, and 16 field-list rows were added at Low. Since 1.1.1 (R15c):
// Kismet's locally administered Axon prefix, at Low.
void oui_confidence_split_is_1_flock_high_3_axon_high_51_flock_low_1_axon_low()
{
    int flockHigh = 0, axonHigh = 0, flockLow = 0, axonLow = 0, other = 0;
    for (const OuiSignature &s : kOuiSignatures) {
        if (s.detector == DetectorId::Flock && s.confidence == Confidence::High) ++flockHigh;
        else if (s.detector == DetectorId::Axon && s.confidence == Confidence::High) ++axonHigh;
        else if (s.detector == DetectorId::Flock && s.confidence == Confidence::Low) ++flockLow;
        else if (s.detector == DetectorId::Axon && s.confidence == Confidence::Low) ++axonLow;
        else ++other;
    }
    CHECK_INT(1, flockHigh);
    CHECK_INT(3, axonHigh);
    CHECK_INT(51, flockLow);
    CHECK_INT(1, axonLow);
    CHECK_INT(0, other);
}

void the_locally_administered_axon_prefix_is_low()
{
    const uint8_t mac[] = {0x12, 0x20, 0x13, 0x01, 0x02, 0x03};
    const OuiSignature *s = lookupOui(mac);
    CHECK_TRUE(s != nullptr);
    if (s) {
        CHECK_INT(static_cast<int>(DetectorId::Axon), static_cast<int>(s->detector));
        CHECK_INT(static_cast<int>(Confidence::Low), static_cast<int>(s->confidence));
        CHECK_STR("Axon? (locally administered)", s->label);
    }
}

void ble_name_prefixes_are_the_one_axon_prefix()
{
    CHECK_INT(1, sizeof(kBleNamePrefixes) / sizeof(kBleNamePrefixes[0]));
    CHECK_STR("Axon-X", kBleNamePrefixes[0].prefix);
    CHECK_INT(static_cast<int>(DetectorId::Axon), static_cast<int>(kBleNamePrefixes[0].detector));
    CHECK_INT(static_cast<int>(Confidence::Medium), static_cast<int>(kBleNamePrefixes[0].confidence));
}

void name_prefix_ignores_case_and_checks_length()
{
    CHECK_TRUE(nameHasPrefix("Axon-X12", "Axon-X"));
    CHECK_TRUE(nameHasPrefix("AXON-x12", "Axon-X"));
    CHECK_TRUE(nameHasPrefix("Axon-X", "Axon-X"));
    CHECK_FALSE(nameHasPrefix("Axon-", "Axon-X"));
    CHECK_FALSE(nameHasPrefix("Axonics", "Axon-X"));
    CHECK_FALSE(nameHasPrefix("My Axon-X", "Axon-X"));
    CHECK_FALSE(nameHasPrefix("", "Axon-X"));
    CHECK_FALSE(nameHasPrefix("Axon-X", nullptr));
}

void the_only_high_flock_prefix_is_flock_safetys_own()
{
    for (const OuiSignature &s : kOuiSignatures) {
        if (s.detector != DetectorId::Flock || s.confidence != Confidence::High) continue;
        CHECK_INT(0xB4, s.oui[0]);
        CHECK_INT(0x1E, s.oui[1]);
        CHECK_INT(0x52, s.oui[2]);
    }
}

// The Pineapple list moved from a switch statement into a table in 1.1.0 so
// each row can carry its provenance. Matching must be exactly what 1.0.0
// did: these ten match on any network, these three only on an open one.
void pineapple_table_matches_the_1_0_0_list_exactly()
{
    const uint32_t always[] = {0x001337, 0x02C0CA, 0x021337, 0x000A00, 0x000C43,
                               0x000CE7, 0x0017A5, 0x9CEFD5, 0x9CE5D5, 0xDEADBE};
    const uint32_t openOnly[] = {0x00C0CA, 0x1CBFCE, 0x0CEFAF};
    auto mac = [](uint32_t oui, uint8_t *m) {
        m[0] = uint8_t(oui >> 16); m[1] = uint8_t(oui >> 8); m[2] = uint8_t(oui);
        m[3] = 0x12; m[4] = 0x34; m[5] = 0x56;
    };
    uint8_t m[6];
    for (uint32_t oui : always) {
        mac(oui, m);
        CHECK_TRUE(isPineappleOui(m, false));
        CHECK_TRUE(isPineappleOui(m, true));
    }
    for (uint32_t oui : openOnly) {
        mac(oui, m);
        CHECK_FALSE(isPineappleOui(m, false));
        CHECK_TRUE(isPineappleOui(m, true));
    }
    CHECK_INT(13, sizeof(kPineappleOuis) / sizeof(kPineappleOuis[0]));
    mac(0x001338, m);
    CHECK_FALSE(isPineappleOui(m, true));
    CHECK_FALSE(isPineappleOui(nullptr, true));
}

void lookup_reads_the_first_three_bytes_given()
{
    const uint8_t mac[6] = {0x00, 0x25, 0xDF, 0x99, 0x99, 0x99};
    const OuiSignature *s = lookupOui(mac);
    CHECK_TRUE(s != nullptr);
    if (s) CHECK_STR("Axon (Taser)", s->label);
    const uint8_t reversed[6] = {0x99, 0x99, 0x99, 0xDF, 0x25, 0x00};
    CHECK_TRUE(lookupOui(reversed) == nullptr);
}

void ssid_prefixes_are_the_four_axon_prefixes()
{
    const char *expected[] = {"AB2-", "AB3-", "AB4-", "AXON-"};
    CHECK_INT(4, sizeof(kSsidPrefixes) / sizeof(kSsidPrefixes[0]));
    for (size_t i = 0; i < 4; ++i) {
        CHECK_STR(expected[i], kSsidPrefixes[i].prefix);
        CHECK_INT(static_cast<int>(DetectorId::Axon), static_cast<int>(kSsidPrefixes[i].detector));
        CHECK_INT(static_cast<int>(Confidence::High), static_cast<int>(kSsidPrefixes[i].confidence));
    }
}

void ssid_prefix_handles_non_letters_and_empty()
{
    const uint8_t s[] = {'1', '-', 'x'};
    CHECK_TRUE(ssidHasPrefix(s, 3, "1-"));
    CHECK_TRUE(ssidHasPrefix(s, 0, ""));
    CHECK_FALSE(ssidHasPrefix(s, 0, "1"));
}

void find_my_needs_exactly_three_bytes_minimum()
{
    const uint8_t three[] = {0x4C, 0x00, 0x12};
    CHECK_TRUE(isFindMyBeacon(three, 3));
    CHECK_FALSE(isFindMyBeacon(three, 0));
}

void mac_text_at_the_minimum_buffer()
{
    char out[18];
    const uint8_t mac[] = {0, 1, 2, 3, 4, 255};
    formatMac(out, sizeof(out), mac);
    CHECK_STR("00:01:02:03:04:FF", out);
    char keep[18] = "keep";
    formatMac(keep, sizeof(keep), nullptr);
    CHECK_STR("keep", keep);
}

// 1.1.2: the device type is status bits 4-5 and the owner state is the
// payload length, as AirGuard (seemoo-lab d515c534, DeviceManager.kt) reads
// them. Byte layout: company 4C 00, subtype 12, length, status.
FindMyBeacon fm(uint8_t length, uint8_t status)
{
    const uint8_t r[] = {0x4C, 0x00, 0x12, length, status};
    return parseFindMy(r, sizeof(r));
}

void find_my_device_type_comes_from_status_bits_4_and_5()
{
    CHECK_INT((int)FindMyKind::AppleDevice, (int)fm(0x19, 0x00).kind);
    CHECK_INT((int)FindMyKind::AirTag, (int)fm(0x19, 0x10).kind);
    CHECK_INT((int)FindMyKind::Accessory, (int)fm(0x19, 0x20).kind);
    CHECK_INT((int)FindMyKind::AirPods, (int)fm(0x19, 0x30).kind);
    // The other status bits (battery level in 6-7, flags in 0-3) do not
    // change the type.
    CHECK_INT((int)FindMyKind::AirTag, (int)fm(0x19, 0xD0).kind);
    CHECK_INT((int)FindMyKind::AirTag, (int)fm(0x19, 0x1F).kind);
    CHECK_INT((int)FindMyKind::AppleDevice, (int)fm(0x19, 0xCF).kind);
}

void find_my_length_0x19_means_away_from_the_owner()
{
    CHECK_TRUE(fm(0x19, 0x10).separated);
    CHECK_FALSE(fm(0x02, 0x10).separated);
    CHECK_FALSE(fm(0x18, 0x10).separated);
    CHECK_FALSE(fm(0x1A, 0x10).separated);
}

void find_my_without_a_status_byte_is_unknown()
{
    const uint8_t three[] = {0x4C, 0x00, 0x12};
    const uint8_t four[] = {0x4C, 0x00, 0x12, 0x19};
    CHECK_INT((int)FindMyKind::Unknown, (int)parseFindMy(three, 3).kind);
    CHECK_INT((int)FindMyKind::Unknown, (int)parseFindMy(four, 4).kind);
    CHECK_FALSE(parseFindMy(four, 4).separated);
    CHECK_INT((int)FindMyKind::NotFindMy, (int)parseFindMy(nullptr, 5).kind);
}

void subtype_0x1e_and_others_are_not_find_my()
{
    // 0x1E was a misread length byte, never an Apple subtype (review R13).
    const uint8_t x1e[] = {0x4C, 0x00, 0x1E, 0x19, 0x10};
    const uint8_t x07[] = {0x4C, 0x00, 0x07, 0x19, 0x10};
    const uint8_t x10[] = {0x4C, 0x00, 0x10, 0x05, 0x10};
    CHECK_FALSE(isFindMyBeacon(x1e, 5));
    CHECK_FALSE(isFindMyBeacon(x07, 5));  // proximity pairing stays off
    CHECK_FALSE(isFindMyBeacon(x10, 5));
}

void only_an_airtag_away_from_its_owner_is_high()
{
    struct Row { uint8_t length, status; Confidence c; const char *detail; };
    const Row rows[] = {
        {0x19, 0x10, Confidence::High, "AirTag away from its owner"},
        {0x02, 0x10, Confidence::Low, "AirTag near its owner"},
        {0x19, 0x20, Confidence::Medium, "Find My tag away from owner"},
        {0x02, 0x20, Confidence::Low, "Find My tag near its owner"},
        {0x19, 0x30, Confidence::Low, "AirPods (Find My)"},
        {0x02, 0x30, Confidence::Low, "AirPods (Find My)"},
        {0x19, 0x00, Confidence::Low, "Apple device (Find My)"},
        {0x02, 0x00, Confidence::Low, "Apple device (Find My)"},
    };
    for (const Row &r : rows) {
        const FindMyGrade g = gradeFindMy(fm(r.length, r.status));
        CHECK_INT((int)r.c, (int)g.confidence);
        CHECK_STR(r.detail, g.detail);
    }
    FindMyBeacon unknown;
    unknown.kind = FindMyKind::Unknown;
    CHECK_INT((int)Confidence::Low, (int)gradeFindMy(unknown).confidence);
    CHECK_STR("Find My beacon, type unknown", gradeFindMy(unknown).detail);
}

int main(int argc, char **argv)
{
    CHECK_MAIN(argc, argv);
    CASE(company_ids_and_proximity_pairing_switch);
    CASE(oui_table_has_no_duplicate_prefixes);
    CASE(oui_confidence_split_is_1_flock_high_3_axon_high_51_flock_low_1_axon_low);
    CASE(the_locally_administered_axon_prefix_is_low);
    CASE(ble_name_prefixes_are_the_one_axon_prefix);
    CASE(name_prefix_ignores_case_and_checks_length);
    CASE(the_only_high_flock_prefix_is_flock_safetys_own);
    CASE(pineapple_table_matches_the_1_0_0_list_exactly);
    CASE(lookup_reads_the_first_three_bytes_given);
    CASE(ssid_prefixes_are_the_four_axon_prefixes);
    CASE(ssid_prefix_handles_non_letters_and_empty);
    CASE(find_my_needs_exactly_three_bytes_minimum);
    CASE(find_my_device_type_comes_from_status_bits_4_and_5);
    CASE(find_my_length_0x19_means_away_from_the_owner);
    CASE(find_my_without_a_status_byte_is_unknown);
    CASE(subtype_0x1e_and_others_are_not_find_my);
    CASE(only_an_airtag_away_from_its_owner_is_high);
    CASE(mac_text_at_the_minimum_buffer);
    CHECK_SUMMARY();
}
