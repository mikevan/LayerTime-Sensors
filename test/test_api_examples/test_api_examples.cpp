// Runs the quick-start example from API.md, with the same inputs, and checks
// it reports exactly what the document says it prints. If this fails, the
// document is wrong: fix API.md and this test together.

#include "check.h"

#include <cstring>
#include <string>
#include <vector>

#include <lts/BleAdvertClassifier.h>
#include <lts/WifiFrameClassifier.h>

using namespace lts;

namespace {

struct Seen {
    DetectorId detector;
    Confidence confidence;
    std::string address;
    std::string detail;
    int rssi;
    int channel;
};

// The document's sink prints; this one copies, which is what the document
// tells callers to do, since a candidate's text is only valid during the call.
void onCandidate(const Candidate &c, void *context)
{
    static_cast<std::vector<Seen> *>(context)->push_back(
        {c.detector, c.confidence, c.address, c.detail, c.rssi, c.channel});
}

struct Advert {
    std::string mfg;
};

void manufacturerAt(uint8_t, std::string &out, const void *context)
{
    out = static_cast<const Advert *>(context)->mfg;
}

bool noUuid(uint8_t, uint16_t &, const void *) { return false; }

} // namespace

void the_bluetooth_quick_start_reports_one_find_my_tracker()
{
    std::vector<Seen> seen;
    Advert tag{std::string("\x4C\x00\x12\x19\x00", 5)};
    const uint8_t address[6] = {0xC4, 0x11, 0x22, 0x33, 0x44, 0x55};
    BleAdvertSource advert;
    advert.printedAddress = "c4:11:22:33:44:55";
    advert.addressBytes = address;
    advert.rssi = -61;
    advert.manufacturerCount = 1;
    advert.manufacturer = manufacturerAt;
    advert.uuidCount = 0;
    advert.uuid16 = noUuid;
    advert.context = &tag;
    classifyBleAdvert(advert, DetectorSet::all(), onCandidate, &seen);

    CHECK_INT(1, seen.size());
    if (seen.size() != 1) return;
    CHECK_INT(10, static_cast<int>(seen[0].detector));
    CHECK_INT(static_cast<int>(Confidence::High), static_cast<int>(seen[0].confidence));
    CHECK_STR("c4:11:22:33:44:55", seen[0].address.c_str());
    CHECK_STR("Find My tracker beacon", seen[0].detail.c_str());
    CHECK_INT(-61, seen[0].rssi);
    CHECK_INT(0, seen[0].channel);
}

void the_wifi_quick_start_reports_axon_twice()
{
    std::vector<Seen> seen;
    uint8_t frame[64] = {0};
    frame[0] = 0x80;  // management frame, subtype 8: a beacon
    const uint8_t bssid[6] = {0x00, 0x25, 0xDF, 0x01, 0x02, 0x03};
    std::memset(frame + 4, 0xFF, 6);   // destination: broadcast
    std::memcpy(frame + 10, bssid, 6);  // transmitter
    std::memcpy(frame + 16, bssid, 6);  // BSSID
    frame[36] = 0x00;                   // SSID element
    frame[37] = 8;                      // SSID length
    std::memcpy(frame + 38, "AB3-1234", 8);
    WifiFrameClassifier wifi;
    wifi.classify(frame, 46, -70, 6, 1000, DetectorSet::all(), onCandidate, &seen);

    CHECK_INT(2, seen.size());
    if (seen.size() != 2) return;
    CHECK_INT(13, static_cast<int>(seen[0].detector));
    CHECK_STR("Axon (Taser)", seen[0].detail.c_str());
    CHECK_STR("SSID AB3-1234", seen[1].detail.c_str());
    for (const Seen &s : seen) {
        CHECK_STR("00:25:DF:01:02:03", s.address.c_str());
        CHECK_INT(static_cast<int>(Confidence::High), static_cast<int>(s.confidence));
        CHECK_INT(-70, s.rssi);
        CHECK_INT(6, s.channel);
    }
}

void an_empty_detector_set_reports_nothing()
{
    std::vector<Seen> seen;
    Advert tag{std::string("\x4C\x00\x12\x19\x00", 5)};
    const uint8_t address[6] = {0};
    BleAdvertSource advert;
    advert.addressBytes = address;
    advert.manufacturerCount = 1;
    advert.manufacturer = manufacturerAt;
    advert.uuid16 = noUuid;
    advert.context = &tag;
    classifyBleAdvert(advert, DetectorSet::none(), onCandidate, &seen);
    CHECK_INT(0, seen.size());
}

// API.md tells NimBLE users to reverse the address, because the library
// reads the vendor prefix from bytes 0 to 2. Prove both halves of that.
void the_address_must_be_handed_over_prefix_first()
{
    std::vector<Seen> seen;
    Advert none;
    const uint8_t prefixFirst[6] = {0xB4, 0x1E, 0x52, 0x01, 0x02, 0x03};
    const uint8_t prefixLast[6] = {0x03, 0x02, 0x01, 0x52, 0x1E, 0xB4};
    BleAdvertSource advert;
    advert.printedAddress = "b4:1e:52:01:02:03";
    advert.manufacturer = manufacturerAt;
    advert.uuid16 = noUuid;
    advert.context = &none;
    advert.addressBytes = prefixFirst;
    classifyBleAdvert(advert, DetectorSet::all(), onCandidate, &seen);
    CHECK_INT(1, seen.size());
    seen.clear();
    advert.addressBytes = prefixLast;
    classifyBleAdvert(advert, DetectorSet::all(), onCandidate, &seen);
    CHECK_INT(0, seen.size());
}

int main(int argc, char **argv)
{
    CHECK_MAIN(argc, argv);
    CASE(the_bluetooth_quick_start_reports_one_find_my_tracker);
    CASE(the_wifi_quick_start_reports_axon_twice);
    CASE(an_empty_detector_set_reports_nothing);
    CASE(the_address_must_be_handed_over_prefix_first);
    CHECK_SUMMARY();
}
