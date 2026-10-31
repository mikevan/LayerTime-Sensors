// Checks where every signature row came from, and that every vendor it
// names is the vendor the official registry names.
//
// The registry owners are read from the pinned snapshots in
// ../sources/snapshots/, which tools/refresh_registry_snapshots.py builds
// from the IEEE and Bluetooth SIG registries. The sources are read from
// ../sources/registry.json. Both are plain files in the library, so this
// suite needs no network.

#include "check.h"

#include <cstdio>
#include <cstring>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include <lts/Signatures.h>

using namespace lts;

namespace {

using Snapshot = std::map<std::string, std::string>;

std::string readFile(const char *path)
{
    std::ifstream in(path, std::ios::binary);
    std::stringstream s;
    s << in.rdbuf();
    return s.str();
}

// One "KEY<tab>OWNER" pair per line; lines starting with '#' are comments.
Snapshot readSnapshot(const char *path)
{
    Snapshot out;
    std::istringstream in(readFile(path));
    std::string line;
    while (std::getline(in, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty() || line[0] == '#') continue;
        const size_t tab = line.find('\t');
        if (tab != std::string::npos) out[line.substr(0, tab)] = line.substr(tab + 1);
    }
    return out;
}

std::set<std::string> registryIds(const std::string &json)
{
    std::set<std::string> ids;
    const std::string key = "\"id\": \"";
    for (size_t at = json.find(key); at != std::string::npos; at = json.find(key, at + 1)) {
        const size_t start = at + key.size();
        ids.insert(json.substr(start, json.find('"', start) - start));
    }
    return ids;
}

std::string ouiText(const uint8_t *oui)
{
    char b[9];
    snprintf(b, sizeof(b), "%02X:%02X:%02X", oui[0], oui[1], oui[2]);
    return b;
}

std::string hex4(uint16_t v)
{
    char b[5];
    snprintf(b, sizeof(b), "%04X", v);
    return b;
}

// What is wrong with one recorded owner, or "" if nothing is.
std::string ownerProblem(const std::string &key, bool locallyAdministered,
                         const std::string &recorded, const Snapshot &snapshot)
{
    if (locallyAdministered)
        return recorded == kLocallyAdministered ? "" :
               key + " is locally administered, so no vendor owns it; record it as " + kLocallyAdministered;
    const auto it = snapshot.find(key);
    if (it == snapshot.end())
        return key + " is not in the registry snapshot; run tools/refresh_registry_snapshots.py";
    if (it->second != recorded)
        return key + " is recorded as \"" + recorded + "\" but the registry says \"" + it->second + "\"";
    return "";
}

// What is wrong with one row's provenance, or "" if nothing is.
std::string provenanceProblem(const std::string &row, const Provenance &p,
                              const std::set<std::string> &ids, const std::string &json)
{
    if (p.source == nullptr || ids.count(p.source) == 0)
        return row + " names source \"" + (p.source ? p.source : "(null)") + "\", which is not in sources/registry.json";
    if (p.since == nullptr || std::strlen(p.since) < 5 || std::strchr(p.since, '.') == nullptr)
        return row + " has no library version in since";
    if (p.commit == nullptr) return row + " has a null commit";
    if (std::strlen(p.commit) == 0)
        return std::strcmp(p.source, "legacy-firmware") == 0 ? "" :
               row + " has no commit; only legacy-firmware rows may omit it";
    if (std::strlen(p.commit) < 7) return row + " commit is shorter than 7 characters";
    // The short id must start a commit id recorded in the registry: right
    // after a quote (a sha field) or a space (a commit named in notes).
    bool recorded = false;
    for (size_t at = json.find(p.commit); at != std::string::npos && !recorded; at = json.find(p.commit, at + 1))
        recorded = at > 0 && (json[at - 1] == '"' || json[at - 1] == ' ');
    if (!recorded)
        return row + " commit " + p.commit + " is not recorded in sources/registry.json";
    return "";
}

// The registry owner name each detector's vendor goes by.
const char *vendorFor(DetectorId d)
{
    switch (d) {
    case DetectorId::Flock: return "Flock Safety";
    case DetectorId::Axon: return "Axon Enterprise";
    case DetectorId::AirTag: return "Apple, Inc.";
    case DetectorId::Tile: return "Tile, Inc.";
    case DetectorId::SamsungTag: return "Samsung Electronics";
    case DetectorId::GoogleTag: return "Google LLC";
    case DetectorId::Meta: return "Meta Platforms";
    default: return nullptr;
    }
}

std::string vendorProblem(const std::string &row, DetectorId d, const std::string &owner, Evidence e)
{
    if (e != Evidence::RegistryVerified) return "";
    const char *vendor = vendorFor(d);
    if (vendor == nullptr) return row + " is RegistryVerified, but its detector has no registered vendor";
    if (owner.compare(0, std::strlen(vendor), vendor) != 0)
        return row + " is RegistryVerified, but the registry gives it to \"" + owner + "\", not " + vendor;
    return "";
}

// High rows that rest on a single source, waiting on a decision. Each entry
// names the review item that decides it. When a row is fixed, remove it
// here; the test fails if an entry no longer matches a High row.
const char *const kHighPendingReview[] = {
    "OUI E4:05:40",  // R5, upstream review 2026-10-29: Axon, unassigned prefix
    "OUI 28:24:FF",  // R5: Axon, registered to WNC
    "SSID AB2-",     // R14: Axon SSID prefixes, AI-assisted compilation upstream
    "SSID AB3-",
    "SSID AB4-",
    "SSID AXON-",
};

bool pending(const std::string &row)
{
    for (const char *p : kHighPendingReview) if (row == p) return true;
    return false;
}

void report(const std::vector<std::string> &problems)
{
    for (const std::string &p : problems) printf("      %s\n", p.c_str());
    CHECK_INT(0, problems.size());
}

} // namespace

void every_row_names_a_recorded_source_and_commit()
{
    const std::string json = readFile("../sources/registry.json");
    CHECK_TRUE(json.size() > 0);
    const std::set<std::string> ids = registryIds(json);
    CHECK_TRUE(ids.size() >= 3);
    std::vector<std::string> problems;
    auto add = [&](const std::string &s) { if (!s.empty()) problems.push_back(s); };
    for (const OuiSignature &s : kOuiSignatures)
        add(provenanceProblem("OUI " + ouiText(s.oui), s.provenance, ids, json));
    for (const PineappleOuiSignature &s : kPineappleOuis)
        add(provenanceProblem("Pineapple OUI " + ouiText(s.oui), s.provenance, ids, json));
    for (const BleUuidSignature &s : kBleUuidSignatures)
        add(provenanceProblem("UUID " + hex4(s.uuid), s.provenance, ids, json));
    for (const CompanyIdSignature &s : kCompanyIdSignatures)
        add(provenanceProblem("Company " + hex4(s.id), s.provenance, ids, json));
    for (const SsidPrefixSignature &s : kSsidPrefixes)
        add(provenanceProblem(std::string("SSID ") + s.prefix, s.provenance, ids, json));
    for (const BleNamePrefixSignature &s : kBleNamePrefixes)
        add(provenanceProblem(std::string("Name ") + s.prefix, s.provenance, ids, json));
    report(problems);
}

void every_recorded_owner_matches_the_registry_snapshot()
{
    const Snapshot ieee = readSnapshot("../sources/snapshots/ieee_oui.tsv");
    const Snapshot uuids = readSnapshot("../sources/snapshots/bt_sig_uuid16.tsv");
    const Snapshot companies = readSnapshot("../sources/snapshots/bt_sig_company.tsv");
    CHECK_TRUE(!ieee.empty() && !uuids.empty() && !companies.empty());
    std::vector<std::string> problems;
    auto add = [&](const std::string &s) { if (!s.empty()) problems.push_back(s); };
    for (const OuiSignature &s : kOuiSignatures)
        add(ownerProblem(ouiText(s.oui), (s.oui[0] & 0x02) != 0, s.registeredTo, ieee));
    for (const PineappleOuiSignature &s : kPineappleOuis)
        add(ownerProblem(ouiText(s.oui), (s.oui[0] & 0x02) != 0, s.registeredTo, ieee));
    for (const BleUuidSignature &s : kBleUuidSignatures)
        add(ownerProblem(hex4(s.uuid), false, s.registeredTo, uuids));
    for (const CompanyIdSignature &s : kCompanyIdSignatures)
        add(ownerProblem(hex4(s.id), false, s.registeredTo, companies));
    report(problems);
}

void company_constants_are_in_the_company_table()
{
    bool apple = false, xuntong = false;
    for (const CompanyIdSignature &s : kCompanyIdSignatures) {
        apple = apple || s.id == kAppleCompanyId;
        xuntong = xuntong || s.id == kXuntongCompanyId;
    }
    CHECK_TRUE(apple);
    CHECK_TRUE(xuntong);
}

void registry_verified_rows_belong_to_the_detected_vendor()
{
    std::vector<std::string> problems;
    auto add = [&](const std::string &s) { if (!s.empty()) problems.push_back(s); };
    for (const OuiSignature &s : kOuiSignatures)
        add(vendorProblem("OUI " + ouiText(s.oui), s.detector, s.registeredTo, s.provenance.evidence));
    for (const BleUuidSignature &s : kBleUuidSignatures)
        add(vendorProblem("UUID " + hex4(s.uuid), s.detector, s.registeredTo, s.provenance.evidence));
    for (const CompanyIdSignature &s : kCompanyIdSignatures)
        add(vendorProblem("Company " + hex4(s.id), s.detector, s.registeredTo, s.provenance.evidence));
    report(problems);
}

// High raises a wrist alert, so it needs more than one unbacked source.
void high_rows_rest_on_registry_or_field_evidence()
{
    std::vector<std::string> problems;
    std::set<std::string> stillPending;
    auto check = [&](const std::string &row, Confidence c, Evidence e) {
        if (c != Confidence::High || e != Evidence::SingleSource) return;
        if (pending(row)) { stillPending.insert(row); return; }
        problems.push_back(row + " is High on a single source; lower it, or add registry or field evidence");
    };
    for (const OuiSignature &s : kOuiSignatures)
        check("OUI " + ouiText(s.oui), s.confidence, s.provenance.evidence);
    for (const BleUuidSignature &s : kBleUuidSignatures)
        check("UUID " + hex4(s.uuid), s.confidence, s.provenance.evidence);
    for (const SsidPrefixSignature &s : kSsidPrefixes)
        check(std::string("SSID ") + s.prefix, s.confidence, s.provenance.evidence);
    for (const BleNamePrefixSignature &s : kBleNamePrefixes)
        check(std::string("Name ") + s.prefix, s.confidence, s.provenance.evidence);
    for (const char *p : kHighPendingReview)
        if (stillPending.count(p) == 0)
            problems.push_back(std::string(p) + " is no longer High on a single source; remove it from kHighPendingReview");
    for (const char *p : kHighPendingReview) printf("      pending review: %s\n", p);
    report(problems);
}

// The checks above are only worth something if they can fail. Each planted
// mistake here must be caught.
void the_checks_catch_planted_mistakes()
{
    const Snapshot snap = {{"B4:1E:52", "Flock Safety"}, {"28:24:FF", "WNC Corporation"}};
    CHECK_TRUE(ownerProblem("B4:1E:52", false, "Flock Safety", snap).empty());
    CHECK_FALSE(ownerProblem("28:24:FF", false, "Axon Enterprise, Inc.", snap).empty());
    CHECK_FALSE(ownerProblem("12:34:56", false, "Anyone", snap).empty());
    CHECK_FALSE(ownerProblem("02:C0:CA", true, "Hak5", snap).empty());
    CHECK_TRUE(ownerProblem("02:C0:CA", true, kLocallyAdministered, snap).empty());

    const std::string json = "{\"id\": \"real-source\", \"sha\": \"abcdef1234567\"}";
    const std::set<std::string> ids = registryIds(json);
    CHECK_INT(1, ids.size());
    CHECK_TRUE(provenanceProblem("row", {"real-source", "abcdef1", "1.1.0", Evidence::FieldCaptured}, ids, json).empty());
    CHECK_FALSE(provenanceProblem("row", {"made-up", "abcdef1", "1.1.0", Evidence::FieldCaptured}, ids, json).empty());
    CHECK_FALSE(provenanceProblem("row", {"real-source", "", "1.1.0", Evidence::FieldCaptured}, ids, json).empty());
    CHECK_FALSE(provenanceProblem("row", {"real-source", "fedcba9", "1.1.0", Evidence::FieldCaptured}, ids, json).empty());
    CHECK_FALSE(provenanceProblem("row", {"real-source", "abcdef1", "", Evidence::FieldCaptured}, ids, json).empty());
    // A short id found only in the middle of a longer one does not count.
    CHECK_FALSE(provenanceProblem("row", {"real-source", "1234567", "1.1.0", Evidence::FieldCaptured}, ids, json).empty());

    CHECK_TRUE(vendorProblem("row", DetectorId::Flock, "Flock Safety", Evidence::RegistryVerified).empty());
    CHECK_FALSE(vendorProblem("row", DetectorId::Flock, "Liteon Technology Corporation", Evidence::RegistryVerified).empty());
    CHECK_TRUE(vendorProblem("row", DetectorId::Flock, "Liteon Technology Corporation", Evidence::FieldCaptured).empty());
    CHECK_FALSE(vendorProblem("row", DetectorId::Pineapple, "Alfa, Inc.", Evidence::RegistryVerified).empty());
}

int main(int argc, char **argv)
{
    CHECK_MAIN(argc, argv);
    CASE(every_row_names_a_recorded_source_and_commit);
    CASE(every_recorded_owner_matches_the_registry_snapshot);
    CASE(company_constants_are_in_the_company_table);
    CASE(registry_verified_rows_belong_to_the_detected_vendor);
    CASE(high_rows_rest_on_registry_or_field_evidence);
    CASE(the_checks_catch_planted_mistakes);
    CHECK_SUMMARY();
}
