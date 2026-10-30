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

// Where each signature row came from, and how strong the evidence behind it
// is. Every row in Signatures.h carries one.
//
// The sources named here are listed, linked, and thanked in
// sources/registry.json and SOURCES.md. test_sources checks that every row
// names a source that exists there, and checks each row's recorded registry
// owner against the pinned IEEE and Bluetooth SIG snapshots in sources/.

#include <stdint.h>

namespace lts {

enum class Evidence : uint8_t {
    // The official registry (IEEE for address prefixes, the Bluetooth SIG
    // for company IDs and 16-bit UUIDs) assigns the identifier to the vendor
    // the row detects.
    RegistryVerified = 0,
    // A named source reports capturing it from real devices, in the field or
    // from a firmware image.
    FieldCaptured = 1,
    // One source lists it, with no registry support and no published
    // captures.
    SingleSource = 2,
};

struct Provenance {
    const char *source;  // the source's id in sources/registry.json
    const char *commit;  // the source commit the row was taken from; "" when none was recorded
    const char *since;   // the library version that first carried the row
    Evidence evidence;
};

// The registry owner recorded for identifiers that no single vendor owns.
inline constexpr const char *kUnassigned = "UNASSIGNED";
inline constexpr const char *kLocallyAdministered = "LOCALLY ADMINISTERED";
inline constexpr const char *kMediumBlock = "IEEE MA-M BLOCK";

} // namespace lts
