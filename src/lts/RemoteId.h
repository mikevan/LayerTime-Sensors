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
#include <stddef.h>
#include <stdint.h>
#include <array>
namespace lts {
// A decoded, unverified broadcast claim. No aircraft presence/authenticity inference.
struct RemoteIdBasicClaim {
    uint8_t protocolVersion = 0;
    uint8_t counter = 0;
    uint8_t idType = 0;
    uint8_t aircraftType = 0;
    std::array<uint8_t,20> identifier{};
};
// serviceData excludes the UUID, includes application code + counter + message.
// Supports standalone Basic ID v0..2, ID types 1..4. Packs and other message
// types are unsupported, not malformed Basic IDs. Output is unchanged on failure.
bool parseRemoteIdBasicServiceData(uint16_t uuid, const uint8_t* serviceData,
                                  size_t size, RemoteIdBasicClaim& out);
}
