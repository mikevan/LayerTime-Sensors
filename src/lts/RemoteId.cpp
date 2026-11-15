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

#include "RemoteId.h"
#include <algorithm>
namespace lts {
bool parseRemoteIdBasicServiceData(uint16_t uuid, const uint8_t* data,
                                  size_t size, RemoteIdBasicClaim& out) {
    if (uuid != 0xfffa || data == nullptr || size != 27 || data[0] != 0x0d) return false;
    const uint8_t* message = data + 2;
    const auto version = static_cast<uint8_t>(message[0] & 15);
    const auto type = static_cast<uint8_t>(message[1] >> 4);
    if ((message[0] >> 4) != 0 || version > 2 || type < 1 || type > 4) return false;
    // Empty identifiers cannot support a useful Basic ID claim. Keep all 20
    // bytes (UUID/session IDs are binary); never render them as unchecked text.
    if (std::all_of(message+2,message+22,[](uint8_t b){return b==0;})) return false;
    RemoteIdBasicClaim claim;
    claim.protocolVersion=version; claim.counter=data[1];
    claim.idType=type; claim.aircraftType=message[1] & 15;
    std::copy(message+2,message+22,claim.identifier.begin());
    out=claim;
    return true;
}
}
