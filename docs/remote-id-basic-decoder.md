# Passive Remote ID Basic ID decoding

Recognizing the structure of a broadcast gives later analysis an inspectable observation. It does not verify who sent it or whether an aircraft exists nearby.

`lts/RemoteId.h` decodes standalone Basic ID service data for UUID `0xFFFA`, application code `0x0D`, a counter and a 25-byte message. The UUID is supplied separately. Versions 0 through 2 and nonempty identifiers of types 1 through 4 are supported. All 20 identifier bytes are retained, including binary values. Unsupported versions, message packs, other message types, incomplete payloads and empty IDs return false without changing the output. Rejection means unsupported or unusable input, not absence of a drone. No authenticity or location claim is produced.

The wire layout was checked against the upstream [OpenDroneID message definitions](https://github.com/opendroneid/opendroneid-core-c/blob/master/libopendroneid/opendroneid.h) and [Bluetooth service-data example](https://github.com/opendroneid/transmitter-linux/blob/master/bluetooth.c). This small decoder covers Basic ID only and is not a complete Remote ID implementation or conformance certification.

Verification: all 10 isolated native sensor test suites passed. The new decoder suite includes 45 checks for valid and binary identifiers, truncated and oversized payloads, wrong UUID/application/message/version, empty IDs, and unchanged output after rejection. The BLE classifier now accepts a service-data callback and emits sensor DetectorId 18 (core ReconTarget 19) only after payload decoding succeeds. Its `RID1:` detail retains the full service data as hex; UUID/name-only lookalikes do not match. Consumer scanner adapters must supply the callback.
