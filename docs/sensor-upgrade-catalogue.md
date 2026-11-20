# Sensor upgrade catalogue

Reviewed 2026-11-20. This records the approved upstream review, the value to LayerTime, implementation status, and hardware or license constraints. Upstream commits are evidence to review; they do not imply code was imported.

## Implemented in 1.1.3

| Change | Source and credit | Value and limit | Status |
|---|---|---|---|
| DJI Wi-Fi presence lead | Isaac Bentley, [Orecchino ESP32, commit a3d0620](https://github.com/isaacbentley/orecchino-esp32/commit/a3d06206010e66d5295ad36e167e100d2c0670c6) | Low-confidence match on 0C:9A:E6 in Wi-Fi beacons and probe responses. It reports a vendor prefix only; it does not identify an aircraft, locate it, determine intent, or decode Remote ID. | Added as detector 18 with replay tests. Needs owned-device RF captures and false-positive evaluation before alert use. |

## Approved additions for evaluation

| Area | Upstream changes and credit | Value | Requirement and status |
|---|---|---|---|
| Drone Remote ID | OpenDroneID core C; Mattbusel’s [remoteid](https://github.com/Mattbusel/remoteid), linked from OpenDroneID; and Just Call Me Koko’s [Remote ID Radar](https://github.com/justcallmekoko/wifipineapplepager-payloads/tree/submission/remote-id-radar), branch commit [`fdabf88`](https://github.com/justcallmekoko/wifipineapplepager-payloads/commit/fdabf882155be0e228a686d168c6e7e6dd3e1abf) | A standards-based BLE and Wi-Fi Remote ID decoder. Remote ID Radar provides an independent Python port of ESP32 Marauder behavior, fixtures, and a Pager UI/logger; useful as a cross-check and source of replay cases. | Compare its tests and behavior with Rust `remoteid` and OpenDroneID before choosing a C++ implementation. Pager payload is GPL-3.0-only, derived from ESP32 Marauder, and uses Wi-Fi channel 6 plus stock BLE scanning; it is not drop-in Hunter firmware. Evaluation only; no code imported. |
| Sub-GHz sensor protocols | [rtl_433](https://github.com/merbanan/rtl_433/commit/f76ec77b581bd1c01857aac3f0976615cb8dad11) Elsys ERS LoRaWAN; [Bresser](https://github.com/merbanan/rtl_433/commit/f15b67699e902522014e7593d060ad37410eda00); [Paradox](https://github.com/merbanan/rtl_433/commit/1190337c2abeedf98d68f4d6b159db640198084c); RainPoint and EN2058 fixes | More environmental, alarm, and utility observations. | Requires a compatible sub-GHz receiver. rtl_433 is GPL-2.0-or-later; review compatibility and attribution before any code copy. Catalogue only. |
| Optional hardware drivers | [Zephyr](https://github.com/zephyrproject-rtos/zephyr) adds BMA400, ADIS16607, ADXL373, STC31 CO2, and TSL2522; [ESPHome](https://github.com/esphome/esphome) adds VL6180X, BMI270, and MLX fixes; [ST MEMS drivers](https://github.com/STMicroelectronics) updates LSM6 APIs | Keeps the catalogue current for possible motion, gas, light, and distance sensors. | Driver inventory only. These parts are not claimed as fitted or supported by current LayerTime devices. Check each license, wiring, and power budget first. |
| RF activity options | [LilyGoLib CC1101 RSSI scan](https://github.com/Xinyuan-LilyGO/LilyGoLib/commit/875da656aed6902cd51e33a26ba8a52dec69766e); [nRF24 channel scan](https://github.com/Xinyuan-LilyGO/LilyGoLib/commit/932af78062aa8893f5b7bec0b4c37a5a508fc03c) | Adds channel-energy/activity observations for compatible equipment. | Separate hardware options; activity does not identify a device or prove a drone. Compatibility and license review required. |
| External radiation instrument | [RadPro GQ GMC-800 V2](https://github.com/Gissio/radpro/commit/9113c99d7a33081b9ac7034c1f70bdc26c73be51) | Potential integration of a documented instrument and tube-sensitivity correction. | Optional catalogue entry. No radiation hardware is claimed on the watch or Hunter; validate device model and calibration before showing readings. |

## Evidence and credit policy

- Credit the repository owner and link the exact commit in release notes. `SOURCES.md` and `sources/registry.json` are the machine-readable and human-readable attribution records.
- Review licenses before copying code. A catalogue entry does not import implementation code.
- Presence is not intent. A vendor prefix is not aircraft identity or location.
- Software replay tests validate classification from supplied bytes. They do not validate RF acquisition, antenna behavior, radio coexistence, or field false-positive rates.
