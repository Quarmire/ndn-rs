# BLE Test Applications

End-to-end test applications for verifying NDN-over-BLE across platforms.

## Architecture

Two **GATT peripherals** (producers) and two **GATT centrals** (consumers):

| App | Role | Platform | Framing |
|-----|------|----------|---------|
| `macos/` | Peripheral (producer) | macOS | NDNLPv2 |
| `esp32c3/` | Peripheral (producer) | ESP32-C3 | NDNts 1-byte header |
| `android/` | Central (consumer) | Android | Both (selectable) |
| `ios/` | Central (consumer) | iOS | Both (selectable) |

## Test Scenarios

| Scenario | Peripheral | Client | Framing Mode |
|----------|-----------|--------|--------------|
| A | macOS | Android | NDNLPv2 |
| B | macOS | iOS | NDNLPv2 |
| C | ESP32-C3 | Android | NDNts 1-byte |
| D | ESP32-C3 | iOS | NDNts 1-byte |

## Prerequisites

### macOS app
- Rust toolchain (stable)
- macOS with Bluetooth hardware
- Bluetooth must be enabled in System Settings

### ESP32-C3 app
- Rust stable toolchain with `riscv32imc-unknown-none-elf` target:
  ```sh
  rustup target add riscv32imc-unknown-none-elf
  ```
- `espflash` for flashing:
  ```sh
  cargo install espflash
  ```
- ESP32-C3 development board connected via USB

### Android app
- Android Studio with SDK 26+ and NDK r27+
- `cargo-ndk` for building the Rust JNI library (optional):
  ```sh
  cargo install cargo-ndk
  rustup target add aarch64-linux-android
  ```
- Samsung phone (or any Android device with BLE support)
- BLE permissions granted at runtime

### iOS app
- Xcode 15+ with iOS 17 SDK
- Physical iPhone/iPad (BLE does not work in the simulator)
- Add the BleTest Swift package to an Xcode project, or open it
  with `xed examples/ble/ios/`

## Building and Running

### macOS peripheral

```sh
# From the ndn-rs workspace root:
cargo run -p example-ble-macos

# With debug logging:
RUST_LOG=debug cargo run -p example-ble-macos
```

The app starts a BLE GATT peripheral advertising the NDN service UUID
(`099577e3-...`), then serves Data packets for `/ndn/ble/test`.

### ESP32-C3 peripheral

```sh
cd examples/ble/esp32c3
cargo run           # builds and flashes via espflash
cargo run --release # optimized build
```

The firmware starts a BLE GATT peripheral and responds to Interests
for `/ndn/ble/esp32` with "Hello from ESP32!". Serial output shows
packet exchange status.

**Note:** The ESP32-C3 app contains TODO placeholders for the esp-wifi
BLE event loop integration. The `BlePlatform` implementation and NDN
forwarder logic are complete; the BLE stack initialization depends on
the rapidly-evolving esp-wifi API. See the inline comments and
[esp-hal examples](https://github.com/esp-rs/esp-hal/tree/main/examples)
for the current API surface.

### Android client

1. (Optional) Build the Rust JNI library:
   ```sh
   cd examples/ble/android/rust
   cargo ndk -t arm64-v8a build --release
   # Copy the .so to the Android project:
   mkdir -p ../app/src/main/jniLibs/arm64-v8a
   cp ../../../../target/aarch64-linux-android/release/libndn_ble_test_jni.so \
      ../app/src/main/jniLibs/arm64-v8a/
   ```

2. Build and install the app:
   ```sh
   cd examples/ble/android
   ./gradlew installDebug
   ```

   Or open in Android Studio and run on device.

3. The app works without the Rust JNI library — it includes a pure-Kotlin
   NDN TLV encoder/decoder as a fallback.

### iOS client

1. Open the Swift package in Xcode:
   ```sh
   xed examples/ble/ios/
   ```

2. Select your iPhone as the build target and run.

3. The app includes a pure-Swift NDN TLV encoder/decoder — no Rust
   native library is required for basic testing.

## Test Procedure

1. Start the peripheral (macOS or ESP32-C3)
2. Launch the client app (Android or iOS)
3. Select the framing mode matching your peripheral:
   - **macOS (NDNLPv2)** for the macOS peripheral
   - **ESP32 (NDNts)** for the ESP32-C3 peripheral
4. Tap **Scan** — the NDN BLE service should appear
5. Tap the discovered device to connect
6. Tap **Send Interest**
7. Verify the Data response appears in the log:
   - macOS: `"Hello from macOS! t=<timestamp>"`
   - ESP32: `"Hello from ESP32!"`

## Troubleshooting

### "Bluetooth not available" / no scan results
- Ensure Bluetooth is enabled on both devices
- On Android: grant Location and Bluetooth permissions
- On iOS: grant Bluetooth permission when prompted
- On macOS: ensure no other app has exclusive BLE access

### "NDN BLE service not found"
- The peripheral must be running and advertising
- Check that the service UUID matches: `099577e3-0788-412a-8824-395084d97391`

### "Write FAILED"
- The BLE connection may have dropped — try reconnecting
- Check the MTU negotiation in the log (should be > 50 bytes)

### ESP32 not responding
- Check serial output for errors
- Ensure the BLE stack initialized successfully
- Try power-cycling the ESP32-C3 board

## Protocol Details

### GATT Profile (NDNts-compatible)

| Component | UUID |
|-----------|------|
| Service | `099577e3-0788-412a-8824-395084d97391` |
| CS (client -> server) | `cc5abb89-a541-46d8-a351-2f95a6a81f49` |
| SC (server -> client) | `972f9527-0d83-4261-b95d-b1b2fc73bde4` |

### Framing Modes

**NDNLPv2** (macOS/Linux `BleFace`): Each BLE ATT write carries one
NDNLPv2 `LpPacket` (TLV type 0x64) containing either a complete
Interest/Data or a fragment with sequence/index/count fields.

**NDNts 1-byte header** (ESP32 `EmbeddedBleFace`): First fragment has
header byte `0x80 | seq`; continuation fragments have `seq & 0x7F`.
Unfragmented packets have no header byte.
