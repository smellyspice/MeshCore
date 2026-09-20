# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## About

MeshCore is a lightweight, portable C++ library implementing multi-hop packet routing for embedded LoRa devices (ESP32, nRF52, RP2040, STM32), built on PlatformIO/Arduino. It targets 50+ hardware variants and produces several firmware "roles" (companion radio, repeater, room server, sensor node, KISS modem) from the same core.

## Build system

Built with PlatformIO. Board/radio combinations are defined per-variant under `variants/<name>/platformio.ini` and pulled in automatically via `extra_configs` in the root `platformio.ini`. Each variant file defines a base env (pins, radio chip, board) plus one `[env:...]` per firmware role (e.g. `Heltec_v3_repeater`, `Heltec_v3_companion_radio_ble`).

List all buildable environments:
```bash
pio project config | grep 'env:'
# or
sh build.sh list
```

Build a single firmware target (requires `FIRMWARE_VERSION` env var):
```bash
export FIRMWARE_VERSION=v1.0.0
sh build.sh build-firmware Heltec_v3_repeater
```
Output binaries land in `out/`. For ESP32 targets this also runs `mergebin` to produce a flash-ready merged .bin; for nRF52 it produces a .uf2/.zip; for STM32/RP2040 it copies .bin/.hex/.uf2.

Other build.sh subcommands: `build-firmwares` (everything), `build-matching-firmwares <substring>`, `build-companion-firmwares`, `build-repeater-firmwares`, `build-room-server-firmwares`, `build-kiss-radio-firmwares`.

Set `DISABLE_DEBUG=1` to strip debug logging flags (`MESH_DEBUG`, `BLE_DEBUG_LOGGING`, `WIFI_DEBUG_LOGGING`, `BRIDGE_DEBUG`, etc.) from the build.

Raw `pio run -e <env>` also works directly once a target environment name is known.

## Tests

Unit tests run against the `native` platform (no hardware needed), using GoogleTest:
```bash
pio test --environment native --verbose
```
There is a separate `native_kiss_modem` environment for the KISS modem example (`test_kiss_modem` test suite is excluded from the main `native` env via `test_ignore`).

Test suites live under `test/` (e.g. `test_utils`, `test_mesh_tables`, `test_routing_policy`, `test_config_serializer`, `test_utf8_helpers`, `test_companion_node_prefs`, `test_kiss_modem`), with shared fakes in `test/mocks`. To run a single suite, use PlatformIO's `-f` filter or `test_filter`/`test_ignore` in `platformio.ini`.

## Architecture

**Core library (`src/`)** — hardware/framework-agnostic mesh networking stack:
- `Packet.h/.cpp` — wire packet format.
- `Dispatcher.h/.cpp` — base radio TX/RX task: manages the packet queue, timing/airtime, and dispatches received packets.
- `Mesh.h/.cpp` — extends `Dispatcher`; understands payload *types* and provides virtual hooks for subclasses to handle inbound packets and prepare outbound ones. Also defines `MeshTables` (duplicate-packet tracking) as a virtual interface.
- `Identity.h/.cpp` — public/private key identity and signing.
- `Utils.h/.cpp` — misc helpers (also compiled into the `native` test env).
- `MeshCore.h` — shared constants (packet sizes, key sizes, hash sizes, debug print macros) included everywhere.

**`src/helpers/`** — reusable building blocks layered on the core, shared across example firmwares: `BaseChatMesh` (chat-oriented mesh subclass used by companion/chat examples), `ClientACL`, `CommonCLI` (shared serial CLI command handling), `ConfigSerializer`, `IdentityStore`, `RoutingPolicy`, `StaticPoolPacketManager` (no-dynamic-allocation packet pool), `TransportKeyStore`, `AdvertDataHelpers`, `TxtDataHelpers`, plus platform subfolders (`esp32/`, `nrf52/`, `stm32/`, `ethernet/`, `radiolib/`, `sensors/`, `ui/`, `bridges/`) containing board/radio-specific implementations behind common interfaces (e.g. `BaseSerialInterface`, `AbstractBridge`, `RTC_RX8130CE`).

**`examples/`** — the actual firmware entry points, each a distinct "role" built as a `.cpp` compiled into a variant's PlatformIO env via `build_src_filter`:
- `companion_radio` — BLE/USB/WiFi companion firmware for chat apps (`MyMesh`, `NodePrefs`, `DataStore`, plus swappable UI implementations in `ui-new`/`ui-orig`/`ui-tiny`).
- `simple_repeater` — relay-only node (no chat).
- `simple_room_server` — BBS-style shared post server.
- `simple_secure_chat` — terminal chat example.
- `simple_sensor` — telemetry/sensor node.
- `kiss_modem` — serial KISS protocol bridge (has its own native test env).

**`variants/<board>/`** — one directory per physical board, each with `platformio.ini` (pin mappings, radio chip selection via `RADIO_CLASS`/`WRAPPER_CLASS`, board-specific `build_flags`), `target.h/.cpp` (board bring-up), and a `*Board.h` (implements board interface, e.g. power/GPIO). Radio chip and pin flags (`P_LORA_*`, `USE_SX1262`, etc.) here determine what RadioLib backend gets compiled in from `src/helpers/radiolib/`.

**`boards/`** — PlatformIO board JSON definitions (memory layout, upload config) for custom boards not in upstream PlatformIO.

**`arch/`** — per-architecture extra build scripts/libraries (`arch/esp32/AsyncElegantOTA`, `arch/stm32/build_hex.py` + `Adafruit_LittleFS_stm32`).

To add a new firmware role or radio feature, the layering to understand is: `Dispatcher` (raw radio I/O/timing) → `Mesh` (packet-type semantics) → `helpers/` (feature-specific reusable logic) → `examples/*` (concrete firmware, wires everything together in `main.cpp`) → `variants/*` (per-board pins/radio selection glueing an example to a PlatformIO env).

## Project conventions (from CONTRIBUTING.md)

- Base branch for PRs is `dev`, not `main`.
- Embedded-first style: no dynamic memory allocation except during setup/begin functions; avoid unnecessary abstraction layers.
- Match existing brace/indent style (`.clang-format` exists but do NOT reformat existing code — it creates noisy diffs).
- 2-space indent, `camelCase` functions/variables, `UpperCamelCase` classes, `ALL_CAPS` `#define` constants.
- One feature/fix per PR. Larger changes need an issue + rough maintainer sign-off first.
- New public-API changes should update `README.md` and `library.json`/`library.properties`; new features should include an example sketch.

## Release process (fork betas: `trifecta-betaN`)

Betas are tagged on the active dev branch (currently `espnow-ip-bridge`), pushed to the `fork` remote (`smellyspice/MeshCore`), and published as GitHub pre-releases with built binaries attached.

**This section is a summary, not the full process.** Before cutting any release, read `planning/beta-release-process.md` in full — it has the mandatory pre-push PII/secrets check (real SSIDs/passwords, binary `strings` scan, commit/tag message scan) and the current release asset list, neither of which is repeated here.

**Tagging gotcha that has bitten before:** `git tag <name>` with no explicit ref tags whatever `HEAD` happens to be for the *current checkout* — if the working directory isn't actually on the intended branch (e.g. it silently ended up on `main`/`fork/main`, which is a stale, rarely-updated pointer), the tag silently lands on the wrong, often much older, commit. The push and release creation both succeed either way, so nothing errors — the mistake is invisible unless checked for.

Before tagging a release, always verify explicitly:
1. `git branch --show-current` — confirm it's the intended dev branch, not `main`.
2. `git rev-parse HEAD` and `git log -1 --format='%H %cI %s' HEAD` — confirm the commit and its message match what the release notes describe.
3. Create the tag against that resolved SHA explicitly (`git tag <name> <sha>`), not a bare `git tag <name>`.
4. After tagging, `git log -1 <tag>` — confirm it shows the same commit as step 2 before pushing.

After publishing, verify the release actually landed correctly — don't trust a successful `gh release create` exit code alone:
- `gh release view <tag> --json tagName,isDraft,isPrerelease,publishedAt,assets` — confirm not a draft, has the expected asset count.
- `gh api repos/<owner>/<repo>/releases | jq '.[0].tag_name'` (or check the releases page) — confirm the new release actually sorts first. GitHub sorts the releases list by the **tagged commit's date**, not by upload/publish time — a tag on an old commit gets buried out of view on the releases page even though the release itself is live, published, and fully intact. This is exactly how `trifecta-beta14` went missing the first time: tagged on stale `fork/main` (a commit from weeks earlier), so it silently sorted to the bottom of the list instead of erroring.

## Checking whether a feature already shipped

**Before concluding a feature isn't implemented, check the real changelog — don't rely on a source grep alone.** Every `trifecta-betaN` tag's annotated message is a genuine per-release changelog entry describing exactly what shipped (e.g. `git tag -l 'trifecta-beta*' -n99`, or `git tag -l --format='%(contents)' trifecta-beta14` for one). All of beta3 through the current beta are ancestors of every active dev branch. The `promo` branch also has public-facing per-feature pages (`git show promo:trifecta.html`, `sidecar.html`, `echo-board.html`) describing shipped functionality in user terms.

A source grep that finds nothing means the grep missed it (wrong keyword, feature lives behind a runtime flag, different naming) far more often than it means the feature is absent — this fork has shipped 16+ betas of exactly this kind of change. Check the tag messages before telling the user a feature doesn't exist.

## Working conventions (standing rules, not per-task requests)

Personal hardware-fleet config and working-style preferences live in `CLAUDE.local.md` (gitignored, not part of this public repo) — read it too.

**Before changing anything in `src/`, `helpers/`, or another file shared across firmware roles:** enumerate every caller/consumer across `examples/*` (and any `variants/*` build flags that alter its behavior) before editing, not after. This codebase has repeatedly broken in a different role/layer than the one being changed — `region default` silently broke propagation through unconfigured repeaters, and switching `bridge.source` to `logRx` silently truncated DIRECT-route paths learned two layers away. A change that looks locally correct is not enough; state explicitly what else touches the changed function/state and what happens to each of those call sites before calling a change safe.
