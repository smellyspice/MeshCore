#pragma once

#include <stdint.h>
#include <stddef.h>

// Mock SHA256 for native testing — deterministic but not cryptographic.
// finalize() writes real (non-garbage) output so calculatePacketHash() produces
// distinguishable results for packets with different payloads.
#include <string.h>

class SHA256 {
  uint8_t _state[32];
  size_t _len;
public:
  SHA256() : _len(0) { memset(_state, 0, sizeof(_state)); }

  void update(const void* data, size_t len) {
    const uint8_t* bytes = static_cast<const uint8_t*>(data);
    for (size_t i = 0; i < len; i++) {
      uint8_t b = bytes[i];
      _state[_len % 32] ^= b;
      _state[(_len + 1) % 32] += (uint8_t)((b >> 1) | (b << 7));
      _len++;
    }
  }

  void finalize(uint8_t* hash, size_t hashLen) {
    for (size_t i = 0; i < hashLen; i++) {
      hash[i] = _state[i % 32];
    }
  }

  // Previously both no-ops: finalizeHMAC never wrote its output buffer, so
  // MACThenDecrypt()'s HMAC comparison always compared against uninitialized
  // stack garbage on both sides and (astronomically reliably) never matched
  // -- meaning any test exercising real encrypted payload decrypt (TXT_MSG/
  // REQ/RESPONSE/PATH) would silently fail before ever reaching application
  // logic. Deterministic but not cryptographic, same spirit as finalize()
  // above: real enough to round-trip correctly for two parties sharing the
  // same key, wrong for anyone who doesn't.
  void resetHMAC(const uint8_t* key, size_t keyLen) {}
  void finalizeHMAC(const uint8_t* key, size_t keyLen, uint8_t* hash, size_t hashLen) {
    for (size_t i = 0; i < hashLen; i++) {
      hash[i] = _state[i % 32] ^ key[i % keyLen];
    }
  }
};
