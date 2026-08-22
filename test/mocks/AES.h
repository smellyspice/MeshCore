#pragma once

#include <stdint.h>
#include <stddef.h>
#include <cstring>

// Mock AES128 for native testing -- a real (reversible), deterministic
// substitute for AES-ECB, not a security primitive. Earlier this class was a
// pure no-op (output buffer left untouched), which meant Utils::encrypt()/
// decrypt() never actually round-tripped in native tests -- fine for tests
// that don't exercise encrypted payloads, but silently breaks anything that
// does (e.g. end-to-end companion-to-companion messaging tests), since the
// data handed to onPeerDataRecv() would be uninitialized garbage instead of
// the real message. XOR-with-key is reversible and enough to validate
// protocol/routing logic, which is all native tests need.
class AES128 {
  uint8_t _key[16];
public:
  void setKey(const uint8_t* key, size_t keySize) {
    memset(_key, 0, sizeof(_key));
    memcpy(_key, key, keySize < sizeof(_key) ? keySize : sizeof(_key));
  }
  void encryptBlock(uint8_t* output, const uint8_t* input) {
    for (int i = 0; i < 16; i++) output[i] = input[i] ^ _key[i];
  }
  void decryptBlock(uint8_t* output, const uint8_t* input) {
    for (int i = 0; i < 16; i++) output[i] = input[i] ^ _key[i];
  }
};
