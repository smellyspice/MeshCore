// Minimal stub linking the REAL src/Identity.h declarations for native tests
// that need Mesh.cpp/Dispatcher.cpp (which reference LocalIdentity/Identity)
// without pulling in the real Ed25519/ECDH crypto backend (nRF/mbedtls-only,
// not available on the native platform). No test relies on these values
// being cryptographically meaningful -- only on the interfaces linking.
#include <Identity.h>

namespace mesh {

Identity::Identity() {
  memset(pub_key, 0, PUB_KEY_SIZE);
}

Identity::Identity(const char* pub_hex) {
  memset(pub_key, 0, PUB_KEY_SIZE);
}

bool Identity::verify(const uint8_t* sig, const uint8_t* message, int msg_len) const {
  return true;
}

bool Identity::readFrom(Stream& s) { return false; }
bool Identity::writeTo(Stream& s) const { return false; }
void Identity::printTo(Stream& s) const { }

LocalIdentity::LocalIdentity() : Identity() {
  memset(prv_key, 0, PRV_KEY_SIZE);
}

LocalIdentity::LocalIdentity(const char* prv_hex, const char* pub_hex) : Identity(pub_hex) {
  memset(prv_key, 0, PRV_KEY_SIZE);
}

LocalIdentity::LocalIdentity(RNG* rng) : Identity() {
  memset(prv_key, 0, PRV_KEY_SIZE);
}

void LocalIdentity::sign(uint8_t* sig, const uint8_t* message, int msg_len) const {
  memset(sig, 0, SIGNATURE_SIZE);
}

void LocalIdentity::calcSharedSecret(uint8_t* secret, const uint8_t* other_pub_key) const {
  memset(secret, 0, PUB_KEY_SIZE);
}

}
