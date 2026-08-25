// When a companion (B) receives someone's (A's) message as a FLOOD packet,
// B's own reply (an ACK, carrying a reciprocal path so A can reach B
// directly next time) is itself flooded back -- but nothing in that
// exchange gives B a direct path back to A. B's out_path to A stays unknown
// until B independently receives an explicit PATH packet from A. A plain
// protocol property of BaseChatMesh, no bridge involved.
//
// Runs the real production BaseChatMesh::onPeerDataRecv(), not a
// reimplementation.
#include <gtest/gtest.h>
#include <helpers/BaseChatMesh.h>
#include <cstring>

using namespace mesh;

namespace {

class FakeRadio : public Radio {
public:
  int recvRaw(uint8_t*, int) override { return 0; }
  uint32_t getEstAirtimeFor(int) override { return 10; }
  float packetScore(float, int) override { return 1.0f; }
  bool startSendRaw(const uint8_t*, int) override { return true; }
  bool isSendComplete() override { return true; }
  void onSendFinished() override {}
  bool isInRecvMode() const override { return true; }
};

class FakeClock : public MillisecondClock {
public:
  unsigned long getMillis() override { return 0; }
};

class FakeRTC : public RTCClock {
public:
  uint32_t getCurrentTime() override { return 1000; }
  void setCurrentTime(uint32_t) override {}
};

class FakeRNG : public RNG {
public:
  void random(uint8_t* dest, size_t sz) override { memset(dest, 0, sz); }
};

class FakePacketManager : public PacketManager {
public:
  Packet* allocNew() override { return new Packet(); }
  void free(Packet* p) override { delete p; }
  void queueOutbound(Packet*, uint8_t, uint32_t) override {}
  Packet* getNextOutbound(uint32_t) override { return nullptr; }
  int getOutboundCount(uint32_t) const override { return 0; }
  int getOutboundTotal() const override { return 0; }
  int getFreeCount() const override { return 100; }
  Packet* getOutboundByIdx(int) override { return nullptr; }
  Packet* removeOutboundByIdx(int) override { return nullptr; }
  void queueInbound(Packet*, uint32_t) override {}
  Packet* getNextInbound(uint32_t) override { return nullptr; }
};

class FakeTables : public MeshTables {
public:
  bool wasSeen(const Packet*) override { return false; }
  void markSeen(const Packet*) override {}
  void clear(const Packet*) override {}
};

// See BridgeDirectPathCrossing test: base classes construct before derived
// members, so these must live ahead of BaseChatMesh in the inheritance list.
struct FakeMeshDeps {
  FakeRadio radio;
  FakeClock clock;
  FakeRNG rng;
  FakeRTC rtc;
  FakePacketManager mgr;
  FakeTables tables;
};

class TestChatMesh : public FakeMeshDeps, public BaseChatMesh {
public:
  int flood_scoped_calls = 0;

  TestChatMesh() : FakeMeshDeps(), BaseChatMesh(radio, clock, rng, rtc, mgr, tables) {}

  // pure virtuals -- no-op stubs, not under test here
  void onDiscoveredContact(ContactInfo&, bool, uint8_t, const uint8_t*) override {}
  ContactInfo* processAck(const uint8_t*) override { return nullptr; }
  void onContactPathUpdated(const ContactInfo&) override {}
  void onMessageRecv(const ContactInfo&, Packet*, uint32_t, const char*) override {}
  void onCommandDataRecv(const ContactInfo&, Packet*, uint32_t, const char*) override {}
  void onSignedMessageRecv(const ContactInfo&, Packet*, uint32_t, const uint8_t*, const char*) override {}
  uint32_t calcFloodTimeoutMillisFor(uint32_t) const override { return 5000; }
  uint32_t calcDirectTimeoutMillisFor(uint32_t, uint8_t) const override { return 5000; }
  void onSendTimeout() override {}
  void onChannelMessageRecv(const GroupChannel&, Packet*, uint32_t, const char*) override {}
  uint8_t onContactRequest(const ContactInfo&, uint32_t, const uint8_t*, uint8_t, uint8_t*) override { return 0; }
  void onContactResponse(const ContactInfo&, const uint8_t*, uint8_t) override {}

  // Records instead of actually transmitting, so the test can observe
  // whether/how B tries to reply, without a real radio/dispatcher loop.
  void sendFloodScoped(const ContactInfo&, Packet* pkt, uint32_t) override {
    flood_scoped_calls++;
    if (pkt) releasePacket(pkt);
  }

  // exposes the protected production method under test
  void recvPeerData(Packet* packet, uint8_t type, int sender_idx, const uint8_t* secret, uint8_t* data, size_t len) {
    onPeerDataRecv(packet, type, sender_idx, secret, data, len);
  }

  bool addTestContact(const ContactInfo& ci) { return addContact(ci); }
  ContactInfo* lookup(const uint8_t* pub_key) { return lookupContactByPubKey(pub_key, PUB_KEY_SIZE); }
};

ContactInfo makeContact(uint8_t key_byte) {
  ContactInfo ci;
  memset(&ci, 0, sizeof(ci));
  memset(ci.id.pub_key, 0, PUB_KEY_SIZE);
  ci.id.pub_key[0] = key_byte;
  ci.type = ADV_TYPE_CHAT;
  strcpy(ci.name, "A");
  ci.out_path_len = OUT_PATH_UNKNOWN;
  ci.lastmod = 1000;
  return ci;
}

}  // namespace

// B (this node) receives a FLOOD text message from A, whose path it just
// travelled is embedded in the packet. B has no prior contact/path info for A.
TEST(OutPathAsymmetry, ReceivingAFloodDoesNotTeachUsAPathBackToTheSender) {
  TestChatMesh b;

  ContactInfo a = makeContact(0xAA);
  ASSERT_TRUE(b.addTestContact(a));
  ContactInfo* stored = b.lookup(a.id.pub_key);
  ASSERT_NE(stored, nullptr);
  ASSERT_EQ(stored->out_path_len, OUT_PATH_UNKNOWN) << "sanity: starts unknown";

  // A FLOOD packet that accumulated a 2-hop path getting to B.
  Packet pkt;
  pkt.header = ROUTE_TYPE_FLOOD | (PAYLOAD_TYPE_TXT_MSG << PH_TYPE_SHIFT);
  pkt.path[0] = 0x11;
  pkt.path[1] = 0x22;
  pkt.setPathHashSizeAndCount(1, 2);
  pkt.payload_len = 0;

  // Decrypted TXT_MSG payload: 4-byte timestamp + 1 flags byte (TXT_TYPE_PLAIN
  // is 0, stored in upper 6 bits) + text, matching what onRecvPacket would
  // have handed to onPeerDataRecv after a real decrypt.
  uint8_t data[32];
  memset(data, 0, sizeof(data));
  const char* text = "hi";
  strcpy((char*)&data[5], text);
  size_t len = 5 + strlen(text);

  uint8_t secret[PUB_KEY_SIZE];
  memset(secret, 0x11, sizeof(secret));

  b.recvPeerData(&pkt, PAYLOAD_TYPE_TXT_MSG, /*sender_idx (matches addContact's slot 0)*/ 0, secret, data, len);

  // B DID try to reply (with an ACK carrying A's return path) -- confirming
  // the exchange wasn't simply skipped.
  EXPECT_EQ(b.flood_scoped_calls, 1)
      << "B should still flood back a PATH-return ACK for A's message";

  // But B's own stored path to reach A directly is untouched: nothing in
  // this exchange taught B a route back to A. This is the asymmetry theory 4
  // describes -- A will learn a direct path to B from this ACK, but B still
  // has none for A, and won't until B independently receives a PATH packet
  // from A.
  stored = b.lookup(a.id.pub_key);
  ASSERT_NE(stored, nullptr);
  EXPECT_EQ(stored->out_path_len, OUT_PATH_UNKNOWN)
      << "receiving A's flood message must not, by itself, give B a path back to A";
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
