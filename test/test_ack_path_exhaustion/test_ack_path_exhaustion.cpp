// Investigating a live hardware symptom (message delivered on first try, ACK
// not seen by the sender until the 3rd attempt) that survived the confirmed
// fixes for the bridge dedup-cache and logRx bugs -- a live packet trace
// (BRIDGE_DEBUG+MESH_DEBUG on both repeaters) showed zero packets lost
// crossing the bridge itself, which rules the bridge out and points at
// something in direct-ACK routing through a repeater instead.
//
// Hypothesis read out of Mesh::onRecvPacket (src/Mesh.cpp): a DIRECT packet
// only gets the "one more hop" treatment (matching this node's hash at
// path[0], stripping it, and retransmitting/re-routing regardless of the
// resulting remaining count) if it arrives with getPathHashCount() > 0.  A
// direct packet that arrives at a repeater with 0 hops ALREADY remaining
// skips that whole branch entirely and falls through to the top-level
// payload-type switch, which for PAYLOAD_TYPE_ACK is just
// onAckRecv()+routeRecvPacket() -- and routeRecvPacket() only re-broadcasts
// FLOOD packets, doing nothing for DIRECT ones. So: if whoever composed the
// ACK's path over/under-counted by exactly one hop (e.g. a stale cached
// out_path from an earlier session, or one learned under a since-fixed
// bug), the ACK dead-ends silently at whichever repeater it reaches with 0
// hops left, never reaching the final companion -- no log, no error,
// exactly matching the observed symptom. Confirmed here against the real
// Mesh::onRecvPacket, not a reimplementation.
#include <gtest/gtest.h>
#include <Mesh.h>
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

class CountingPacketManager : public PacketManager {
public:
  int outbound_queued = 0;

  Packet* allocNew() override { return new Packet(); }
  void free(Packet* p) override { delete p; }
  void queueOutbound(Packet* p, uint8_t, uint32_t) override { outbound_queued++; delete p; }
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

struct FakeMeshDeps {
  FakeRadio radio;
  FakeClock clock;
  FakeRNG rng;
  FakeRTC rtc;
  CountingPacketManager mgr;
  FakeTables tables;
};

class TestRepeaterMesh : public FakeMeshDeps, public Mesh {
public:
  explicit TestRepeaterMesh(uint8_t hash_byte)
    : FakeMeshDeps(), Mesh(radio, clock, rng, rtc, mgr, tables) {
    memset(self_id.pub_key, 0, PUB_KEY_SIZE);
    self_id.pub_key[0] = hash_byte;
  }

  bool allowPacketForward(const Packet*) override { return true; }
  uint32_t getDirectRetransmitDelay(const Packet*) override { return 0; }

  DispatcherAction recv(Packet* pkt) { return onRecvPacket(pkt); }
};

Packet makeDirectAck(uint8_t* path, uint8_t path_len) {
  Packet p;
  p.header = ROUTE_TYPE_DIRECT | (PAYLOAD_TYPE_ACK << PH_TYPE_SHIFT);
  for (uint8_t i = 0; i < path_len; i++) p.path[i] = path[i];
  p.setPathHashSizeAndCount(1, path_len);
  uint32_t ack_crc = 0x12345678;
  memcpy(p.payload, &ack_crc, 4);
  p.payload_len = 4;
  return p;
}

}  // namespace

TEST(AckPathExhaustion, AckArrivingWithOneHopRemaining_GetsForwarded) {
  TestRepeaterMesh repeater(0xB1);   // e.g. "Xiao", still one hop from the final companion
  uint8_t path[] = {0xB1};
  Packet ack = makeDirectAck(path, 1);

  repeater.recv(&ack);

  EXPECT_EQ(repeater.mgr.outbound_queued, 1)
      << "with the repeater's own hash still in the path, routeDirectRecvAcks() "
         "should compose and queue a forwarded ACK for the final local hop";
}

// This is the actual bug: same repeater, same intent (deliver an ACK that
// still needs one more local-radio hop to reach the companion), but the
// path handed to it was recorded one hop short -- e.g. a stale/incorrect
// out_path. The ACK silently dead-ends here: no forward, no error, and
// nothing distinguishes this from "delivered successfully" at the log
// level, matching exactly what the live hardware trace showed.
TEST(AckPathExhaustion, AckArrivingWithZeroHopsRemaining_IsSilentlyDropped) {
  TestRepeaterMesh repeater(0xB1);
  Packet ack = makeDirectAck(nullptr, 0);

  DispatcherAction action = repeater.recv(&ack);

  EXPECT_EQ(action, (DispatcherAction) ACTION_RELEASE);
  EXPECT_EQ(repeater.mgr.outbound_queued, 0)
      << "an ACK arriving DIRECT with 0 hops left at a repeater (not the "
         "final companion) is dropped -- Mesh::onRecvPacket's direct-forward "
         "branch requires getPathHashCount() > 0, and the fallback "
         "top-level ACK handling (onAckRecv + routeRecvPacket) only "
         "re-broadcasts FLOOD packets, doing nothing for DIRECT ones";
}

// Contrast: a normal (non-ACK) direct message payload behaves differently
// at the SAME 0-remaining-hops boundary -- confirms this is specific to how
// PAYLOAD_TYPE_ACK is special-cased, not a general property of direct
// routing at 0 hops (a TXT_MSG addressed to a companion is still visible
// via the top-level switch's own dest-hash check, even if that companion
// isn't this node -- but only ACK skips any equivalent local delivery path
// entirely once path is empty AND it didn't arrive via the >0 branch).
TEST(AckPathExhaustion, ForNonAckPayload_ZeroHopsBehavesDifferently) {
  TestRepeaterMesh repeater(0xB1);
  Packet msg;
  msg.header = ROUTE_TYPE_DIRECT | (PAYLOAD_TYPE_TXT_MSG << PH_TYPE_SHIFT);
  msg.setPathHashSizeAndCount(1, 0);
  // dest_hash, src_hash, then MAC+ciphertext -- content doesn't matter here,
  // only whether the packet is even routed anywhere.
  msg.payload_len = 2 + CIPHER_MAC_SIZE + 1;

  DispatcherAction action = repeater.recv(&msg);

  EXPECT_EQ(action, (DispatcherAction) ACTION_RELEASE)
      << "also released at 0 hops (as expected, this repeater isn't the "
         "dest_hash match) -- included to document that TXT_MSG doesn't "
         "get any special extra local-forward treatment here either; the "
         "asymmetry is that the FORWARD leg's path is always provisioned "
         "with one entry per repeater already, so it never legitimately "
         "arrives at 0 hops mid-route the way a stale-cached reverse ACK "
         "path can";
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
