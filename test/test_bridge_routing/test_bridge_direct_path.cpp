// Reproduces (against the REAL production Mesh::onRecvPacket/removeSelfFromPath,
// not a reimplementation) the bridge direct-path-crossing bug described in
// planning/bridge-direct-routing-path-gap.md: a DIRECT-routed packet's path[]
// is only in a state the far side of a bridge can consume if the local hop's
// hash has already been stripped before the bridge mirrors it out. Whether
// that's true is currently an accident of `bridge_pkt_src` timing (logRx vs
// logTx in examples/simple_repeater/MyMesh.cpp), not anything coordinated.
//
// No hardware, no radio, no serial port: two in-process Mesh instances stand
// in for RepeaterA/RepeaterB, and a bridge crossing is simulated by handing
// one repeater's packet object directly to the other's onRecvPacket(), at
// the two different points in the pipeline that logRx (before onRecvPacket)
// and logTx (after it) would have captured it.
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
  uint32_t getCurrentTime() override { return 0; }
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

// Mesh's constructor takes these by reference and uses them immediately
// (e.g. Dispatcher's ctor calls ms.getMillis()), so they must be fully
// constructed before the Mesh base class is -- which requires them to live
// in a base class ahead of Mesh in the inheritance list, not as ordinary
// derived-class members (those wouldn't exist yet when Mesh(...) runs).
struct FakeMeshDeps {
  FakeRadio radio;
  FakeClock clock;
  FakeRNG rng;
  FakeRTC rtc;
  FakePacketManager mgr;
  FakeTables tables;
};

// A repeater: forwards anything addressed to it (mirrors MyMesh::allowPacketForward
// returning true for repeaters), exposes the protected onRecvPacket() for the test.
class TestRepeaterMesh : public FakeMeshDeps, public Mesh {
public:
  TestRepeaterMesh(uint8_t hash_byte)
    : FakeMeshDeps(), Mesh(radio, clock, rng, rtc, mgr, tables) {
    memset(self_id.pub_key, 0, PUB_KEY_SIZE);
    self_id.pub_key[0] = hash_byte;   // path hashes are just a prefix of pub_key
  }

  bool allowPacketForward(const Packet*) override { return true; }
  uint32_t getDirectRetransmitDelay(const Packet*) override { return 0; }

  DispatcherAction recv(Packet* pkt) { return onRecvPacket(pkt); }
};

Packet makeDirectTextPacket(uint8_t hop1, uint8_t hop2) {
  Packet p;
  p.header = ROUTE_TYPE_DIRECT | (PAYLOAD_TYPE_TXT_MSG << PH_TYPE_SHIFT);
  p.path[0] = hop1;
  p.path[1] = hop2;
  p.setPathHashSizeAndCount(1, 2);
  p.payload_len = 0;   // direct-forward branch never inspects payload contents
  return p;
}

}  // namespace

// Topology: CompanionA -> RepeaterA(0xAA) <-bridge-> RepeaterB(0xBB) -> CompanionB
// A already has a learned out_path=[0xAA, 0xBB] and sends its DM DIRECT.

TEST(BridgeDirectPathCrossing, LogRxTimingMirrorsBeforeStrip_FarSideSilentlyDrops) {
  TestRepeaterMesh repeaterB(0xBB);

  // logRx fires BEFORE RepeaterA's onRecvPacket runs, so this is the exact
  // byte state a logRx-mode bridge (bridge_pkt_src=1) mirrors to RepeaterB:
  // RepeaterA's own hash is still at the head of path[].
  Packet mirroredAtRx = makeDirectTextPacket(0xAA, 0xBB);

  DispatcherAction action = repeaterB.recv(&mirroredAtRx);

  EXPECT_EQ(action, (DispatcherAction) ACTION_RELEASE)
      << "RepeaterB's hash isn't at path[0] (RepeaterA's still is), so the "
         "real self_id.isHashMatch() check fails and the packet is silently "
         "released -- no log, no error, matching the reported symptom.";
  // path is untouched: confirms nothing about this drop is visible/logged.
  EXPECT_EQ(mirroredAtRx.getPathHashCount(), 2);
}

TEST(BridgeDirectPathCrossing, LogTxTimingMirrorsAfterStrip_FarSideForwardsCorrectly) {
  TestRepeaterMesh repeaterA(0xAA);
  TestRepeaterMesh repeaterB(0xBB);

  Packet pkt = makeDirectTextPacket(0xAA, 0xBB);

  // RepeaterA actually processes it first (real production onRecvPacket):
  // matches path[0]==0xAA, strips itself via the real removeSelfFromPath().
  DispatcherAction actionA = repeaterA.recv(&pkt);
  ASSERT_NE(actionA, (DispatcherAction) ACTION_RELEASE)
      << "sanity check: RepeaterA should accept and forward this packet";
  ASSERT_EQ(pkt.getPathHashCount(), 1);
  ASSERT_EQ(pkt.path[0], 0xBB);

  // logTx fires only after this point (Dispatcher queues/sends the packet in
  // this already-mutated state) -- so this is exactly what a logTx-mode
  // bridge (bridge_pkt_src=0, the default) mirrors to RepeaterB.
  DispatcherAction actionB = repeaterB.recv(&pkt);

  EXPECT_NE(actionB, (DispatcherAction) ACTION_RELEASE)
      << "RepeaterB's hash IS at path[0] in this timing, so it accepts and "
         "forwards -- this is the 'logTx happens to work' behavior, which is "
         "incidental to bridge_pkt_src timing, not a designed guarantee.";
  EXPECT_EQ(pkt.getPathHashCount(), 0)
      << "both hops now consumed -- packet is ready for RepeaterB's local "
         "(non-bridged) hop to CompanionB";
}

// Validates fix direction #3 from the planning doc: always strip the local
// hop before handing a packet to a bridge, independent of bridge_pkt_src.
// If RepeaterA's hop is stripped before mirroring even in logRx timing, the
// far side should behave identically to the logTx case above.
TEST(BridgeDirectPathCrossing, StrippingLocalHopBeforeMirror_FixesLogRxTiming) {
  TestRepeaterMesh repeaterB(0xBB);

  Packet pkt = makeDirectTextPacket(0xAA, 0xBB);

  // Simulate "always strip before bridging" applied at logRx time, without
  // going through RepeaterA's own onRecvPacket (which would also schedule a
  // pointless local LoRa retransmit RepeaterB can't hear in this topology).
  // This mirrors exactly what Mesh::removeSelfFromPath does.
  ASSERT_EQ(pkt.path[0], 0xAA);
  pkt.setPathHashCount(pkt.getPathHashCount() - 1);
  memmove(&pkt.path[0], &pkt.path[1], pkt.getPathHashCount());

  DispatcherAction action = repeaterB.recv(&pkt);

  EXPECT_NE(action, (DispatcherAction) ACTION_RELEASE)
      << "with the local hop pre-stripped, RepeaterB accepts regardless of "
         "bridge_pkt_src mode -- confirms fix direction #3 is mechanically "
         "sound for this leg";
  EXPECT_EQ(pkt.getPathHashCount(), 0);
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
