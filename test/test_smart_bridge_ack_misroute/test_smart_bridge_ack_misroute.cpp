// examples/simple_repeater/MyMesh.cpp's "smart bridge reply routing"
// (recv_pkt_source_bridge / trySendViaBridge()) stamps
// recv_pkt_source_bridge = pkt->_src_bridge at the top of every
// onRecvPacket() call and consumes it on the next sendPacket() call,
// redirecting that packet back out the same bridge instead of queuing it
// for local radio transmission.
//
// For a direct ACK arriving at a repeater that is itself the last hop
// before the destination companion, PAYLOAD_TYPE_ACK's special-case
// handling calls routeDirectRecvAcks(), which composes a new packet (fully-
// consumed path) and sends it via sendPacket(). If this repeater's own
// receipt of the incoming ack was bridge-sourced, the "next sendPacket()
// call" heuristic can't distinguish "this new packet is my own final local
// delivery" from "this is a genuine bridge-sourced-request reply" -- it
// bounces it back out the bridge instead of broadcasting locally to reach
// the actual destination, with no second chance.
//
// Reproduces MyMesh's exact wrapper logic (not the full MyMesh class, which
// needs CommonCLI/IdentityStore and isn't natively compilable) against the
// real Mesh::onRecvPacket/routeDirectRecvAcks.
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
  int local_outbound_queued = 0;

  Packet* allocNew() override { return new Packet(); }
  void free(Packet* p) override { delete p; }
  void queueOutbound(Packet* p, uint8_t, uint32_t) override { local_outbound_queued++; delete p; }
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

// Stands in for the "far side" bridge object -- only its identity as a
// non-null void* matters here (matches AbstractBridge* usage in MyMesh).
struct FakeBridgeHandle {
  int send_calls = 0;
};

struct FakeMeshDeps {
  FakeRadio radio;
  FakeClock clock;
  FakeRNG rng;
  FakeRTC rtc;
  CountingPacketManager mgr;
  FakeTables tables;
};

// Mirrors examples/simple_repeater/MyMesh.cpp's onRecvPacket()/
// trySendViaBridge() pair exactly (see MyMesh.cpp:576-609), the only two
// methods this bug depends on -- everything else in real MyMesh (CLI,
// region scoping, display, etc.) is irrelevant to this mechanism.
class TestRepeaterMesh : public FakeMeshDeps, public Mesh {
public:
  void* recv_pkt_source_bridge = nullptr;
  FakeBridgeHandle* bridge_seen_via = nullptr;   // records what trySendViaBridge redirected to

  explicit TestRepeaterMesh(uint8_t hash_byte)
    : FakeMeshDeps(), Mesh(radio, clock, rng, rtc, mgr, tables) {
    memset(self_id.pub_key, 0, PUB_KEY_SIZE);
    self_id.pub_key[0] = hash_byte;
  }

  bool allowPacketForward(const Packet*) override { return true; }
  uint32_t getDirectRetransmitDelay(const Packet*) override { return 0; }

  DispatcherAction onRecvPacket(Packet* pkt) override {
    recv_pkt_source_bridge = pkt->_src_bridge;   // MyMesh.cpp:577, unconditional
    return Mesh::onRecvPacket(pkt);
  }

protected:
  bool trySendViaBridge(Packet* packet) override {   // MyMesh.cpp:594-609
    void* bridge = recv_pkt_source_bridge;
    recv_pkt_source_bridge = nullptr;
    if (bridge == nullptr) return false;
    bridge_seen_via = (FakeBridgeHandle*)bridge;
    bridge_seen_via->send_calls++;
    releasePacket(packet);
    return true;
  }

public:
  DispatcherAction recv(Packet* pkt) { return onRecvPacket(pkt); }
};

Packet makeDirectAck(uint8_t self_hash) {
  Packet p;
  p.header = ROUTE_TYPE_DIRECT | (PAYLOAD_TYPE_ACK << PH_TYPE_SHIFT);
  p.path[0] = self_hash;
  p.setPathHashSizeAndCount(1, 1);
  uint32_t ack_crc = 0xDEADBEEF;
  memcpy(p.payload, &ack_crc, 4);
  p.payload_len = 4;
  return p;
}

}  // namespace

// The scenario that should work: an ACK arrives over LOCAL RADIO (not the
// bridge) at the second-to-last repeater. Its forwarded copy should queue
// for local transmission normally.
TEST(SmartBridgeAckMisroute, AckArrivingLocallyForwardsNormally) {
  TestRepeaterMesh repeater(0x73);
  FakeBridgeHandle bridge;

  Packet ack = makeDirectAck(0x73);
  ack._src_bridge = nullptr;   // arrived over local LoRa, not the bridge

  repeater.recv(&ack);

  EXPECT_EQ(repeater.mgr.local_outbound_queued, 1)
      << "forwarded ack should be queued for local radio transmission";
  EXPECT_EQ(bridge.send_calls, 0);
}

// The actual bug: a repeater is the last hop before the destination
// companion and receives the ack via the bridge. routeDirectRecvAcks()
// composes a fresh, fully-path-consumed packet and sends it -- but because
// this repeater's own receipt of the incoming ack was bridge-sourced,
// trySendViaBridge() intercepts this brand new, unrelated packet and bounces
// it back out the bridge instead of broadcasting it locally to the
// destination companion. The ack never reaches its actual destination.
TEST(SmartBridgeAckMisroute, AckArrivingViaBridgeGetsMisroutedBackOutTheBridge) {
  TestRepeaterMesh repeater(0x73);   // last hop before the companion
  FakeBridgeHandle bridge;

  Packet ack = makeDirectAck(0x73);
  ack._src_bridge = &bridge;   // arrived via the bridge

  repeater.recv(&ack);

  EXPECT_EQ(repeater.mgr.local_outbound_queued, 0)
      << "the forwarded ack never reaches the local radio queue -- it's "
         "silently redirected instead, so it can never reach the actual "
         "destination companion";
  EXPECT_EQ(bridge.send_calls, 1)
      << "trySendViaBridge() sent it right back out the same bridge it just "
         "arrived from, even though this repeater is the one that should "
         "have broadcast it locally";
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
