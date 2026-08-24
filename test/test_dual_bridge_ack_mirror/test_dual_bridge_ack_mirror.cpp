// Investigating a live hardware symptom reported on a topology the original
// trySendViaBridge fix (see test_smart_bridge_ack_misroute) was never tested
// against: a single repeater (Xiao/R73) running BOTH an ESPNowBridge (to a
// companion with no LoRa radio at all) AND an IpBridge (to a remote site,
// V3/Ra2) at once -- the "trifecta" env.
//
// Reported symptom: companion -> M5 message delivers fine; the ACK back
// (M5 -> V3 -[IP bridge]-> R73 -[ESPNOW bridge]-> companion) never arrives
// on the first two send attempts, only on the 3rd flood-escalated one --
// same "silent, deterministic" signature as the original bug.
//
// First theory tested here (see git history) was that the "0 path hops
// left" carve-out from the original fix didn't cover R73's case, since its
// last hop (the companion) is ESPNOW-only, not real LoRa. That test PASSED
// against the current code, proving the 0-hop case was already fine here --
// so the theory was wrong and the investigation moved to live hardware with
// BRIDGE_DEBUG on. The real capture showed the actual failure:
// `trySendViaBridge: redirecting type=3 back out originating bridge,
// path_hops=1` -- a DIRECT-route ack with ONE hop still remaining (not
// zero) was bounced straight back out the IP bridge it arrived from,
// instead of continuing on (via normal local TX + logTx()'s mirror hook)
// toward the ESPNOW bridge its path[] actually pointed to.
//
// Root cause: trySendViaBridge()'s "redirect back out the originating
// bridge" behavior was never actually about hop count -- it's only correct
// for FLOOD-route replies with no path of their own (e.g.
// sendFloodReply()'s REQ/RESPONSE and TXT_MSG/CLI-over-chat replies, both
// validated on real hardware per planning/smart-bridge-routing-design.md
// §11). A DIRECT-route packet always carries a real path[] to follow --
// bouncing it back the way it came is only coincidentally correct when that
// packet happens to have 0 hops left (single-bridge, last-hop case). The
// fix: gate on packet->isRouteDirect(), not path hash count.
//
// This test drives the REAL Mesh::onRecvPacket/routeDirectRecvAcks and REAL
// Dispatcher::loop()/checkSend() send-completion cycle (not just the
// trySendViaBridge hook in isolation, unlike test_smart_bridge_ack_misroute)
// against a repeater carrying MyMesh's CURRENT trySendViaBridge (route-type
// gated) and CURRENT logTx() (bridge_pkt_src==0 mirror-on-TX, unconditionally
// fanning out to every compiled-in bridge).
#include <gtest/gtest.h>
#include <Mesh.h>
#include <helpers/AbstractBridge.h>
#include <cstring>

using namespace mesh;

namespace {

class FakeRadio : public Radio {
public:
  int recvRaw(uint8_t*, int) override { return 0; }
  uint32_t getEstAirtimeFor(int) override { return 10; }
  float packetScore(float, int) override { return 1.0f; }
  bool startSendRaw(const uint8_t*, int) override { return true; }
  bool isSendComplete() override { return true; }   // completes on the very next loop() poll
  void onSendFinished() override {}
  bool isInRecvMode() const override { return true; }
};

class FakeClock : public MillisecondClock {
public:
  unsigned long getMillis() override { return _now; }
  unsigned long _now = 0;
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

// Unlike the single-hook test's CountingPacketManager, this one actually
// stores the queued packet so Dispatcher::checkSend() can retrieve it via
// getNextOutbound() and drive a real send-completion cycle through to
// logTx() -- that's the whole point of this test.
class RealQueuePacketManager : public PacketManager {
public:
  Packet* pending = nullptr;

  Packet* allocNew() override { return new Packet(); }
  void free(Packet* p) override { delete p; }
  void queueOutbound(Packet* p, uint8_t, uint32_t) override {
    ASSERT_EQ(pending, nullptr) << "test only expects one in-flight outbound packet at a time";
    pending = p;
  }
  Packet* getNextOutbound(uint32_t) override {
    Packet* p = pending;
    pending = nullptr;
    return p;
  }
  int getOutboundCount(uint32_t) const override { return pending ? 1 : 0; }
  int getOutboundTotal() const override { return pending ? 1 : 0; }
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

// Stands in for AbstractBridge -- real ESPNowBridge/IpBridge depend on
// ESP-NOW/WiFi/DTLS libraries that don't compile natively (same reason the
// original bug's test uses a bare void* handle). Only sendPacket() and its
// own per-instance dedup semantics matter for what this test is checking:
// whether MyMesh's own routing logic ever calls it, not the bridge's
// internal transport.
class FakeBridge : public AbstractBridge {
public:
  int send_calls = 0;
  Packet* last_sent = nullptr;

  void begin() override {}
  void end() override {}
  bool isRunning() const override { return true; }
  void loop() override {}
  void sendPacket(Packet* packet) override { send_calls++; last_sent = packet; }
  void onPacketReceived(Packet*) override {}
};

struct FakeMeshDeps {
  FakeRadio radio;
  FakeClock clock;
  FakeRNG rng;
  FakeRTC rtc;
  RealQueuePacketManager mgr;
  FakeTables tables;
};

// Mirrors examples/simple_repeater/MyMesh.cpp's CURRENT onRecvPacket() /
// trySendViaBridge() / logTx() trio exactly, for a trifecta node running
// both WITH_ESPNOW_BRIDGE and WITH_IP_BRIDGE -- see MyMesh.cpp:479-626.
class TestTrifectaMesh : public FakeMeshDeps, public Mesh {
public:
  void* recv_pkt_source_bridge = nullptr;
  int bridge_pkt_src = 0;   // 0 = logTx (mirror-on-TX), matches R73's confirmed live 'bridge.source=logTx'
  FakeBridge espnow_bridge;
  FakeBridge ip_bridge;

  explicit TestTrifectaMesh(uint8_t hash_byte)
    : FakeMeshDeps(), Mesh(radio, clock, rng, rtc, mgr, tables) {
    memset(self_id.pub_key, 0, PUB_KEY_SIZE);
    self_id.pub_key[0] = hash_byte;
  }

  bool allowPacketForward(const Packet*) override { return true; }
  uint32_t getDirectRetransmitDelay(const Packet*) override { return 0; }

  DispatcherAction onRecvPacket(Packet* pkt) override {   // MyMesh.cpp:572-591
    recv_pkt_source_bridge = pkt->_src_bridge;
    return Mesh::onRecvPacket(pkt);
  }

  void logTx(Packet* packet, int) override {   // MyMesh.cpp:513-526, WITH_ESPNOW_BRIDGE + WITH_IP_BRIDGE both defined
    if (bridge_pkt_src == 0) {
      espnow_bridge.sendPacket(packet);
      ip_bridge.sendPacket(packet);
    }
  }

protected:
  bool trySendViaBridge(Packet* packet) override {   // MyMesh.cpp:594-626, CURRENT (route-type-gated) version
    void* bridge = recv_pkt_source_bridge;
    recv_pkt_source_bridge = nullptr;
    if (bridge == nullptr) return false;

    if (packet->isRouteDirect()) {
      // MyMesh.cpp's current gate (see planning/ip-bridge-mesh-safety.md
      // gap #4): a freshly-composed zero-hop reply, for any payload type
      // that can never reach here as Mesh::routeDirectRecvAcks()'s
      // decremented relay-in-transit shape (ACK/MULTIPART), can safely be
      // answered bridge-only -- path_len==0 unambiguously names the peer
      // we just heard from as the destination.
      if (packet->getPathHashCount() == 0 &&
          packet->getPayloadType() != PAYLOAD_TYPE_ACK &&
          packet->getPayloadType() != PAYLOAD_TYPE_MULTIPART) {
        ((AbstractBridge*)bridge)->sendPacket(packet);
        releasePacket(packet);
        return true;
      }
      return false;   // has its own path[] to follow -- fall through to normal local TX (-> logTx mirror)
    }

    ((AbstractBridge*)bridge)->sendPacket(packet);
    releasePacket(packet);
    return true;
  }

public:
  DispatcherAction recv(Packet* pkt) { return onRecvPacket(pkt); }

  // Drives the real Dispatcher send-completion cycle: one loop() to pick up
  // and "start" the queued send, one more for FakeRadio's always-true
  // isSendComplete() to be observed and fire the real logTx() call. The
  // clock must actually advance between calls -- Dispatcher::millisHasNowPassed()
  // requires strictly-greater-than, so a clock frozen at the constructor's
  // initial next_tx_time (also 0) would make checkSend() return early forever.
  void pumpSendCycle() {
    clock._now += 10;
    loop();
    clock._now += 10;
    loop();
  }
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

// Matches the live hardware capture: a DIRECT ack whose path is [self_hash,
// next_hop_hash] -- self_hash is stripped by Mesh::onRecvPacket's
// removeSelfFromPath() before routeDirectRecvAcks() composes the forwarded
// copy, leaving exactly 1 hop (next_hop_hash) for trySendViaBridge to see.
Packet makeDirectAckWithOneMoreHop(uint8_t self_hash, uint8_t next_hop_hash) {
  Packet p;
  p.header = ROUTE_TYPE_DIRECT | (PAYLOAD_TYPE_ACK << PH_TYPE_SHIFT);
  p.path[0] = self_hash;
  p.path[1] = next_hop_hash;
  p.setPathHashSizeAndCount(1, 2);
  uint32_t ack_crc = 0xDEADBEEF;
  memcpy(p.payload, &ack_crc, 4);
  p.payload_len = 4;
  return p;
}

// A DIRECT, zero-hop RESPONSE -- the shape of onAnonDataRecv()'s admin/CLI
// reply (createDatagram(PAYLOAD_TYPE_RESPONSE,...) + sendDirect(reply,
// client->out_path,...) with out_path_len==0), never a relay-in-transit.
Packet* makeZeroHopDirectResponse() {
  Packet* p = new Packet();
  p->header = ROUTE_TYPE_DIRECT | (PAYLOAD_TYPE_RESPONSE << PH_TYPE_SHIFT);
  p->path_len = 0;
  uint8_t body[4] = {5, 6, 7, 8};
  memcpy(p->payload, body, sizeof(body));
  p->payload_len = sizeof(body);
  return p;
}

// A FLOOD-route reply with no path of its own -- the shape of
// sendFloodReply()'s REQ/RESPONSE and TXT_MSG/CLI-over-chat replies, the two
// scenarios trySendViaBridge's bridge-redirect behavior was actually
// designed and validated for (planning/smart-bridge-routing-design.md §11).
// Heap-allocated (unlike makeDirectAck/makeDirectAckWithOneMoreHop above,
// which the caller feeds to onRecvPacket() by address and never frees) --
// trySendViaBridge's redirect path calls releasePacket(), which for this
// test's RealQueuePacketManager does `delete p`, so this one must actually
// come from `new` to avoid freeing a stack object.
Packet* makeFloodReply() {
  Packet* p = new Packet();
  p->header = ROUTE_TYPE_FLOOD | (PAYLOAD_TYPE_RESPONSE << PH_TYPE_SHIFT);
  p->path_len = 0;
  uint8_t body[4] = {1, 2, 3, 4};
  memcpy(p->payload, body, sizeof(body));
  p->payload_len = sizeof(body);
  return p;
}

}  // namespace

// Control case: with only the IpBridge active (bridge_pkt_src doesn't matter
// since ip_bridge is the only one exercised), a 0-hop-left ack arriving via
// the IP bridge falls through to a real local TX -- and logTx() mirrors it
// back out over IP too, which is harmless (V3 will dedup it) and matches
// the topology the original fix was actually validated against.
TEST(DualBridgeAckMirror, SingleBridgeZeroHopFallsThroughToLocalTxAndMirrors) {
  TestTrifectaMesh repeater(0x33);   // stand-in for V3/Ra2

  Packet ack = makeDirectAck(0x33);
  ack._src_bridge = &repeater.ip_bridge;

  repeater.begin();
  repeater.recv(&ack);
  repeater.pumpSendCycle();

  EXPECT_EQ(repeater.ip_bridge.send_calls, 1)
      << "logTx() should mirror the completed local TX back out the IP bridge";
}

// The scenario under investigation: R73, a trifecta node, receives M5's ack
// via the IP bridge (from V3) with 0 hops left -- meaning R73 itself must
// deliver it to the companion, which is ONLY reachable via the ESPNOW
// bridge (no real LoRa radio on that end at all). If this fails, the
// current code has a genuine hole for this topology; if it passes, the
// MyMesh-level routing logic is provably correct and the real root cause
// lies elsewhere (ESPNowBridge's own internals, peer state, hardware).
TEST(DualBridgeAckMirror, ZeroHopAckFromIpBridgeStillReachesEspNowBridge) {
  TestTrifectaMesh repeater(0x73);   // R73/Xiao, dual-bridge trifecta node
  repeater.bridge_pkt_src = 0;       // confirmed live via CLI: R73's bridge.source=logTx

  Packet ack = makeDirectAck(0x73);
  ack._src_bridge = &repeater.ip_bridge;   // arrived from V3's side, via the IP bridge

  repeater.begin();
  repeater.recv(&ack);
  repeater.pumpSendCycle();

  EXPECT_EQ(repeater.espnow_bridge.send_calls, 1)
      << "the ack must reach the ESPNOW bridge's sendPacket() for the companion "
         "to have any chance of receiving it -- it has no other path to it";
}

// The actual live hardware failure (BRIDGE_DEBUG capture, 2026-08-22): a
// DIRECT ack arrives via the IP bridge still carrying ONE more hop (the
// companion's ESPNOW leg) after this repeater's own hash is stripped --
// exactly the "path_hops=1" seen in the real log. Before the route-type fix,
// this got bounced straight back out the IP bridge instead of continuing on.
TEST(DualBridgeAckMirror, DirectAckWithRemainingHopFallsThroughAndReachesEspNowBridge) {
  TestTrifectaMesh repeater(0x73);   // R73/Xiao
  repeater.bridge_pkt_src = 0;

  Packet ack = makeDirectAckWithOneMoreHop(0x73, 0x99);   // 0x99 stands in for the companion's leg
  ack._src_bridge = &repeater.ip_bridge;

  repeater.begin();
  repeater.recv(&ack);
  repeater.pumpSendCycle();

  EXPECT_EQ(repeater.espnow_bridge.send_calls, 1)
      << "a DIRECT ack with hops remaining must still fall through to local "
         "TX + logTx()'s mirror, not get bounced back out the IP bridge it "
         "arrived from -- that bridge has nothing to do with where this "
         "packet's path[] actually points";
  EXPECT_EQ(repeater.ip_bridge.send_calls, 1)
      << "logTx() mirrors to every configured bridge, including IP -- "
         "harmless, V3 will dedup it";
}

// Regression guard: the two reply mechanisms trySendViaBridge's
// bridge-redirect behavior was originally built and validated for
// (sendFloodReply()'s REQ/RESPONSE and TXT_MSG/CLI-over-chat replies) must
// keep working -- these are FLOOD-route packets with no path of their own,
// where bouncing back out the originating bridge is the ONLY way back to
// the requester on the far side.
TEST(DualBridgeAckMirror, FloodReplyStillRedirectsBackOutOriginatingBridge) {
  TestTrifectaMesh repeater(0x73);
  repeater.recv_pkt_source_bridge = &repeater.ip_bridge;   // as if just processed a bridge-sourced request

  repeater.sendPacket(makeFloodReply(), 0, 0);

  EXPECT_EQ(repeater.ip_bridge.send_calls, 1)
      << "a FLOOD-route reply with no path of its own must still be "
         "redirected back out the bridge it arrived from";
  EXPECT_EQ(repeater.espnow_bridge.send_calls, 0);
}

// The fix under test (planning/ip-bridge-mesh-safety.md gap #4): a
// zero-hop DIRECT admin/CLI reply, generated in response to a request that
// arrived via the bridge, must go bridge-only -- the observed live symptom
// was Ra2's LoRa radio keying on every admin/CLI request from a companion
// reachable ONLY through the ESPNOW+IP bridge chain (no radio on that end
// at all), a pure waste of airtime nobody could ever receive.
TEST(DualBridgeAckMirror, ZeroHopDirectResponseFromBridgeRedirectsBridgeOnly) {
  TestTrifectaMesh repeater(0x73);
  repeater.recv_pkt_source_bridge = &repeater.ip_bridge;   // as if just processed a bridge-sourced admin request

  repeater.sendPacket(makeZeroHopDirectResponse(), 0, 0);

  EXPECT_EQ(repeater.ip_bridge.send_calls, 1)
      << "a zero-hop DIRECT reply to a bridge-sourced request must be answered "
         "bridge-only -- its destination has no radio to receive a local TX";
  EXPECT_EQ(repeater.espnow_bridge.send_calls, 0);
}

// Regression guard for the fix above: it must NOT widen to cover ACK, since
// PAYLOAD_TYPE_ACK is the one payload type that can ALSO reach
// trySendViaBridge() as Mesh::routeDirectRecvAcks()'s decremented
// relay-in-transit shape (see SingleBridgeZeroHopFallsThroughToLocalTxAndMirrors
// and ZeroHopAckFromIpBridgeStillReachesEspNowBridge above) -- indistinguishable
// from a fresh reply by payload type + path_len alone, so ACK must keep
// falling through to real local TX unconditionally, even zero-hop.
TEST(DualBridgeAckMirror, ZeroHopDirectAckFromBridgeStillFallsThrough) {
  TestTrifectaMesh repeater(0x73);
  repeater.recv_pkt_source_bridge = &repeater.ip_bridge;

  Packet* ack = new Packet();
  ack->header = ROUTE_TYPE_DIRECT | (PAYLOAD_TYPE_ACK << PH_TYPE_SHIFT);
  ack->path_len = 0;
  uint32_t ack_crc = 0xDEADBEEF;
  memcpy(ack->payload, &ack_crc, 4);
  ack->payload_len = 4;

  repeater.sendPacket(ack, 0, 0);

  EXPECT_EQ(repeater.ip_bridge.send_calls, 0)
      << "ACK must never be bridge-redirected by the zero-hop DIRECT fix -- "
         "only real local TX (+ logTx's separate mirror) is safe for it";
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
