// Covers a repeater running both an ESPNowBridge and an IpBridge at once
// (the "trifecta" env) -- a topology test_smart_bridge_ack_misroute's
// single-bridge fix doesn't exercise.
//
// trySendViaBridge()'s "redirect back out the originating bridge" behavior
// is only correct for FLOOD-route replies with no path of their own (e.g.
// sendFloodReply()'s REQ/RESPONSE and TXT_MSG/CLI-over-chat replies). A
// DIRECT-route packet always carries a real path[] to follow -- bouncing it
// back the way it came is only coincidentally correct when it happens to
// have 0 hops left (single-bridge, last-hop case). Gate on
// packet->isRouteDirect(), not path hash count.
//
// Drives the real Mesh::onRecvPacket/routeDirectRecvAcks and real
// Dispatcher::loop()/checkSend() send-completion cycle (not just the
// trySendViaBridge hook in isolation, unlike test_smart_bridge_ack_misroute)
// against a repeater carrying MyMesh's current trySendViaBridge (route-type
// gated) and current logTx() (bridge_pkt_src==0 mirror-on-TX, fanning out to
// every compiled-in bridge).
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
// Max age for recv_pkt_source_bridge -- mirrors MyMesh.h's
// RECV_PKT_SOURCE_BRIDGE_MAX_AGE_MS.
static const unsigned long RECV_PKT_SOURCE_BRIDGE_MAX_AGE_MS = 1000;

class TestTrifectaMesh : public FakeMeshDeps, public Mesh {
public:
  void* recv_pkt_source_bridge = nullptr;
  unsigned long recv_pkt_source_bridge_set_at = 0;
  int bridge_pkt_src = 0;   // 0 = logTx (mirror-on-TX), confirmed live default
  FakeBridge espnow_bridge;
  FakeBridge ip_bridge;

  // Minimal mirror of MyMesh's neighbours[]/bridge_neighbours[] tables
  // (examples/simple_repeater/MyMesh.h) -- only what findBridgeOnlyNextHop()
  // needs: an identity hash and when it was last heard, split RF vs bridge.
  static const int MAX_TABLE = 4;
  struct { Identity id; unsigned long heard_timestamp; } rf_neighbours[MAX_TABLE] = {};
  struct { Identity id; unsigned long heard_timestamp; void* bridge; } bridge_neighbours[MAX_TABLE] = {};

  void putRfNeighbourHash(uint8_t hash_byte) {
    Identity id;
    memset(id.pub_key, 0, PUB_KEY_SIZE);
    id.pub_key[0] = hash_byte;
    rf_neighbours[0].id = id;
    rf_neighbours[0].heard_timestamp = 1000;
  }

  void putBridgeNeighbourHash(uint8_t hash_byte, void* via_bridge) {
    Identity id;
    memset(id.pub_key, 0, PUB_KEY_SIZE);
    id.pub_key[0] = hash_byte;
    bridge_neighbours[0].id = id;
    bridge_neighbours[0].heard_timestamp = 1000;
    bridge_neighbours[0].bridge = via_bridge;
  }

  explicit TestTrifectaMesh(uint8_t hash_byte)
    : FakeMeshDeps(), Mesh(radio, clock, rng, rtc, mgr, tables) {
    memset(self_id.pub_key, 0, PUB_KEY_SIZE);
    self_id.pub_key[0] = hash_byte;
  }

  bool allowPacketForward(const Packet*) override { return true; }
  uint32_t getDirectRetransmitDelay(const Packet*) override { return 0; }

  DispatcherAction onRecvPacket(Packet* pkt) override {   // MyMesh.cpp:708-726
    recv_pkt_source_bridge = pkt->_src_bridge;
    recv_pkt_source_bridge_set_at = clock.getMillis();
    return Mesh::onRecvPacket(pkt);
  }

  void logTx(Packet* packet, int) override {   // MyMesh.cpp:513-526, WITH_ESPNOW_BRIDGE + WITH_IP_BRIDGE both defined
    if (bridge_pkt_src == 0) {
      espnow_bridge.sendPacket(packet);
      ip_bridge.sendPacket(packet);
    }
  }

  // Mirrors MyMesh::findBridgeOnlyNextHop() (MyMesh.cpp) exactly in shape:
  // RF sighting (ever) disqualifies; a fresh bridge-only sighting wins.
  void* findBridgeOnlyNextHop(const uint8_t* hash, uint8_t hash_size) const {
    for (int i = 0; i < MAX_TABLE; i++) {
      if (rf_neighbours[i].heard_timestamp > 0 && rf_neighbours[i].id.isHashMatch(hash, hash_size)) {
        return nullptr;
      }
    }
    for (int i = 0; i < MAX_TABLE; i++) {
      if (bridge_neighbours[i].heard_timestamp > 0 && bridge_neighbours[i].id.isHashMatch(hash, hash_size)) {
        return bridge_neighbours[i].bridge;
      }
    }
    return nullptr;
  }

protected:
  bool trySendViaBridge(Packet* packet) override {   // MyMesh.cpp:729-820, CURRENT version
    void* bridge = (clock.getMillis() - recv_pkt_source_bridge_set_at < RECV_PKT_SOURCE_BRIDGE_MAX_AGE_MS)
                   ? recv_pkt_source_bridge : nullptr;
    recv_pkt_source_bridge = nullptr;

    if (packet->isRouteDirect()) {
      // Exception 1: freshly-composed zero-hop reply, non-ACK/MULTIPART.
      if (bridge != nullptr && packet->getPathHashCount() == 0 &&
          packet->getPayloadType() != PAYLOAD_TYPE_ACK &&
          packet->getPayloadType() != PAYLOAD_TYPE_MULTIPART) {
        ((AbstractBridge*)bridge)->sendPacket(packet);
        releasePacket(packet);
        return true;
      }

      // Exception 2: real path with hops remaining, next hop is a known
      // bridge-only neighbour (looked up fresh, not from how the
      // triggering packet arrived) -- safe for ACK/MULTIPART too.
      if (packet->getPathHashCount() > 0) {
        void* target_bridge = findBridgeOnlyNextHop(packet->path, packet->getPathHashSize());
        if (target_bridge != nullptr) {
          ((AbstractBridge*)target_bridge)->sendPacket(packet);
          releasePacket(packet);
          return true;
        }
      }

      return false;   // has its own path[] to follow -- fall through to normal local TX (-> logTx mirror)
    }

    if (bridge == nullptr) return false;

    ((AbstractBridge*)bridge)->sendPacket(packet);
    releasePacket(packet);
    return true;
  }

  // Mirrors MyMesh::tryRelayViaBridge() (MyMesh.cpp) -- relay-forwarding
  // counterpart to trySendViaBridge() above, called from
  // Dispatcher::processRecvPacket() for ACTION_RETRANSMIT* actions
  // (packets not addressed to this node, being passed along).
  bool tryRelayViaBridge(Packet* packet) override {
    if (packet->isRouteDirect() && packet->getPathHashCount() > 0) {
      void* target_bridge = findBridgeOnlyNextHop(packet->path, packet->getPathHashSize());
      if (target_bridge != nullptr) {
        ((AbstractBridge*)target_bridge)->sendPacket(packet);
        releasePacket(packet);
        return true;
      }
    }
    return false;
  }

public:
  DispatcherAction recv(Packet* pkt) { return onRecvPacket(pkt); }

  // Direct access to the hook in isolation, for testing its own gating
  // logic (e.g. FLOOD packets must never be considered) without needing to
  // fabricate a fully wire-valid FLOOD packet that survives Mesh's own
  // parsing just to reach it via the full pipeline.
  bool tryRelay(Packet* pkt) { return tryRelayViaBridge(pkt); }

  // Drives the REAL Dispatcher::processRecvPacket() (now protected,
  // visibility-only change) -- unlike recv() above (which calls
  // onRecvPacket() directly), this exercises the actual ACTION_RETRANSMIT*
  // handling in Dispatcher.cpp, including the new tryRelayViaBridge() hook.
  // Needs a heap-allocated packet (RealQueuePacketManager::free() does
  // `delete p`) -- both the "redirected" path (tryRelayViaBridge releases
  // it directly) and the "queued" path (freed later via the outbound
  // queue) assume that.
  void relayRecv(Packet* pkt) { processRecvPacket(pkt); }

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

// A DIRECT packet with one real hop remaining -- the shape of a
// CLI-over-chat reply (onPeerDataRecv(), PAYLOAD_TYPE_TXT_MSG) sent via
// sendDirect(reply, client->out_path,...) where out_path is one real hop
// long (a genuine intermediate repeater, not a fake/local-delivery marker).
// This is the actual live symptom this fix targets: exception 1 doesn't
// apply here (path_hash_count is 1, not 0).
Packet* makeDirectPacketWithOneHop(uint8_t payload_type, uint8_t next_hop_hash) {
  Packet* p = new Packet();
  p->header = ROUTE_TYPE_DIRECT | (payload_type << PH_TYPE_SHIFT);
  p->path[0] = next_hop_hash;
  p->setPathHashSizeAndCount(1, 1);
  uint8_t body[4] = {9, 9, 9, 9};
  memcpy(p->payload, body, sizeof(body));
  p->payload_len = sizeof(body);
  return p;
}

// A DIRECT packet being genuinely relayed through this repeater (not
// addressed to it) -- path is [self_hash, next_hop_hash], matching how a
// real REQ/RESPONSE/TXT_MSG/PATH arrives when this repeater is a mid-path
// hop. Heap-allocated (unlike makeDirectAckWithOneMoreHop, which is only
// ever fed to onRecvPacket() directly, bypassing the packet manager) --
// relayRecv() drives the REAL Dispatcher::processRecvPacket(), which frees
// the packet one way or another (either tryRelayViaBridge() releasing it
// directly, or the outbound queue owning and eventually freeing it), and
// RealQueuePacketManager::free() does `delete p`.
Packet* makeDirectRelayPacket(uint8_t payload_type, uint8_t self_hash, uint8_t next_hop_hash) {
  Packet* p = new Packet();
  p->header = ROUTE_TYPE_DIRECT | (payload_type << PH_TYPE_SHIFT);
  p->path[0] = self_hash;
  p->path[1] = next_hop_hash;
  p->setPathHashSizeAndCount(1, 2);
  uint8_t body[4] = {1, 1, 1, 1};
  memcpy(p->payload, body, sizeof(body));
  p->payload_len = sizeof(body);
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
// scenarios trySendViaBridge's bridge-redirect behavior was designed for.
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
// back out over IP too, which is harmless (the peer will dedup it).
TEST(DualBridgeAckMirror, SingleBridgeZeroHopFallsThroughToLocalTxAndMirrors) {
  TestTrifectaMesh repeater(0x33);

  Packet ack = makeDirectAck(0x33);
  ack._src_bridge = &repeater.ip_bridge;

  repeater.begin();
  repeater.recv(&ack);
  repeater.pumpSendCycle();

  EXPECT_EQ(repeater.ip_bridge.send_calls, 1)
      << "logTx() should mirror the completed local TX back out the IP bridge";
}

// A dual-bridge trifecta node receives an ack via the IP bridge with 0 hops
// left -- meaning it must deliver locally to a companion reachable only via
// the ESPNOW bridge (no real LoRa radio on that end at all).
TEST(DualBridgeAckMirror, ZeroHopAckFromIpBridgeStillReachesEspNowBridge) {
  TestTrifectaMesh repeater(0x73);
  repeater.bridge_pkt_src = 0;

  Packet ack = makeDirectAck(0x73);
  ack._src_bridge = &repeater.ip_bridge;

  repeater.begin();
  repeater.recv(&ack);
  repeater.pumpSendCycle();

  EXPECT_EQ(repeater.espnow_bridge.send_calls, 1)
      << "the ack must reach the ESPNOW bridge's sendPacket() for the companion "
         "to have any chance of receiving it -- it has no other path to it";
}

// A DIRECT ack arrives via the IP bridge still carrying one more hop (the
// companion's ESPNOW leg) after this repeater's own hash is stripped.
// Before the route-type fix, this got bounced straight back out the IP
// bridge instead of continuing on.
TEST(DualBridgeAckMirror, DirectAckWithRemainingHopFallsThroughAndReachesEspNowBridge) {
  TestTrifectaMesh repeater(0x73);
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
         "harmless, the peer will dedup it";
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

// recv_pkt_source_bridge is "consume-once" but was previously unbounded in
// age -- if nothing gets sent for a while after a bridge-sourced receive
// (bridge heartbeat pongs don't go through Mesh::sendPacket() at all), a
// stale flag could misfire on a later, unrelated send. A broadcast FLOOD
// send unrelated to any prior receive must reach both bridges, not get
// redirected bridge-only just because a receive happened long ago and was
// never consumed by an intervening send.
TEST(DualBridgeAckMirror, StaleRecvPktSourceBridgeDoesNotMisrouteUnrelatedSend) {
  TestTrifectaMesh repeater(0x73);
  repeater.recv_pkt_source_bridge = &repeater.ip_bridge;
  repeater.recv_pkt_source_bridge_set_at = 0;          // "received" at t=0
  repeater.clock._now = RECV_PKT_SOURCE_BRIDGE_MAX_AGE_MS + 1;   // long after, nothing sent in between

  repeater.sendPacket(makeFloodReply(), 0, 0);

  EXPECT_EQ(repeater.ip_bridge.send_calls, 0)
      << "a stale recv_pkt_source_bridge must not redirect an unrelated later send";
  EXPECT_EQ(repeater.espnow_bridge.send_calls, 0)
      << "trySendViaBridge declining just means 'fall through to normal "
         "local TX', which this synthetic FLOOD packet doesn't actually "
         "drive through a full send cycle -- the point here is only that "
         "it did NOT get redirected";
}

// Regression guard: a FRESH recv_pkt_source_bridge (well within the age
// bound) must still redirect exactly as before -- the fix narrows when the
// flag is trusted, it doesn't disable the mechanism.
TEST(DualBridgeAckMirror, FreshRecvPktSourceBridgeStillRedirects) {
  TestTrifectaMesh repeater(0x73);
  repeater.recv_pkt_source_bridge = &repeater.ip_bridge;
  repeater.recv_pkt_source_bridge_set_at = 0;
  repeater.clock._now = RECV_PKT_SOURCE_BRIDGE_MAX_AGE_MS - 1;   // just under the bound

  repeater.sendPacket(makeFloodReply(), 0, 0);

  EXPECT_EQ(repeater.ip_bridge.send_calls, 1)
      << "a fresh flag (well within the age bound) must still redirect normally";
  EXPECT_EQ(repeater.espnow_bridge.send_calls, 0);
}

// A zero-hop DIRECT admin/CLI reply, generated in response to a request that
// arrived via the bridge, must go bridge-only -- the observed live symptom
// was a repeater's LoRa radio keying on every admin/CLI request from a
// companion reachable only through an ESPNOW+IP bridge chain (no radio on
// that end at all), a pure waste of airtime nobody could ever receive.
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

// The actual live symptom this fix targets: a CLI-over-chat reply (TXT_MSG)
// with one real hop remaining whose next hop (the intermediate repeater)
// has only ever been heard over the IP bridge, never over local RF. Must
// redirect bridge-only instead of needlessly keying local RF.
TEST(DualBridgeAckMirror, DirectTxtMsgToKnownBridgeOnlyNextHopRedirects) {
  TestTrifectaMesh repeater(0x73);
  repeater.putBridgeNeighbourHash(0x99, &repeater.ip_bridge);   // 0x99 heard only via IP bridge, never RF

  repeater.sendPacket(makeDirectPacketWithOneHop(PAYLOAD_TYPE_TXT_MSG, 0x99), 0, 0);

  EXPECT_EQ(repeater.ip_bridge.send_calls, 1)
      << "next hop is a known bridge-only neighbour -- must redirect there directly";
  EXPECT_EQ(repeater.espnow_bridge.send_calls, 0);
}

// Regression guard: if the next hop's identity is unknown to both tables
// (never populated in this test), the new lookup must decline and preserve
// today's safe default -- normal local TX + logTx()'s mirror, exactly like
// DirectAckWithRemainingHopFallsThroughAndReachesEspNowBridge above.
TEST(DualBridgeAckMirror, DirectTxtMsgToUnknownNextHopFallsThroughAndMirrors) {
  TestTrifectaMesh repeater(0x73);
  // no neighbour tables populated -- next hop identity is unknown

  repeater.sendPacket(makeDirectPacketWithOneHop(PAYLOAD_TYPE_TXT_MSG, 0x99), 0, 0);
  repeater.pumpSendCycle();

  EXPECT_EQ(repeater.espnow_bridge.send_calls, 1)
      << "unknown next hop must fall through to real local TX + logTx's mirror";
  EXPECT_EQ(repeater.ip_bridge.send_calls, 1);
}

// Safety guard: if the next hop has EVER been heard over real RF (even if
// it also happens to have a bridge_neighbours entry -- a node can be both
// RF- and bridge-reachable), local delivery must not be skipped.
TEST(DualBridgeAckMirror, DirectTxtMsgToRfHeardNextHopFallsThroughAndMirrors) {
  TestTrifectaMesh repeater(0x73);
  repeater.putRfNeighbourHash(0x99);
  repeater.putBridgeNeighbourHash(0x99, &repeater.ip_bridge);   // also bridge-heard -- RF must still win

  repeater.sendPacket(makeDirectPacketWithOneHop(PAYLOAD_TYPE_TXT_MSG, 0x99), 0, 0);
  repeater.pumpSendCycle();

  EXPECT_EQ(repeater.espnow_bridge.send_calls, 1)
      << "an RF-heard next hop must never be skipped in favor of a bridge redirect";
  EXPECT_EQ(repeater.ip_bridge.send_calls, 1);
}

// The new lookup is identity-based, not payload-type-based, so it can safely
// extend to ACK/MULTIPART too (unlike exception 1) -- an ACK relay-in-transit
// packet whose next hop is a known bridge-only neighbour should also redirect.
TEST(DualBridgeAckMirror, DirectAckToKnownBridgeOnlyNextHopRedirects) {
  TestTrifectaMesh repeater(0x73);
  repeater.putBridgeNeighbourHash(0x99, &repeater.ip_bridge);

  Packet ack = makeDirectAckWithOneMoreHop(0x73, 0x99);
  ack._src_bridge = &repeater.ip_bridge;

  repeater.begin();
  repeater.recv(&ack);
  repeater.pumpSendCycle();

  EXPECT_EQ(repeater.ip_bridge.send_calls, 1)
      << "identity-based lookup is safe for ACK too -- the redirect decision "
         "never depends on distinguishing fresh-reply from relay-in-transit";
  EXPECT_EQ(repeater.espnow_bridge.send_calls, 0);
}

// The relay-forwarding fix: a DIRECT packet genuinely being relayed through
// this repeater (addressed elsewhere, e.g. a REQ/RESPONSE/TXT_MSG mid-path)
// must redirect bridge-only when its real next hop is a known bridge-only
// neighbour. This never reaches trySendViaBridge() at all -- a different
// code path, ACTION_RETRANSMIT* via processRecvPacket(), not sendPacket().
// Drives the real Dispatcher::processRecvPacket(), not just the hook in
// isolation.
TEST(DualBridgeAckMirror, DirectRelayPacketToKnownBridgeOnlyNextHopRedirects) {
  TestTrifectaMesh repeater(0x73);
  repeater.putBridgeNeighbourHash(0x99, &repeater.ip_bridge);

  repeater.relayRecv(makeDirectRelayPacket(PAYLOAD_TYPE_REQ, 0x73, 0x99));

  EXPECT_EQ(repeater.ip_bridge.send_calls, 1)
      << "next hop is a known bridge-only neighbour -- must redirect there directly";
  EXPECT_EQ(repeater.espnow_bridge.send_calls, 0);
  EXPECT_EQ(repeater.mgr.pending, nullptr)
      << "a redirected relay packet must NOT also be queued for local TX";
}

// Regression guard: unknown next hop must fall through to the existing,
// already-tested behavior -- queued for local TX (and, once actually sent,
// mirrored to every bridge via logTx(), same as before this fix existed).
TEST(DualBridgeAckMirror, DirectRelayPacketToUnknownNextHopFallsThroughToQueue) {
  TestTrifectaMesh repeater(0x73);
  // no neighbour tables populated -- next hop identity is unknown

  repeater.relayRecv(makeDirectRelayPacket(PAYLOAD_TYPE_REQ, 0x73, 0x99));

  ASSERT_NE(repeater.mgr.pending, nullptr)
      << "unknown next hop must fall through to the normal local-TX queue";
  repeater.pumpSendCycle();

  EXPECT_EQ(repeater.espnow_bridge.send_calls, 1)
      << "once actually sent locally, logTx() still mirrors to every bridge as before";
  EXPECT_EQ(repeater.ip_bridge.send_calls, 1);
}

// Safety guard: an RF-heard next hop must never be redirected, even during
// relay-forwarding -- same principle as the reply-path fix, re-verified for
// this separate code path since it has its own independent gate.
TEST(DualBridgeAckMirror, DirectRelayPacketToRfHeardNextHopFallsThroughToQueue) {
  TestTrifectaMesh repeater(0x73);
  repeater.putRfNeighbourHash(0x99);
  repeater.putBridgeNeighbourHash(0x99, &repeater.ip_bridge);

  repeater.relayRecv(makeDirectRelayPacket(PAYLOAD_TYPE_REQ, 0x73, 0x99));

  ASSERT_NE(repeater.mgr.pending, nullptr)
      << "an RF-heard next hop must never be skipped in favor of a bridge redirect";
}

// Safety guard: FLOOD-route relaying (broadcast to whoever's listening, not
// a single known next hop) must never be redirected, even if the neighbour
// tables happen to have a matching entry for some unrelated reason --
// tryRelayViaBridge() gates on isRouteDirect() specifically because FLOOD
// has no single "next hop" concept to look up.
TEST(DualBridgeAckMirror, FloodPacketNeverRedirectsViaRelayHook) {
  TestTrifectaMesh repeater(0x73);
  repeater.putBridgeNeighbourHash(0x99, &repeater.ip_bridge);

  Packet flood;
  flood.header = ROUTE_TYPE_FLOOD | (PAYLOAD_TYPE_ADVERT << PH_TYPE_SHIFT);
  flood.path[0] = 0x99;
  flood.setPathHashSizeAndCount(1, 1);

  EXPECT_FALSE(repeater.tryRelay(&flood))
      << "FLOOD-route packets must never be redirected by the relay hook";
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
