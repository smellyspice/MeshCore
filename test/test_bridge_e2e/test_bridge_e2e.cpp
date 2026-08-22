// Full software-only, end-to-end reproduction of the trifecta hardware
// topology described in planning/bridge-direct-routing-path-gap.md:
//
//   CompanionA -- RepeaterA <==bridge==> RepeaterB -- CompanionB
//
// Every node runs the REAL production classes (mesh::Mesh, mesh::Dispatcher,
// BaseChatMesh, mesh::StaticPoolPacketManager), driven through real
// Dispatcher::loop() cycles -- not a reimplementation of routing logic. The
// only things stood in for are: the physical radio (a simple broadcast
// medium standing in for LoRa), the bridge transport (an in-process
// equivalent of BridgeBase's RX/TX guard -- see TestBridge below), and the
// AES/SHA256 mock backends (upgraded from pure no-ops to real, reversible
// XOR-based substitutes so encrypted payloads actually round-trip -- see
// test/mocks/AES.h and SHA256.h).
//
// Goal: settle, with reproducible software evidence, whether the confirmed
// bugs (bridge path-crossing under logRx, out_path asymmetry, shared RX/TX
// dedup cache under logTx) actually compose into the "stuck until 3rd
// attempt" symptom seen on hardware -- or whether they don't, in which case
// something else is responsible and more guessing should stop.
#include <gtest/gtest.h>
#include <helpers/BaseChatMesh.h>
#include <helpers/StaticPoolPacketManager.h>
#include <helpers/SimpleMeshTables.h>
#include <cstring>
#include <vector>
#include <deque>
#include <memory>

using namespace mesh;

namespace {

// ─── shared virtual clock/RTC ───────────────────────────────────────────────

struct SharedClock : public MillisecondClock {
  unsigned long now = 0;
  unsigned long getMillis() override { return now; }
};

struct SharedRTC : public RTCClock {
  uint32_t getCurrentTime() override { return 1000; }
  void setCurrentTime(uint32_t) override {}
};

struct ZeroRNG : public RNG {
  void random(uint8_t* dest, size_t sz) override { memset(dest, 0, sz); }
};

// ─── broadcast RF medium (stands in for a shared LoRa channel) ─────────────

struct RfMedium {
  struct Pending { const void* sender; std::vector<uint8_t> bytes; };
  std::vector<Pending> in_flight;
};

class MediumRadio : public Radio {
  RfMedium& _medium;
  std::deque<std::vector<uint8_t>> _inbox;
public:
  explicit MediumRadio(RfMedium& medium) : _medium(medium) {}

  int recvRaw(uint8_t* dest, int maxlen) override {
    if (_inbox.empty()) return 0;
    auto& frame = _inbox.front();
    int n = (int)frame.size() < maxlen ? (int)frame.size() : maxlen;
    memcpy(dest, frame.data(), n);
    _inbox.pop_front();
    return n;
  }
  uint32_t getEstAirtimeFor(int) override { return 10; }
  float packetScore(float, int) override { return 1.0f; }
  bool startSendRaw(const uint8_t* bytes, int len) override {
    // sender identity is this MediumRadio itself -- matches the `r` values
    // pumpMedium() compares against below, so self-echo is actually excluded.
    _medium.in_flight.push_back({this, std::vector<uint8_t>(bytes, bytes + len)});
    return true;
  }
  bool isSendComplete() override { return true; }
  void onSendFinished() override {}
  bool isInRecvMode() const override { return true; }

  void deliver(const std::vector<uint8_t>& bytes) { _inbox.push_back(bytes); }
};

// After every node has had a chance to loop() once, fan out anything
// transmitted this tick to every OTHER radio sharing the same medium.
void pumpMedium(RfMedium& medium, const std::vector<MediumRadio*>& radios) {
  auto in_flight = std::move(medium.in_flight);
  medium.in_flight.clear();
  for (auto& frame : in_flight) {
    for (auto* r : radios) {
      if ((const void*)r != frame.sender) r->deliver(frame.bytes);
    }
  }
}

// ─── in-process bridge (mirrors BridgeBase's RX/TX guard + SimpleMeshTables) ──
//
// Real BridgeBase declares ONE SimpleMeshTables _seen_packets checked/marked
// from both handleReceivedPacket() (RX) and every subclass's sendPacket()
// (TX) -- see src/helpers/bridges/BridgeBase.{h,cpp} and {Ip,ESPNow,RS232}
// Bridge.cpp's identical 3-line TX guard. shared_dedup selects which of
// those two real-world configurations this instance reproduces.
class TestBridge {
  PacketManager& _mgr;
  SharedClock& _clock;
  SimpleMeshTables _table_owned_rx, _table_owned_tx;
  SimpleMeshTables* _rx_seen;
  SimpleMeshTables* _tx_seen;
  TestBridge* _peer = nullptr;
  uint32_t _bridge_delay_ms;
public:
  TestBridge(PacketManager& mgr, SharedClock& clock, bool shared_dedup, uint32_t bridge_delay_ms)
    : _mgr(mgr), _clock(clock), _bridge_delay_ms(bridge_delay_ms) {
    if (shared_dedup) {
      _rx_seen = _tx_seen = &_table_owned_rx;   // the real (buggy) BridgeBase shape
    } else {
      _rx_seen = &_table_owned_rx;
      _tx_seen = &_table_owned_tx;              // the proposed fix
    }
  }

  void setPeer(TestBridge* p) { _peer = p; }

  // mirrors BridgeBase::handleReceivedPacket()
  void handleReceivedPacket(Packet* pkt) {
    if (!_rx_seen->wasSeen(pkt)) {
      _rx_seen->markSeen(pkt);
      pkt->_src_bridge = this;
      _mgr.queueInbound(pkt, _clock.now + _bridge_delay_ms);
    } else {
      _mgr.free(pkt);
    }
  }

  // mirrors {Ip,ESPNow,RS232}Bridge::sendPacket()
  void sendPacket(Packet* pkt) {
    if (!_peer) return;
    if (!_tx_seen->wasSeen(pkt)) {
      _tx_seen->markSeen(pkt);
      uint8_t buf[MAX_TRANS_UNIT + 1];
      uint8_t len = pkt->writeTo(buf);
      Packet* copy = _peer->_mgr.allocNew();
      if (copy) {
        copy->readFrom(buf, len);
        _peer->handleReceivedPacket(copy);
      }
    }
  }
};

// ─── repeater node (real mesh::Mesh, mirrors examples/simple_repeater/MyMesh's
//     forwarding + logRx/logTx bridge hooks) ────────────────────────────────

struct FakeMeshDeps {
  ZeroRNG rng;
  SimpleMeshTables tables;
};

class TestRepeaterMesh : public FakeMeshDeps, public Mesh {
public:
  TestBridge* bridge = nullptr;
  uint8_t bridge_pkt_src = 0;   // 0 = logTx (default), 1 = logRx

  TestRepeaterMesh(Radio& radio, SharedClock& clock, SharedRTC& rtc, PacketManager& mgr, uint8_t hash_byte)
    : FakeMeshDeps(), Mesh(radio, clock, rng, rtc, mgr, tables) {
    memset(self_id.pub_key, 0, PUB_KEY_SIZE);
    self_id.pub_key[0] = hash_byte;
  }

  bool allowPacketForward(const Packet*) override { return true; }
  uint32_t getDirectRetransmitDelay(const Packet*) override { return 0; }

  // mirrors examples/simple_repeater/MyMesh.cpp's logRx()/logTx()
  void logRx(Packet* pkt, int, float) override {
    if (bridge && bridge_pkt_src == 1) bridge->sendPacket(pkt);
  }
  void logTx(Packet* pkt, int) override {
    if (bridge && bridge_pkt_src == 0) bridge->sendPacket(pkt);
  }
};

// ─── companion node (real BaseChatMesh) ────────────────────────────────────

class TestChatMesh : public FakeMeshDeps, public BaseChatMesh {
public:
  bool got_ack = false;
  uint32_t expected_ack_crc = 0;
  bool discovered_contact = false;

  TestChatMesh(Radio& radio, SharedClock& clock, SharedRTC& rtc, PacketManager& mgr, uint8_t hash_byte)
    : FakeMeshDeps(), BaseChatMesh(radio, clock, rng, rtc, mgr, tables) {
    memset(self_id.pub_key, 0, PUB_KEY_SIZE);
    self_id.pub_key[0] = hash_byte;
  }

  void onDiscoveredContact(ContactInfo&, bool, uint8_t, const uint8_t*) override { discovered_contact = true; }
  ContactInfo* processAck(const uint8_t* data) override {
    uint32_t crc;
    memcpy(&crc, data, 4);
    if (crc == expected_ack_crc) {
      got_ack = true;
      return contacts_dummy();
    }
    return nullptr;
  }
  void onContactPathUpdated(const ContactInfo&) override {}
  void onMessageRecv(const ContactInfo&, Packet*, uint32_t, const char*) override {}
  void onCommandDataRecv(const ContactInfo&, Packet*, uint32_t, const char*) override {}
  void onSignedMessageRecv(const ContactInfo&, Packet*, uint32_t, const uint8_t*, const char*) override {}
  uint32_t calcFloodTimeoutMillisFor(uint32_t) const override { return 30000; }
  uint32_t calcDirectTimeoutMillisFor(uint32_t, uint8_t) const override { return 30000; }
  void onSendTimeout() override {}
  void onChannelMessageRecv(const GroupChannel&, Packet*, uint32_t, const char*) override {}
  uint8_t onContactRequest(const ContactInfo&, uint32_t, const uint8_t*, uint8_t, uint8_t*) override { return 0; }
  void onContactResponse(const ContactInfo&, const uint8_t*, uint8_t) override {}

private:
  // processAck() only needs to signal "matched" via non-null; content unused
  // by the base class beyond the null check (see BaseChatMesh.cpp callers).
  ContactInfo* contacts_dummy() { static ContactInfo dummy; return &dummy; }
};

ContactInfo makeContact(uint8_t key_byte, const char* name) {
  ContactInfo ci;
  memset(&ci, 0, sizeof(ci));
  ci.id.pub_key[0] = key_byte;
  ci.type = ADV_TYPE_CHAT;
  strncpy(ci.name, name, sizeof(ci.name) - 1);
  ci.out_path_len = OUT_PATH_UNKNOWN;
  ci.lastmod = 1000;
  return ci;
}

// ─── topology ───────────────────────────────────────────────────────────────

enum class Mode { STOCK_RF, BRIDGED_LOGTX_SHARED_DEDUP, BRIDGED_LOGRX_SHARED_DEDUP, BRIDGED_LOGTX_SEPARATE_DEDUP };

struct Topology {
  SharedClock clock;
  SharedRTC rtc;

  RfMedium side_a_medium;   // CompanionA <-> RepeaterA (or, in STOCK, everyone)
  RfMedium side_b_medium;   // RepeaterB <-> CompanionB (unused in STOCK)

  std::unique_ptr<MediumRadio> radio_a_companion, radio_a_repeater, radio_b_repeater, radio_b_companion;
  std::unique_ptr<StaticPoolPacketManager> mgr_a_companion, mgr_a_repeater, mgr_b_repeater, mgr_b_companion;
  std::unique_ptr<TestChatMesh> companionA, companionB;
  std::unique_ptr<TestRepeaterMesh> repeaterA, repeaterB;
  std::unique_ptr<TestBridge> bridge_a, bridge_b;

  Mode mode;

  Topology(Mode m, bool pre_add_contacts = true) : mode(m) {
    mgr_a_companion = std::make_unique<StaticPoolPacketManager>(16);
    mgr_a_repeater = std::make_unique<StaticPoolPacketManager>(16);
    mgr_b_repeater = std::make_unique<StaticPoolPacketManager>(16);
    mgr_b_companion = std::make_unique<StaticPoolPacketManager>(16);

    if (m == Mode::STOCK_RF) {
      // everyone shares one medium: a plain 4-node multi-hop RF mesh, no bridge.
      radio_a_companion = std::make_unique<MediumRadio>(side_a_medium);
      radio_a_repeater = std::make_unique<MediumRadio>(side_a_medium);
      radio_b_repeater = std::make_unique<MediumRadio>(side_a_medium);
      radio_b_companion = std::make_unique<MediumRadio>(side_a_medium);
    } else {
      // segregated: repeaters are NOT in RF range of each other (that's the
      // whole reason to bridge) -- only the bridge connects them.
      radio_a_companion = std::make_unique<MediumRadio>(side_a_medium);
      radio_a_repeater = std::make_unique<MediumRadio>(side_a_medium);
      radio_b_repeater = std::make_unique<MediumRadio>(side_b_medium);
      radio_b_companion = std::make_unique<MediumRadio>(side_b_medium);
    }

    companionA = std::make_unique<TestChatMesh>(*radio_a_companion, clock, rtc, *mgr_a_companion, 0xA0);
    repeaterA = std::make_unique<TestRepeaterMesh>(*radio_a_repeater, clock, rtc, *mgr_a_repeater, 0xA1);
    repeaterB = std::make_unique<TestRepeaterMesh>(*radio_b_repeater, clock, rtc, *mgr_b_repeater, 0xB1);
    companionB = std::make_unique<TestChatMesh>(*radio_b_companion, clock, rtc, *mgr_b_companion, 0xB0);

    if (m != Mode::STOCK_RF) {
      bool shared_dedup = (m != Mode::BRIDGED_LOGTX_SEPARATE_DEDUP);
      bridge_a = std::make_unique<TestBridge>(*mgr_a_repeater, clock, shared_dedup, /*bridge_delay_ms=*/10);
      bridge_b = std::make_unique<TestBridge>(*mgr_b_repeater, clock, shared_dedup, /*bridge_delay_ms=*/10);
      bridge_a->setPeer(bridge_b.get());
      bridge_b->setPeer(bridge_a.get());
      repeaterA->bridge = bridge_a.get();
      repeaterB->bridge = bridge_b.get();
      uint8_t pkt_src = (m == Mode::BRIDGED_LOGRX_SHARED_DEDUP) ? 1 : 0;
      repeaterA->bridge_pkt_src = pkt_src;
      repeaterB->bridge_pkt_src = pkt_src;
    }

    companionA->begin();
    repeaterA->begin();
    repeaterB->begin();
    companionB->begin();

    // A and B already know each other (adverts exchanged previously) but have
    // never sent a direct-routed message -- matches "already-a-contact"
    // real-world state, isolating path-learning/routing behavior from advert
    // propagation (tested separately below). Skipped when the test wants to
    // exercise genuine advert-based discovery across the bridge instead.
    if (pre_add_contacts) {
      companionA->addContact(makeContact(0xB0, "B"));
      companionB->addContact(makeContact(0xA0, "A"));
    }
  }

  void tick(int n = 1) {
    for (int i = 0; i < n; i++) {
      clock.now += 20;
      companionA->loop();
      repeaterA->loop();
      repeaterB->loop();
      companionB->loop();

      if (mode == Mode::STOCK_RF) {
        pumpMedium(side_a_medium, {radio_a_companion.get(), radio_a_repeater.get(),
                                    radio_b_repeater.get(), radio_b_companion.get()});
      } else {
        pumpMedium(side_a_medium, {radio_a_companion.get(), radio_a_repeater.get()});
        pumpMedium(side_b_medium, {radio_b_repeater.get(), radio_b_companion.get()});
      }
    }
  }
};

ContactInfo* lookupB(TestChatMesh& a) {
  uint8_t key[PUB_KEY_SIZE] = {0};
  key[0] = 0xB0;
  return a.lookupContactByPubKey(key, PUB_KEY_SIZE);
}

ContactInfo* lookupA(TestChatMesh& b) {
  uint8_t key[PUB_KEY_SIZE] = {0};
  key[0] = 0xA0;
  return b.lookupContactByPubKey(key, PUB_KEY_SIZE);
}

// Sends one message A->B using whatever out_path state currently exists
// (exactly what a real client does -- no artificial retry logic here, since
// attempt/retry/flood-escalation policy lives in application code outside
// this repo, not in BaseChatMesh itself). Returns the number of ticks until
// A's ACK arrived, or -1 if it never did within max_ticks.
int sendAndWaitForAck(Topology& topo, const char* text, int max_ticks = 200) {
  ContactInfo* b = lookupB(*topo.companionA);
  if (!b) return -1;

  topo.companionA->got_ack = false;
  uint32_t expected_ack = 0, est_timeout = 0;
  int rc = topo.companionA->sendMessage(*b, topo.clock.now, 0, text, expected_ack, est_timeout);
  if (rc == MSG_SEND_FAILED) return -1;
  topo.companionA->expected_ack_crc = expected_ack;

  for (int t = 0; t < max_ticks; t++) {
    topo.tick();
    if (topo.companionA->got_ack) return t;
  }
  return -1;
}

}  // namespace

// ─── the decisive comparison ────────────────────────────────────────────────

TEST(BridgeEndToEnd, StockRfMultiHopDeliversThreeConsecutiveMessages) {
  Topology topo(Mode::STOCK_RF);
  EXPECT_GE(sendAndWaitForAck(topo, "msg one"), 0) << "message 1 (flood, no path yet) should be ACKed";
  EXPECT_GE(sendAndWaitForAck(topo, "msg two"), 0) << "message 2 should be ACKed";
  EXPECT_GE(sendAndWaitForAck(topo, "msg three"), 0) << "message 3 should be ACKed";
}

TEST(BridgeEndToEnd, BridgedLogTxDefaultDeliversThreeConsecutiveMessagesJustAsFluidly) {
  Topology topo(Mode::BRIDGED_LOGTX_SHARED_DEDUP);   // real default config: logTx + shared dedup
  int t1 = sendAndWaitForAck(topo, "msg one");
  int t2 = sendAndWaitForAck(topo, "msg two");
  int t3 = sendAndWaitForAck(topo, "msg three");
  EXPECT_GE(t1, 0) << "message 1 (flood) should be ACKed";
  EXPECT_GE(t2, 0) << "message 2 should be ACKed -- if this fails, the default bridge config "
                       "reproduces the hardware symptom in software";
  EXPECT_GE(t3, 0) << "message 3 should be ACKed";
}

// First finding here, NOT predicted going in: under logRx, a repeater
// bridges a flood packet BEFORE its own onRecvPacket()/routeRecvPacket()
// runs -- so the copy that crosses the bridge is captured before that
// repeater appends its own hash to path[]. In this 2-repeater topology that
// means A's learned out_path ends up as just [RepeaterB] (1 hop), never
// [RepeaterA, RepeaterB] (2 hops) -- RepeaterA's hash is silently missing
// from flood-accumulated paths under logRx, not just corrupted for direct
// packets as originally catalogued. That's a second, previously unknown
// logRx defect, distinct from (and upstream of) the path-crossing bug the
// bridge_routing suite proved.
TEST(BridgeEndToEnd, LogRxAlsoCorruptsFloodPathAccumulation) {
  Topology topo(Mode::BRIDGED_LOGRX_SHARED_DEDUP);
  ASSERT_GE(sendAndWaitForAck(topo, "msg one"), 0);

  ContactInfo* b_on_a = lookupB(*topo.companionA);
  ASSERT_NE(b_on_a, nullptr);
  EXPECT_EQ(b_on_a->out_path_len, 1)
      << "expected the flood-accumulation bug to produce a 1-hop path here; "
         "if this now fails, logRx's flood behavior has changed and this "
         "test's premise needs re-checking";
}

// This is the scenario the bridge_routing suite's isolated tests actually
// proved (a genuine 2-hop path, [RepeaterA, RepeaterB], crossing under
// logRx timing) -- forced explicitly here since the natural flood-learned
// path in this topology is only 1 hop (see test above), which sidesteps the
// original bug by accident. A real multi-repeater chain, or a path cached
// before switching to logRx, would produce a genuine 2+-hop path naturally.
TEST(BridgeEndToEnd, BridgedLogRxDropsAGenuineTwoHopDirectMessage) {
  Topology topo(Mode::BRIDGED_LOGRX_SHARED_DEDUP);
  ASSERT_GE(sendAndWaitForAck(topo, "msg one"), 0);

  ContactInfo* b_on_a = lookupB(*topo.companionA);
  ASSERT_NE(b_on_a, nullptr);
  b_on_a->out_path[0] = 0xA1;  // RepeaterA
  b_on_a->out_path[1] = 0xB1;  // RepeaterB
  b_on_a->out_path_len = 2;

  int t2 = sendAndWaitForAck(topo, "msg two", /*max_ticks=*/50);
  EXPECT_LT(t2, 0) << "a genuine 2-hop direct path should silently and permanently fail to "
                       "cross under logRx, per the confirmed bridge_routing test";
}

TEST(BridgeEndToEnd, SeparateDedupTablesDoesNotRegressAnything) {
  Topology topo(Mode::BRIDGED_LOGTX_SEPARATE_DEDUP);
  EXPECT_GE(sendAndWaitForAck(topo, "msg one"), 0);
  EXPECT_GE(sendAndWaitForAck(topo, "msg two"), 0);
  EXPECT_GE(sendAndWaitForAck(topo, "msg three"), 0);
}


// Stress test: sustained bidirectional traffic is where the shared RX/TX
// dedup cache (theory 3) would actually have a chance to collide -- unlike
// the simple A->B-only sequence above. If this ever fails while the STOCK
// baseline doesn't, that isolates the dedup cache as a real contributor
// under realistic (not just worst-case single-message) conditions.
TEST(BridgeEndToEnd, SustainedBidirectionalTrafficDefaultConfig) {
  Topology topo(Mode::BRIDGED_LOGTX_SHARED_DEDUP);
  int failures = 0;
  for (int i = 0; i < 10; i++) {
    char buf[32];
    snprintf(buf, sizeof(buf), "a->b #%d", i);
    if (sendAndWaitForAck(topo, buf, 100) < 0) failures++;

    ContactInfo* a_on_b = lookupA(*topo.companionB);
    ASSERT_NE(a_on_b, nullptr);
    topo.companionB->got_ack = false;
    uint32_t expected_ack = 0, est_timeout = 0;
    char buf2[32];
    snprintf(buf2, sizeof(buf2), "b->a #%d", i);
    topo.companionB->sendMessage(*a_on_b, topo.clock.now, 0, buf2, expected_ack, est_timeout);
    topo.companionB->expected_ack_crc = expected_ack;
    bool acked = false;
    for (int t = 0; t < 100; t++) {
      topo.tick();
      if (topo.companionB->got_ack) { acked = true; break; }
    }
    if (!acked) failures++;
  }
  EXPECT_EQ(failures, 0) << failures << " of 20 messages in a sustained bidirectional exchange "
                             "were never ACKed under default (logTx, shared dedup) bridge config";
}

TEST(BridgeEndToEnd, StockRfSustainedBidirectionalTrafficBaseline) {
  Topology topo(Mode::STOCK_RF);
  int failures = 0;
  for (int i = 0; i < 10; i++) {
    char buf[32];
    snprintf(buf, sizeof(buf), "a->b #%d", i);
    if (sendAndWaitForAck(topo, buf, 100) < 0) failures++;

    ContactInfo* a_on_b = lookupA(*topo.companionB);
    ASSERT_NE(a_on_b, nullptr);
    topo.companionB->got_ack = false;
    uint32_t expected_ack = 0, est_timeout = 0;
    char buf2[32];
    snprintf(buf2, sizeof(buf2), "b->a #%d", i);
    topo.companionB->sendMessage(*a_on_b, topo.clock.now, 0, buf2, expected_ack, est_timeout);
    topo.companionB->expected_ack_crc = expected_ack;
    bool acked = false;
    for (int t = 0; t < 100; t++) {
      topo.tick();
      if (topo.companionB->got_ack) { acked = true; break; }
    }
    if (!acked) failures++;
  }
  EXPECT_EQ(failures, 0) << failures << " of 20 messages failed on the stock (no-bridge) baseline";
}

// Different code path entirely from DM/ACK: pure flood, no direct routing,
// no prior contact relationship (tests genuine discovery, not just delivery
// to an already-known peer). Adverts are how companions/repeaters actually
// find each other in the first place -- if this doesn't cross the bridge,
// nothing downstream matters.
TEST(BridgeEndToEnd, AdvertPropagatesAcrossBridgeUnderDefaultConfig) {
  Topology topo(Mode::BRIDGED_LOGTX_SHARED_DEDUP, /*pre_add_contacts=*/false);

  Packet* advert = topo.companionA->createSelfAdvert("CompanionA");
  ASSERT_NE(advert, nullptr);
  topo.companionA->sendFlood(advert);

  bool discovered = false;
  for (int t = 0; t < 100; t++) {
    topo.tick();
    if (topo.companionB->discovered_contact) { discovered = true; break; }
  }
  EXPECT_TRUE(discovered) << "CompanionB never discovered CompanionA's advert across the bridge";
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
