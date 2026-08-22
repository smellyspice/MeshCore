// Tests "theory 3" from planning/bridge-direct-routing-path-gap.md:
// BridgeBase declares ONE SimpleMeshTables _seen_packets member, and every
// concrete bridge (RS232Bridge, ESPNowBridge, IpBridge) checks/marks that
// SAME instance from both directions -- BridgeBase::handleReceivedPacket()
// on RX, and each bridge's own sendPacket() on TX (confirmed identical
// 3-line guard in all three: `if (!_seen_packets.wasSeen(p)) { markSeen(p); ... }`,
// see src/helpers/bridges/{RS232,ESPNow,Ip}Bridge.cpp).
//
// This uses the REAL production mesh::SimpleMeshTables class (not a
// reimplementation) -- the actual defect is in how BridgeBase shares one
// instance across both call sites, which this test reproduces directly by
// mirroring those two real call sites against one shared table, exactly as
// BridgeBase's declaration does.
#include <gtest/gtest.h>
#include "helpers/SimpleMeshTables.h"

using namespace mesh;

namespace {

Packet makePacket(uint8_t seed) {
  Packet p;
  p.header = ROUTE_TYPE_FLOOD | (PAYLOAD_TYPE_TXT_MSG << PH_TYPE_SHIFT);
  p.payload[0] = seed;
  p.payload_len = 1;
  p.path_len = 0;
  return p;
}

// Mirrors BridgeBase::handleReceivedPacket()'s dedup guard exactly.
bool simulateBridgeRx(SimpleMeshTables& seen, Packet* pkt) {
  if (!seen.wasSeen(pkt)) {
    seen.markSeen(pkt);
    return true;  // queued for local mesh processing
  }
  return false;  // dropped as a dup
}

// Mirrors {RS232,ESPNow,Ip}Bridge::sendPacket()'s dedup guard exactly.
bool simulateBridgeTx(SimpleMeshTables& seen, Packet* pkt) {
  if (!seen.wasSeen(pkt)) {
    seen.markSeen(pkt);
    return true;  // actually sent
  }
  return false;  // silently dropped -- no log line in IpBridge, per the doc
}

}  // namespace

TEST(BridgeSharedDedupCache, IndependentPacketCrossingOppositeDirectionIsNotBlocked) {
  SimpleMeshTables seen;  // BridgeBase's single _seen_packets instance

  Packet inbound = makePacket(0x01);
  EXPECT_TRUE(simulateBridgeRx(seen, &inbound)) << "sanity: first RX of a new packet is accepted";

  Packet unrelated_outbound = makePacket(0x02);  // different content -> different hash
  EXPECT_TRUE(simulateBridgeTx(seen, &unrelated_outbound))
      << "an unrelated packet crossing the other direction should not be affected";
}

// The actual defect: content-identical packets legitimately need to cross a
// bridge in BOTH directions in normal operation -- e.g. the same reply
// packet's hash colliding with something the bridge already relayed
// recently the other way (retransmission, or a packet that legitimately
// needs to bounce back out the way it came). Because RX and TX share one
// dedup table, the second crossing is silently swallowed regardless of
// which direction it's actually going.
TEST(BridgeSharedDedupCache, IdenticalPacketNeedingToCrossOppositeDirectionIsSilentlyDropped) {
  SimpleMeshTables seen;

  Packet inbound = makePacket(0x42);
  ASSERT_TRUE(simulateBridgeRx(seen, &inbound));

  // Same content (same calculatePacketHash()) now needs to go out the OTHER
  // direction shortly after -- e.g. this exact payload/type bouncing back.
  Packet outbound_same_content = makePacket(0x42);
  EXPECT_FALSE(simulateBridgeTx(seen, &outbound_same_content))
      << "BridgeBase's shared _seen_packets means this real, independent "
         "crossing is dropped -- no log line, since IpBridge has no 'TX ok' "
         "debug print (unlike ESPNowBridge), matching the doc's account of "
         "why this was hard to observe live";
}

// Validates the fix direction the doc proposes: separate RX/TX dedup state
// removes the false-positive entirely, with zero effect on real duplicate
// detection within each direction.
TEST(BridgeSharedDedupCache, SeparateRxTxTablesFixesTheCrossDirectionFalsePositive) {
  SimpleMeshTables rx_seen, tx_seen;

  Packet inbound = makePacket(0x42);
  ASSERT_TRUE(simulateBridgeRx(rx_seen, &inbound));

  Packet outbound_same_content = makePacket(0x42);
  EXPECT_TRUE(simulateBridgeTx(tx_seen, &outbound_same_content))
      << "with independent tables, the TX-direction crossing is judged "
         "purely on its own history and goes through correctly";

  // Real duplicate suppression within a single direction still works.
  Packet outbound_retry = makePacket(0x42);
  EXPECT_FALSE(simulateBridgeTx(tx_seen, &outbound_retry))
      << "a genuine repeat send in the same direction is still deduped";
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
