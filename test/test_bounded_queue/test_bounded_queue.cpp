#include <gtest/gtest.h>

#include <helpers/BoundedQueue.h>

TEST(BoundedQueue, PreservesOrderAcrossWraparound) {
  mesh::BoundedQueue<int, 4> queue;
  int value = 0;

  for (int i = 0; i < 4; i++) EXPECT_TRUE(queue.push(i));
  EXPECT_FALSE(queue.push(4));

  EXPECT_TRUE(queue.pop(value));
  EXPECT_EQ(0, value);
  EXPECT_TRUE(queue.pop(value));
  EXPECT_EQ(1, value);

  EXPECT_TRUE(queue.push(4));
  EXPECT_TRUE(queue.push(5));

  for (int expected = 2; expected < 6; expected++) {
    EXPECT_TRUE(queue.pop(value));
    EXPECT_EQ(expected, value);
  }
  EXPECT_FALSE(queue.pop(value));
}

TEST(BoundedQueue, SurvivesRepeatedFillAndDrainCycles) {
  mesh::BoundedQueue<int, 4> queue;
  int value = 0;

  for (int cycle = 0; cycle < 1000; cycle++) {
    for (int i = 0; i < 4; i++) EXPECT_TRUE(queue.push(cycle * 4 + i));
    for (int i = 0; i < 4; i++) {
      EXPECT_TRUE(queue.pop(value));
      EXPECT_EQ(cycle * 4 + i, value);
    }
  }
}

TEST(BoundedQueue, ClearDropsPendingItems) {
  mesh::BoundedQueue<int, 4> queue;
  int value = 0;

  EXPECT_TRUE(queue.push(1));
  EXPECT_TRUE(queue.push(2));
  queue.clear();

  EXPECT_EQ(0u, queue.size());
  EXPECT_FALSE(queue.pop(value));
  EXPECT_TRUE(queue.push(3));
  EXPECT_TRUE(queue.pop(value));
  EXPECT_EQ(3, value);
}

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
