#pragma once

#include <cstdint>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include "Stream.h"

inline uint32_t g_mock_millis = 0;

using std::isnan;

inline uint32_t millis() {
  return g_mock_millis;
}

inline void delay(uint32_t ms) {
  g_mock_millis += ms;
}

inline char* ltoa(long value, char* result, int base) {
  snprintf(result, 32, base == 16 ? "%lx" : "%ld", value);
  return result;
}
