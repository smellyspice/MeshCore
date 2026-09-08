#include <Arduino.h>
#include "target.h"
#include <helpers/ArduinoHelpers.h>

XiaoS3Board board;

NullRadio radio_driver;

ESP32RTCClock rtc_clock;
SensorManager sensors;

bool radio_init() {
  rtc_clock.begin();

  radio_driver.init();

  return true;  // success -- no real hardware to fail
}

// as we are using the WiFi radio (ESP-NOW), the ESP_IDF will have enabled
// hardware RNG -- see ESP32_S3_Zero's target.cpp for the same reasoning.
class ESP_RNG : public mesh::RNG {
public:
  void random(uint8_t* dest, size_t sz) override {
    esp_fill_random(dest, sz);
  }
};

mesh::LocalIdentity radio_new_identity() {
  ESP_RNG rng;
  return mesh::LocalIdentity(&rng);  // create new random identity
}
