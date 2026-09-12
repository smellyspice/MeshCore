#include <Arduino.h>
#include "target.h"
#include <helpers/ArduinoHelpers.h>

ESP32Board board;

IpBridgeRadio radio_driver(board);

ESP32RTCClock rtc_clock;
SensorManager sensors;

bool radio_init() {
  rtc_clock.begin();

  radio_driver.init();

  return true;  // success
}

// as we are using the WiFi radio, the ESP_IDF will have enabled hardware RNG --
// see esp32_s3_zero's own target.cpp for the same reasoning.
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
