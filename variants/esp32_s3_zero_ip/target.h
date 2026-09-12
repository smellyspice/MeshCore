#pragma once

#include <helpers/ESP32Board.h>
#include <helpers/esp32/IpBridgeRadio.h>
#include <helpers/SensorManager.h>

extern ESP32Board board;
extern IpBridgeRadio radio_driver;
extern ESP32RTCClock rtc_clock;
extern SensorManager sensors;

bool radio_init();
mesh::LocalIdentity radio_new_identity();
