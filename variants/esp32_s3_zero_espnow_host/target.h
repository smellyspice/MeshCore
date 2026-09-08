#pragma once

#include <helpers/esp32/NullRadio.h>
#include <helpers/ESP32Board.h>
#include <helpers/SensorManager.h>

extern ESP32Board board;
extern NullRadio radio_driver;
extern ESP32RTCClock rtc_clock;
extern SensorManager sensors;

bool radio_init();
mesh::LocalIdentity radio_new_identity();
