#include "NullRadio.h"

#ifdef P_LORA_TX_NEOPIXEL_LED
#include <Arduino.h>

#define BOARD_LED_GREEN(pin, brightness) neopixelWrite(pin, brightness, 0, 0)
#define BOARD_LED_RED(pin, brightness)   neopixelWrite(pin, 0, brightness, 0)
#define BOARD_LED_BLUE(pin, brightness)  neopixelWrite(pin, 0, 0, brightness)
#define BOARD_LED_OFF(pin)               neopixelWrite(pin, 0, 0, 0)
#endif

void NullRadio::indicateServerMode() {
#ifdef P_LORA_TX_NEOPIXEL_LED
  BOARD_LED_BLUE(P_LORA_TX_NEOPIXEL_LED, 40);
  _server_led_on = true;
  _server_led_off_at = millis() + 150;
#endif
}

void NullRadio::indicateIpPing() {
#ifdef P_LORA_TX_NEOPIXEL_LED
  BOARD_LED_BLUE(P_LORA_TX_NEOPIXEL_LED, 40);
  _ip_ping_led_on = true;
  _ip_ping_led_off_at = millis() + 120;
#endif
}

void NullRadio::indicatePongReceived() {
#ifdef P_LORA_TX_NEOPIXEL_LED
  BOARD_LED_GREEN(P_LORA_TX_NEOPIXEL_LED, 40);
  _ip_pong_led_on = true;
  _ip_pong_led_off_at = millis() + 180;
#endif
}

void NullRadio::setLinkConnected(bool connected) {
#ifdef P_LORA_TX_NEOPIXEL_LED
  if (connected) {
    _disconnect_blink_active = false;
    if (_disconnect_led_on) {
      BOARD_LED_OFF(P_LORA_TX_NEOPIXEL_LED);
      _disconnect_led_on = false;
    }
  } else {
    _disconnect_blink_active = true;
    // light it immediately so the state is visible right away, not only
    // after the first 500ms interval elapses
    BOARD_LED_RED(P_LORA_TX_NEOPIXEL_LED, 40);
    _disconnect_led_on = true;
    _disconnect_next_toggle_at = millis() + 500;
  }
#endif
}

void NullRadio::loop() {
#ifdef P_LORA_TX_NEOPIXEL_LED
  if (_server_led_on && (int32_t)(millis() - _server_led_off_at) >= 0) {
    BOARD_LED_OFF(P_LORA_TX_NEOPIXEL_LED);
    _server_led_on = false;
  }
  if (_ip_ping_led_on && (int32_t)(millis() - _ip_ping_led_off_at) >= 0) {
    BOARD_LED_OFF(P_LORA_TX_NEOPIXEL_LED);
    _ip_ping_led_on = false;
  }
  if (_ip_pong_led_on && (int32_t)(millis() - _ip_pong_led_off_at) >= 0) {
    BOARD_LED_OFF(P_LORA_TX_NEOPIXEL_LED);
    _ip_pong_led_on = false;
  }
  if (_disconnect_blink_active && (int32_t)(millis() - _disconnect_next_toggle_at) >= 0) {
    if (_disconnect_led_on) {
      BOARD_LED_OFF(P_LORA_TX_NEOPIXEL_LED);
    } else {
      BOARD_LED_RED(P_LORA_TX_NEOPIXEL_LED, 40);
    }
    _disconnect_led_on = !_disconnect_led_on;
    _disconnect_next_toggle_at = millis() + 500;
  }
#endif
}
