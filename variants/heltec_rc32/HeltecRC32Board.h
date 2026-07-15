#pragma once

#include <Arduino.h>
#include <driver/rtc_io.h>
#include <helpers/ESP32Board.h>
#include <helpers/RefCountedDigitalPin.h>
#if defined(UI_HAS_ROTARY_INPUT)
#include <helpers/ui/RotaryInput.h>
#endif

#ifndef ADC_MULTIPLIER
  #define ADC_MULTIPLIER 4.9f
#endif

class HeltecRC32Board : public ESP32Board {
protected:
  float adc_mult = ADC_MULTIPLIER;

public:
  RefCountedDigitalPin periph_power;

  HeltecRC32Board() : periph_power(SENSOR_POWER_CTRL_PIN, SENSOR_POWER_ON){}

  void begin();
#if defined(UI_HAS_ROTARY_INPUT)
  RotaryInput& rotaryInput();
#endif
  void onBeforeTransmit() override;
  void onAfterTransmit() override;
  void powerOff() override;
  uint16_t getBattMilliVolts() override;
  bool setAdcMultiplier(float multiplier) override;
  float getAdcMultiplier() const override { return adc_mult; }
  const char* getManufacturerName() const override;
};
