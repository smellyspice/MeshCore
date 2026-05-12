#pragma once

#include <Arduino.h>
#include <MeshCore.h>
#include <helpers/NRF52Board.h>

class HeltecTowerV2Board : public NRF52BoardDCDC {
protected:
#ifdef NRF52_POWER_MANAGEMENT
  void initiateShutdown(uint8_t reason) override;
#endif

public:
  HeltecTowerV2Board() : NRF52Board("TOWER_V2_OTA") {}
  void begin();
#ifdef P_LORA_TX_LED
  void onBeforeTransmit() override;
  void onAfterTransmit() override;
#endif
  uint16_t getBattMilliVolts() override;
  const char* getManufacturerName() const override;
  void powerOff() override;
};
