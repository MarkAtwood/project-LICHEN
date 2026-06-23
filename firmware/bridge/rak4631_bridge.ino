// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project
//
// Serial-to-LoRa bridge for RAK4631 (nRF52840 + SX1262)
// Exposes raw LoRa TX/RX over USB serial for host-side development.
//
// Protocol (text-based, easy to debug):
//   TX <hex>\n          - transmit packet
//   RX <rssi> <snr> <hex>\n  - received packet (from radio)
//   CFG SF=10 BW=125 CR=5 FREQ=915000000\n - configure radio
//   OK\n / ERR <msg>\n  - responses
//
// Example:
//   Host sends:  TX 48454c4c4f\n
//   Radio sends: OK\n
//   Radio receives, sends: RX -85 7.5 48454c4c4f\n

#include <RadioLib.h>
#include <SPI.h>

// RAK4631 SX1262 pins
#define LORA_NSS   42
#define LORA_DIO1  47
#define LORA_BUSY  46
#define LORA_RST   38

SX1262 radio = new Module(LORA_NSS, LORA_DIO1, LORA_RST, LORA_BUSY);

// Default LICHEN radio parameters (from spec)
float frequency = 915.0;    // MHz
float bandwidth = 125.0;    // kHz
uint8_t spreadingFactor = 10;
uint8_t codingRate = 5;     // 4/5
int8_t power = 22;          // dBm

volatile bool rxFlag = false;

void setFlag() {
  rxFlag = true;
}

void setup() {
  Serial.begin(115200);
  while (!Serial && millis() < 3000); // Wait for USB, but not forever

  Serial.println("# LICHEN bridge starting");

  int state = radio.begin(frequency, bandwidth, spreadingFactor, codingRate,
                          RADIOLIB_SX126X_SYNC_WORD_PRIVATE, power);
  if (state != RADIOLIB_ERR_NONE) {
    Serial.print("ERR radio init failed: ");
    Serial.println(state);
    while (1);
  }

  radio.setDio1Action(setFlag);
  radio.startReceive();

  Serial.println("OK ready");
}

char lineBuf[1024];
int lineLen = 0;

uint8_t pktBuf[256];

int hexCharToNibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

int hexDecode(const char* hex, uint8_t* out, int maxLen) {
  int len = 0;
  while (*hex && *(hex+1) && len < maxLen) {
    int hi = hexCharToNibble(*hex++);
    int lo = hexCharToNibble(*hex++);
    if (hi < 0 || lo < 0) return -1;
    out[len++] = (hi << 4) | lo;
  }
  return len;
}

void hexEncode(const uint8_t* data, int len, char* out) {
  const char* hex = "0123456789abcdef";
  for (int i = 0; i < len; i++) {
    *out++ = hex[data[i] >> 4];
    *out++ = hex[data[i] & 0x0f];
  }
  *out = '\0';
}

void processLine() {
  lineBuf[lineLen] = '\0';

  if (strncmp(lineBuf, "TX ", 3) == 0) {
    // Transmit packet
    int pktLen = hexDecode(lineBuf + 3, pktBuf, sizeof(pktBuf));
    if (pktLen < 0) {
      Serial.println("ERR bad hex");
      return;
    }

    int state = radio.transmit(pktBuf, pktLen);
    if (state == RADIOLIB_ERR_NONE) {
      Serial.println("OK");
    } else {
      Serial.print("ERR tx failed: ");
      Serial.println(state);
    }

    radio.startReceive();  // Back to RX mode

  } else if (strncmp(lineBuf, "CFG ", 4) == 0) {
    // Parse config: CFG SF=10 BW=125 CR=5 FREQ=915000000
    char* p = lineBuf + 4;

    while (*p) {
      while (*p == ' ') p++;

      if (strncmp(p, "SF=", 3) == 0) {
        spreadingFactor = atoi(p + 3);
      } else if (strncmp(p, "BW=", 3) == 0) {
        bandwidth = atof(p + 3);
      } else if (strncmp(p, "CR=", 3) == 0) {
        codingRate = atoi(p + 3);
      } else if (strncmp(p, "FREQ=", 5) == 0) {
        frequency = atof(p + 5) / 1000000.0;  // Hz to MHz
      } else if (strncmp(p, "PWR=", 4) == 0) {
        power = atoi(p + 4);
      }

      while (*p && *p != ' ') p++;
    }

    radio.standby();
    radio.setFrequency(frequency);
    radio.setBandwidth(bandwidth);
    radio.setSpreadingFactor(spreadingFactor);
    radio.setCodingRate(codingRate);
    radio.setOutputPower(power);
    radio.startReceive();

    Serial.print("OK SF=");
    Serial.print(spreadingFactor);
    Serial.print(" BW=");
    Serial.print(bandwidth);
    Serial.print(" CR=");
    Serial.print(codingRate);
    Serial.print(" FREQ=");
    Serial.print(frequency * 1000000, 0);
    Serial.print(" PWR=");
    Serial.println(power);

  } else if (strcmp(lineBuf, "STATUS") == 0) {
    Serial.print("OK SF=");
    Serial.print(spreadingFactor);
    Serial.print(" BW=");
    Serial.print(bandwidth);
    Serial.print(" CR=");
    Serial.print(codingRate);
    Serial.print(" FREQ=");
    Serial.print(frequency * 1000000, 0);
    Serial.print(" PWR=");
    Serial.println(power);

  } else if (lineLen > 0) {
    Serial.println("ERR unknown command");
  }
}

void loop() {
  // Handle serial input
  while (Serial.available()) {
    char c = Serial.read();
    if (c == '\n' || c == '\r') {
      if (lineLen > 0) {
        processLine();
        lineLen = 0;
      }
    } else if (lineLen < (int)sizeof(lineBuf) - 1) {
      lineBuf[lineLen++] = c;
    }
  }

  // Handle received packets
  if (rxFlag) {
    rxFlag = false;

    int len = radio.getPacketLength();
    if (len > 0 && len <= (int)sizeof(pktBuf)) {
      int state = radio.readData(pktBuf, len);

      if (state == RADIOLIB_ERR_NONE) {
        char hexBuf[513];
        hexEncode(pktBuf, len, hexBuf);

        Serial.print("RX ");
        Serial.print(radio.getRSSI());
        Serial.print(" ");
        Serial.print(radio.getSNR());
        Serial.print(" ");
        Serial.println(hexBuf);
      }
    }

    radio.startReceive();
  }
}
