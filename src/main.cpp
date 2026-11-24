// S3 AdBlock — DNS sinkhole + web dashboard, ported from
// M-Abozaid/esp32-c3-adblock (MIT) to the ESP32-S3 (4/8/16 MB flash).
// Blocklist = sorted 40-bit FNV-1a hashes in flash, binary-searched.
// Dashboard at http://s3adblock.local : per-client stats, system info,
// ban clients, add custom block domains. All control state persisted to flash.
//
// Port notes (what differs from the C3 original):
//   * flash/PSRAM: the S3 has far more flash, so INDEX_ENTRIES/MAX_RANGE are
//     raised (see platformio.ini) to keep ~2M domains searchable within
//     MAX_RANGE. PSRAM is deliberately unused.
//   * upstream default: AliDNS (223.5.5.5) instead of Quad9, which is not
//     reachable from mainland China (upstream issue #47). Override with
//     -DUPSTREAM_IP=9,9,9,9 to get Quad9 back.
//   * BOOT button: GPIO0 on the S3 DevKitC-1, not the C3's GPIO9.
//   * the C3 "retry WiFi at 8.5 dBm" quirk is C3-only and stays disabled here.

#include <Arduino.h>
#include <WiFiUdp.h>
#include <LittleFS.h>
#include <WiFiClientSecure.h>  // https fetch
#include <ArduinoOTA.h>        // network firmware flashing (pio run over wifi)
#include <DNSServer.h>         // captive-portal catch-all DNS
#if defined(ESP8266)
  #include <ESP8266WiFi.h>         // the ESP8266 core has no WiFi.h
  #include <ESP8266WebServer.h>    // the ESP8266 core has no WebServer.h
  #include <ESP8266HTTPClient.h>   // the ESP8266 core has no HTTPClient.h
  #include <ESP8266mDNS.h>
  #include <Updater.h>             // firmware OTA (the ESP8266 core ships Updater.h, not Update.h)
  #include "prefs_shim.h"          // EEPROM-backed stand-in for the NVS "Preferences" API
  typedef ESP8266WebServer WebServer;   // the ESP8266 class carries a different name
  #define UPDATE_SIZE_UNKNOWN ((size_t)0xFFFFFFFF)   // the ESP8266 Updater.h doesn't define it
#else
  #include <WiFi.h>
  #include <WebServer.h>
  #include <HTTPClient.h>        // remote blocklist fetch
  #include <ESPmDNS.h>
  #include <Update.h>           // firmware OTA
  #include <Preferences.h>      // NVS store for provisioned WiFi creds
  #include "lwip/etharp.h"
  #include "lwip/netif.h"
#endif
#include "secrets.h"   // WIFI_SSID / WIFI_PASS — used only as a FALLBACK if no creds
                       // have been provisioned via the captive portal (copy secrets.example.h)

// ---- config ----
#ifndef UPSTREAM_IP
// AliDNS. The S3 port ships in a mainland-China context where Quad9 (9.9.9.9)
// is unreachable; every allowed lookup would time out. Change it on the
// dashboard (UPSTREAM DNS) or compile with -DUPSTREAM_IP=9,9,9,9.
#define UPSTREAM_IP 223, 5, 5, 5
#endif
#ifndef UPSTREAM_PORT
#define UPSTREAM_PORT 53
#endif
static const IPAddress UPSTREAM(UPSTREAM_IP);   // compile-time fallback
static IPAddress upstreamDns;          // runtime upstream, see upstreamApply()
static const uint16_t DNS_PORT = 53;
static const char* BLOCKLIST_PATH = "/blocklist.bin";
static const int HASH_BYTES = 5;
static const uint64_t HASH_MASK = (1ULL << (HASH_BYTES * 8)) - 1;
// Overridable from build_flags (see platformio.ini).
//
// INDEX_ENTRIES x MAX_RANGE is the hard ceiling on how many hashes can be found:
// inFlash() clamps the bucket it scans to MAX_RANGE, so a smaller MAX_RANGE
// silently misses hashes that land in an overfull bucket. The S3 has 16 MB of
// flash, so the defaults here are sized for a ~2M-domain list (8192 x 256):
//   blIndex = 8192 * 5 B = 40 KB of static RAM
//   rangeBuf = 256 * 5 B = 1.25 KB
// That keeps static RAM at ~110 KB of the S3's 320 KB, with the rest left for
// the lwIP/WiFi stack. For a 4 MB board you would drop back to 4096/256 (~1M).
#ifndef INDEX_ENTRIES
#define INDEX_ENTRIES 8192
#endif
#ifndef CACHE_SIZE
#define CACHE_SIZE 256       // must be power of 2
#endif
#ifndef MAX_RANGE
#define MAX_RANGE 256         // max hashes per index bucket (ceiling = INDEX_ENTRIES * MAX_RANGE)
#endif

// ---- globals ----
WiFiUDP dnsServer, upstreamCli;
WebServer web(80);
File blocklist;
uint32_t numHashes = 0, totalBlocked = 0, totalAllowed = 0;
uint8_t buf[1536];   // fits any non-fragmented UDP reply (EDNS answers can exceed 512)

// first-level flash index (sorted sample hashes) + small direct-mapped cache
static uint8_t blIndex[INDEX_ENTRIES][HASH_BYTES];
static uint8_t cacheKey[CACHE_SIZE][HASH_BYTES];
static uint8_t cacheRes[CACHE_SIZE];
static uint8_t cacheValid[CACHE_SIZE];
static uint8_t rangeBuf[MAX_RANGE * HASH_BYTES];

#ifndef MAX_CLIENTS
#define MAX_CLIENTS 96
#endif
#ifndef MAX_CUSTOM
#define MAX_CUSTOM 200
#endif
struct Dev { uint32_t ip; uint8_t mac[6]; uint32_t blocked, allowed, lastSeen; bool banned; String label; };
Dev clients[MAX_CLIENTS]; int numClients = 0;

String customDom[MAX_CUSTOM]; uint64_t customHash[MAX_CUSTOM]; int numCustom = 0;

static const int MAX_BAN = 32;
uint32_t bannedIP[MAX_BAN]; int numBanned = 0;

// remote blocklist auto-update
String updateUrl = "";              // URL of a prebuilt blocklist.bin (e.g. GitHub release asset)
uint32_t updateIntervalH = 24;      // hours between auto-fetches
uint32_t lastCheckMs = 0;
String updateStatus = "never";

// WiFi provisioning (captive portal)
Preferences prefs;
DNSServer   dnsPortal;
String      portalOpts;             // <option> list of scanned networks, built once at portal start

// blocking pause (Pi-hole-style "disable for a while")
bool     blockingOn = true;
uint32_t resumeAt   = 0;            // millis() to auto-resume; 0 = paused indefinitely / not paused

// ---------- platform shims ----------
#if defined(ESP8266)
// The ESP8266EX has no internal temperature sensor. Same name/signature as the ESP32
// core's temperatureRead() so the stats JSON is identical on both boards.
static float temperatureRead() { return 0.0f; }
#endif
// The ESP32-S3 core returns NAN when the temp sensor read fails. String(NAN)
// formats as "nan", which is not valid JSON and breaks the dashboard's
// JSON.parse. Report 0 instead.
static float tempSafe() {
  const float t = temperatureRead();
  return isnan(t) ? 0.0f : t;
}

// ---------- hashing / matching ----------
static uint64_t fnv40(const char* s, size_t n) {
  uint64_t h = 0xcbf29ce484222325ULL;
  for (size_t i = 0; i < n; i++) { h ^= (uint8_t)s[i]; h *= 0x100000001b3ULL; }
  return h & HASH_MASK;
}
static inline uint64_t unpackHash(const uint8_t* b) {
  uint64_t v = 0;
  for (int k = 0; k < HASH_BYTES; k++) v |= (uint64_t)b[k] << (8 * k);
  return v;
}
static inline void packHash(uint64_t h, uint8_t* b) {
  for (int k = 0; k < HASH_BYTES; k++) { b[k] = (uint8_t)h; h >>= 8; }
}

static void buildFlashIndex() {
  if (!blocklist || numHashes == 0) return;
  for (int i = 0; i < INDEX_ENTRIES; i++) {
    uint32_t pos = (uint32_t)((uint64_t)i * (numHashes - 1) / (INDEX_ENTRIES - 1));
    blocklist.seek((uint32_t)pos * HASH_BYTES);
    blocklist.read(blIndex[i], HASH_BYTES);
  }
  for (int i = 0; i < CACHE_SIZE; i++) cacheValid[i] = 0;
}

static bool inFlash(uint64_t h) {
  if (numHashes == 0) return false;
  uint64_t first = unpackHash(blIndex[0]);
  uint64_t last  = unpackHash(blIndex[INDEX_ENTRIES - 1]);
  if (h < first || h > last) return false;

  int lo = 0, hi = INDEX_ENTRIES - 2, seg = 0;
  while (lo <= hi) {
    int mid = (lo + hi) >> 1;
    uint64_t midv = unpackHash(blIndex[mid]);
    if (midv < h) {
      seg = mid;
      lo = mid + 1;
    } else if (midv > h) {
      hi = mid - 1;
    } else {
      return true;
    }
  }

  uint32_t startPos = (uint32_t)((uint64_t)seg * (numHashes - 1) / (INDEX_ENTRIES - 1));
  uint32_t endPos   = (uint32_t)((uint64_t)(seg + 1) * (numHashes - 1) / (INDEX_ENTRIES - 1));
  if (endPos >= numHashes) endPos = numHashes - 1;
  uint32_t rangeCount = endPos - startPos + 1;
  if (rangeCount > (uint32_t)MAX_RANGE) rangeCount = MAX_RANGE;

  blocklist.seek((uint32_t)startPos * HASH_BYTES);
  blocklist.read(rangeBuf, (uint32_t)rangeCount * HASH_BYTES);

  for (uint32_t i = 0; i < rangeCount; i++) {
    uint64_t v = unpackHash(rangeBuf + i * HASH_BYTES);
    if (v == h) return true;
    if (v > h) break;
  }
  return false;
}

static bool inCustom(uint64_t h) { for (int i = 0; i < numCustom; i++) if (customHash[i] == h) return true; return false; }

// Only flash results are cached: the flash list only changes via reopenBlocklist(), which
// rebuilds the index and clears the cache. Custom domains change at runtime, so they're
// checked uncached (a short linear scan) to avoid serving stale answers.
static bool isBlockedHash(uint64_t h) {
  if (inCustom(h)) return true;
  uint32_t slot = h & (CACHE_SIZE - 1);
  if (cacheValid[slot]) {
    uint8_t want[HASH_BYTES]; packHash(h, want);
    bool same = true;
    for (int k = 0; k < HASH_BYTES; k++) if (cacheKey[slot][k] != want[k]) { same = false; break; }
    if (same) return cacheRes[slot] != 0;
  }
  bool res = inFlash(h);
  cacheValid[slot] = 1;
  cacheRes[slot] = res ? 1 : 0;
  packHash(h, cacheKey[slot]);
  return res;
}

static bool isBlocked(const char* domain) {
  const char* p = domain;
  while (p && *p) {
    uint64_t h = fnv40(p, strlen(p));
    if (isBlockedHash(h)) return true;
    const char* dot = strchr(p, '.'); if (!dot) break;
    const char* next = dot + 1; if (!strchr(next, '.')) break; p = next;
  }
  return false;
}

// ---------- persistence ----------
// Create the state files on first boot instead of probing for them. A missing
// file is expected on a fresh device, but both LittleFS::exists() and a failed
// open() log "does not exist, no permits for creation" at ERROR level, which
// looks like a fault on every first boot. Creating them once makes later reads
// quiet, and also means a corrupted/partial write has a valid file to fall back on.
static void initStateFiles() {
  static const char* files[] = { "/custom.txt", "/banned.txt", "/update.cfg", "/upstream.cfg" };
  for (const char* p : files) {
    // "a" creates the file if absent and never truncates an existing one, so
    // this is a silent no-op on every boot after the first.
    File f = LittleFS.open(p, "a");
    if (f) f.close();
  }
}
static void loadCustom() {
  numCustom = 0;
  File f = LittleFS.open("/custom.txt", "r"); if (!f) return;
  while (f.available() && numCustom < MAX_CUSTOM) {
    String l = f.readStringUntil('\n'); l.trim(); l.toLowerCase();
    if (l.length() && l.indexOf('.') > 0) { customDom[numCustom] = l; customHash[numCustom] = fnv40(l.c_str(), l.length()); numCustom++; }
  }
  f.close();
}
static void saveCustom() { File f = LittleFS.open("/custom.txt", "w"); if (!f) return; for (int i = 0; i < numCustom; i++) f.println(customDom[i]); f.close(); }
static bool addCustom(String d) {
  d.trim(); d.toLowerCase(); if (d.startsWith("www.")) d = d.substring(4);
  if (!d.length() || d.indexOf('.') < 0 || numCustom >= MAX_CUSTOM) return false;
  for (int i = 0; i < numCustom; i++) if (customDom[i] == d) return false;
  customDom[numCustom] = d; customHash[numCustom] = fnv40(d.c_str(), d.length()); numCustom++; saveCustom(); return true;
}
static void removeCustom(String d) {
  d.toLowerCase();
  for (int i = 0; i < numCustom; i++) if (customDom[i] == d) {
    for (int j = i; j < numCustom - 1; j++) { customDom[j] = customDom[j+1]; customHash[j] = customHash[j+1]; }
    numCustom--; saveCustom(); return;
  }
}
static bool isBannedIP(uint32_t ip) { for (int i = 0; i < numBanned; i++) if (bannedIP[i] == ip) return true; return false; }
static void loadBanned() {
  numBanned = 0;
  File f = LittleFS.open("/banned.txt", "r"); if (!f) return;
  while (f.available() && numBanned < MAX_BAN) { String l = f.readStringUntil('\n'); l.trim(); IPAddress ip; if (l.length() && ip.fromString(l)) bannedIP[numBanned++] = (uint32_t)ip; }
  f.close();
}
static void saveBanned() {
  numBanned = 0;
  for (int i = 0; i < numClients && numBanned < MAX_BAN; i++) if (clients[i].banned) bannedIP[numBanned++] = clients[i].ip;
  File f = LittleFS.open("/banned.txt", "w"); if (!f) return;
  for (int i = 0; i < numBanned; i++) { IPAddress ip(bannedIP[i]); f.println(ip.toString()); }
  f.close();
}

// ---------- client table ----------
static void getMac(uint32_t ip, uint8_t* mac) {
  memset(mac, 0, 6);
#if !defined(ESP8266)
  ip4_addr_t ipa; ipa.addr = ip;
  struct eth_addr* eth = nullptr; const ip4_addr_t* ipret = nullptr;
  for (struct netif* nif = netif_list; nif; nif = nif->next)
    if (etharp_find_addr(nif, &ipa, &eth, &ipret) >= 0 && eth) { memcpy(mac, eth->addr, 6); return; }
#else
  (void)ip;   // the ESP8266 exposes no ARP table; clients are identified by IP
#endif
}
static Dev* getClient(uint32_t ip) {
  for (int i = 0; i < numClients; i++) if (clients[i].ip == ip) { clients[i].lastSeen = millis(); return &clients[i]; }
  if (numClients < MAX_CLIENTS) {
    Dev* c = &clients[numClients++];
    c->ip = ip; c->blocked = c->allowed = 0; c->lastSeen = millis(); c->banned = isBannedIP(ip); c->label = "";
    getMac(ip, c->mac); return c;
  }
  return nullptr;
}

// ---------- upstream resolver ----------
// Allowed lookups are forwarded to one of:
//   built-in (default) - the compile-time UPSTREAM_IP (AliDNS on this port). Independent of
//                        the LAN, which matters because this box is often the BACKUP for a
//                        Pi-hole/AdGuard that the router hands out over DHCP; forwarding
//                        there would fail exactly when the backup is needed.
//   router             - the DNS the router hands out over DHCP (else the gateway), opt-in.
//   custom             - an address set on the dashboard.
// Persisted in /upstream.cfg ("router" or an IPv4 address; absent = built-in).
enum UpstreamMode { UP_BUILTIN, UP_ROUTER, UP_CUSTOM };
static UpstreamMode upstreamMode = UP_BUILTIN;
static IPAddress    upstreamSaved;               // the custom address, when UP_CUSTOM
static const char*  upstreamSource = "built-in";
// 0.0.0.0 and 255.255.255.255 parse as valid IPv4 but would silently stop all forwarding.
static bool usableResolver(const IPAddress& ip) { return (uint32_t)ip != 0 && (uint32_t)ip != 0xFFFFFFFF; }
static void upstreamApply() {
  const IPAddress self = WiFi.localIP();
  if (upstreamMode == UP_CUSTOM) { upstreamDns = upstreamSaved; upstreamSource = "custom"; return; }
  if (upstreamMode == UP_ROUTER) {
    const IPAddress dhcp = WiFi.dnsIP(), gw = WiFi.gatewayIP();
    if ((uint32_t)dhcp != 0 && dhcp != self) { upstreamDns = dhcp; upstreamSource = "router (dhcp)"; return; }
    if ((uint32_t)gw != 0 && gw != self)     { upstreamDns = gw;   upstreamSource = "router (gateway)"; return; }
  }
  upstreamDns = UPSTREAM; upstreamSource = "built-in";
}
static void upstreamLoad() {
  upstreamMode = UP_BUILTIN;
  // Nothing saved yet -> stay on the compile-time built-in. Don't call
  // upstreamApply() here: DHCP isn't up until after connectWiFi(), so "router"
  // mode can't resolve yet. setup() calls upstreamApply() once WiFi is up.
  File f = LittleFS.open("/upstream.cfg", "r");
  if (f) {
    String l = f.readStringUntil('\n'); l.trim(); f.close();
    IPAddress ip;
    if (l == "router") upstreamMode = UP_ROUTER;
    else if (l.length() && ip.fromString(l) && usableResolver(ip)) { upstreamSaved = ip; upstreamMode = UP_CUSTOM; }
  }
  // UP_CUSTOM is fully resolved without DHCP, so it is safe to apply now.
  // UP_ROUTER waits for the post-connect apply() in setup().
  if (upstreamMode == UP_CUSTOM) upstreamApply();
}
static void upstreamSave() {
  if (upstreamMode == UP_BUILTIN) { LittleFS.remove("/upstream.cfg"); return; }
  File f = LittleFS.open("/upstream.cfg", "w"); if (!f) return;
  f.println(upstreamMode == UP_ROUTER ? String("router") : upstreamSaved.toString()); f.close();
}

// ---------- DNS ----------
static size_t parseQuery(const uint8_t* pkt, int len, char* out, uint16_t* qtype, int* qend) {
  if (len < 13) return 0; int i = 12; size_t o = 0;
  while (i < len) { uint8_t l = pkt[i++]; if (l == 0) break; if (l & 0xC0) return 0;
    if (o + l + 1 >= 250 || i + l > len) return 0; if (o) out[o++] = '.';
    for (uint8_t k = 0; k < l; k++) out[o++] = tolower(pkt[i++]); }
  out[o] = 0; if (i + 4 > len) return 0; *qtype = (pkt[i] << 8) | pkt[i + 1]; *qend = i + 4;
  if (o > 4 && strncmp(out, "www.", 4) == 0) { memmove(out, out + 4, o - 3); o -= 4; }
  return o;
}
static int buildBlocked(int qend, uint16_t qtype) {
  buf[2] = 0x81; buf[3] = 0x80; buf[6] = 0; buf[7] = (qtype == 1) ? 1 : 0; buf[8] = 0; buf[9] = 0; buf[10] = 0; buf[11] = 0;
  if (qtype != 1) return qend;
  const uint8_t ans[] = {0xC0,0x0C, 0,1, 0,1, 0,0,1,0x2C, 0,4, 0,0,0,0};
  memcpy(buf + qend, ans, sizeof(ans)); return qend + sizeof(ans);
}
// ---------- answer cache ----------
// Every allowed lookup pays a round trip to the upstream resolver (tens of ms on
// WiFi, with occasional 100 ms+ link-layer jitter). Browsers and phones
// re-resolve the same handful of domains constantly, so caching the raw reply
// for its TTL is the biggest latency win available and cuts upstream traffic.
//
// Keyed on (question section, qtype). Stored replies keep the answer and
// authority records but drop the OPT/EDNS pseudo-record, which describes the
// upstream hop; a client that did not send EDNS must not receive it back.
//
// Direct-mapped table: a collision evicts and behaves as a miss, never as a wrong
// answer. Entries also expire at DNS_CACHE_MAX_TTL so a huge TTL can't pin them.
#define DNS_CACHE_SLOTS   128
#define DNS_CACHE_MAX_LEN 512     // per-entry reply bytes; larger replies are not cached
#define DNS_CACHE_MAX_TTL 3600u   // clamp TTLs above this
static uint8_t  dnsCacheData[DNS_CACHE_SLOTS][DNS_CACHE_MAX_LEN];
static uint16_t dnsCacheLen[DNS_CACHE_SLOTS];
static uint16_t dnsCacheKey[DNS_CACHE_SLOTS];
static uint32_t dnsCacheExp[DNS_CACHE_SLOTS];    // millis() deadline; 0 = empty
static uint32_t dnsCacheHits = 0, dnsCacheMisses = 0, dnsCacheStored = 0;

static uint16_t cacheKeyOf(int qend, uint16_t qtype) {
  uint32_t h = 0x811c9dc5u;
  for (int i = 12; i < qend; i++) {
    uint8_t c = buf[i];
    if (c >= 'A' && c <= 'Z') c += 32;       // fold; client buffer is already lowercased
    h = (h ^ c) * 0x01000193u;
  }
  h = (h ^ (qtype & 0xFF)) * 0x01000193u;
  return (uint16_t)((h ^ (h >> 16)) & 0xFFFFu);
}
// Skip one DNS name at p[*i]; returns false on a malformed/overlong name.
static bool skipName(const uint8_t* p, int n, int* i) {
  while (*i < n) {
    const uint8_t l = p[*i];
    if (l == 0) { *i += 1; return true; }
    if ((l & 0xC0) == 0xC0) { if (*i + 2 > n) return false; *i += 2; return true; }
    if (l & 0xC0) return false;
    if (*i + 1 + l > n) return false;
    *i += 1 + l;
  }
  return false;
}
// Minimum TTL across the answer and authority sections, or 0 if not cacheable.
static uint32_t replyTtl(const uint8_t* p, int n) {
  if (n < 12) return 0;
  const int qd = (p[4] << 8) | p[5];
  const int an = (p[6] << 8) | p[7];
  const int ns = (p[8] << 8) | p[9];
  if (an <= 0) return 0;                     // NXDOMAIN / empty answer: don't cache
  int i = 12;
  for (int q = 0; q < qd; q++) { if (!skipName(p, n, &i)) return 0; i += 4; if (i > n) return 0; }
  uint32_t minTtl = 0xFFFFFFFFu;
  for (int r = 0; r < an + ns; r++) {
    if (!skipName(p, n, &i)) return 0;
    if (i + 10 > n) return 0;
    const uint32_t ttl = ((uint32_t)p[i + 4] << 24) | ((uint32_t)p[i + 5] << 16) |
                         ((uint32_t)p[i + 6] << 8) | p[i + 7];
    const int rdlen = (p[i + 8] << 8) | p[i + 9];
    i += 10 + rdlen;
    if (i > n) return 0;
    if (ttl < minTtl) minTtl = ttl;
  }
  if (minTtl == 0xFFFFFFFFu) return 0;
  return minTtl > DNS_CACHE_MAX_TTL ? DNS_CACHE_MAX_TTL : minTtl;
}
// Build the cacheable form of a reply: question + answer + authority verbatim,
// then only the additional records that are not OPT (type 41 describes the
// upstream hop; a client that sent no EDNS must not get one back).
//
// Writes into `scratch` and leaves the caller's `buf` untouched, returns the new
// length, or 0 if the reply is not cacheable. Keeping `buf` pristine matters:
// on a "not cacheable" verdict the original reply must still be sent out intact.
static int buildCached(const uint8_t* p, int n, uint8_t* scratch, int scratchMax) {
  if (n < 12 || n > scratchMax) return 0;
  const int qd = (p[4] << 8) | p[5];
  const int an = (p[6] << 8) | p[7];
  const int ns = (p[8] << 8) | p[9];
  const int ar = (p[10] << 8) | p[11];
  if (qd != 1) return 0;                     // not a simple query reply
  int i = 12;
  if (!skipName(p, n, &i)) return 0;
  i += 4;                                    // qtype + qclass
  if (i > n) return 0;
  int scan = i;
  for (int r = 0; r < an + ns; r++) {        // answers + authority stay contiguous
    if (!skipName(p, n, &scan)) return 0;
    if (scan + 10 > n) return 0;
    const int rdlen = (p[scan + 8] << 8) | p[scan + 9];
    scan += 10 + rdlen;
    if (scan > n) return 0;
  }
  if (scan > scratchMax) return 0;
  memcpy(scratch, p, scan);
  int out = scan;
  int arKept = 0;
  for (int r = 0; r < ar; r++) {
    const int start = scan;
    if (!skipName(p, n, &scan)) return 0;
    if (scan + 10 > n) return 0;
    const int rtype = (p[scan] << 8) | p[scan + 1];
    const int rdlen = (p[scan + 8] << 8) | p[scan + 9];
    scan += 10 + rdlen;
    if (scan > n) return 0;
    if (rtype == 41) continue;
    const int len = scan - start;
    if (out + len > scratchMax) return 0;
    memcpy(scratch + out, p + start, len);
    out += len;
    arKept++;
  }
  scratch[10] = (uint8_t)(arKept >> 8); scratch[11] = (uint8_t)arKept;
  return out;
}
// Filter + store. Returns the length of the reply that should be sent (which may
// be shorter than `n` after dropping OPT), or `n` unchanged if not cacheable.
static int cacheStore(const uint8_t* p, int n, uint16_t key, uint32_t ttlSec) {
  if (ttlSec == 0) return n;
  static uint8_t scratch[DNS_CACHE_MAX_LEN];
  const int out = buildCached(p, n, scratch, DNS_CACHE_MAX_LEN);
  if (out <= 0) return n;
  const int slot = key & (DNS_CACHE_SLOTS - 1);
  memcpy(dnsCacheData[slot], scratch, out);
  dnsCacheLen[slot] = (uint16_t)out;
  dnsCacheKey[slot] = key;
  dnsCacheExp[slot] = millis() + ttlSec * 1000u;
  dnsCacheStored++;
  return out;
}
// Serve a cached reply into `buf`; returns its length, or 0 on miss/expiry.
static int cacheLookup(uint16_t key) {
  const int slot = key & (DNS_CACHE_SLOTS - 1);
  if (!dnsCacheExp[slot] || (int32_t)(millis() - dnsCacheExp[slot]) >= 0) return 0;
  if (dnsCacheKey[slot] != key || dnsCacheLen[slot] < 12) return 0;
  const int n = dnsCacheLen[slot];
  memcpy(buf, dnsCacheData[slot], n);
  dnsCacheHits++;
  return n;
}
static void cacheClear() { memset(dnsCacheExp, 0, sizeof(dnsCacheExp)); }


// Forward to upstream and wait for the reply that actually belongs to THIS query.
// Issue #10: after one timeout the late reply used to sit in the socket and get relayed
// to the next client (every answer shifted by one). Now: drain stale datagrams first,
// send with a fresh random txid, and only accept a reply whose txid, question section,
// and source address/port match. The client's own txid is restored on the way back.
static int forwardUpstream(int qlen, int qend) {
  upstreamCli.flush();                                   // release any half-read buffer
  while (upstreamCli.parsePacket() > 0) upstreamCli.flush();   // drop stale late replies
  const uint8_t cid0 = buf[0], cid1 = buf[1];
#if defined(ESP8266)
  const uint16_t wid = (uint16_t)ESP.random();   // the ESP8266 core's EspClass has random()
#else
  const uint16_t wid = (uint16_t)esp_random();    // ESP32's EspClass has no random()
#endif
  uint8_t q[260]; int ql = qend - 12;
  const bool haveQ = ql > 0 && ql <= (int)sizeof(q) && qend <= qlen;
  if (haveQ) memcpy(q, buf + 12, ql);
  buf[0] = wid >> 8; buf[1] = wid & 0xFF;
  upstreamCli.beginPacket(upstreamDns, UPSTREAM_PORT); upstreamCli.write(buf, qlen); upstreamCli.endPacket();
  const uint32_t t0 = millis();
  while (millis() - t0 < 1000) {                         // deadline, not a retry count
    int sz = upstreamCli.parsePacket();
    if (sz <= 0) { delay(1); continue; }
    const bool fromUp = upstreamCli.remoteIP() == upstreamDns && upstreamCli.remotePort() == UPSTREAM_PORT;
    int n = upstreamCli.read(buf, sizeof(buf));
    upstreamCli.flush();                                 // oversized datagram can't strand rx_buffer
    if (!fromUp || n < 12 || sz > (int)sizeof(buf)) continue;
    if (buf[0] != (wid >> 8) || buf[1] != (wid & 0xFF)) continue;
    if (haveQ && (n < 12 + ql || memcmp(buf + 12, q, ql) != 0)) continue;
    buf[0] = cid0; buf[1] = cid1;
    return n;
  }
  return 0;
}
// Drain a whole RX burst per call (capped, so web/OTA still get a turn) instead of
// one packet per loop iteration. Returns true if any query was handled this call.
static bool handleDns() {
  bool did = false;
  for (int budget = 0; budget < 16; budget++) {
    int sz = dnsServer.parsePacket(); if (sz <= 0) break;
    did = true;
    IPAddress cip = dnsServer.remoteIP(); uint16_t cport = dnsServer.remotePort();
    int qlen = dnsServer.read(buf, sizeof(buf)); if (qlen < 13) continue;
    char domain[256]; uint16_t qtype = 0; int qend = qlen;
    size_t dl = parseQuery(buf, qlen, domain, &qtype, &qend);
    Dev* c = getClient((uint32_t)cip);
    bool ban = c && c->banned;
    bool blocked = ban || (blockingOn && dl && numHashes && isBlocked(domain));
    const uint8_t cid0 = buf[0], cid1 = buf[1];       // client's txid, restored below
    int rlen = 0;
    if (blocked) {
      rlen = buildBlocked(qend, qtype); totalBlocked++; if (c) c->blocked++;
    } else {
      totalAllowed++; if (c) c->allowed++;
      // Only cache well-formed queries with a real question section.
      const uint16_t key = (dl && qend > 12 && qend <= qlen) ? cacheKeyOf(qend, qtype) : 0;
      if (key) { rlen = cacheLookup(key); }
      if (!rlen) {
        rlen = forwardUpstream(qlen, qend);
        if (rlen > 0 && key) {
          const uint32_t ttl = replyTtl(buf, rlen);
          if (ttl) rlen = cacheStore(buf, rlen, key, ttl);   // may shorten: OPT dropped
          else dnsCacheMisses++;
        }
        if (rlen > 0) { buf[0] = cid0; buf[1] = cid1; }
      } else {
        buf[0] = cid0; buf[1] = cid1;
      }
    }
    if (rlen > 0) { dnsServer.beginPacket(cip, cport); dnsServer.write(buf, rlen); dnsServer.endPacket(); }
  }
  return did;
}

// ---------- web ----------
static String macStr(const uint8_t* m) { char s[18]; snprintf(s, sizeof(s), "%02x:%02x:%02x:%02x:%02x:%02x", m[0],m[1],m[2],m[3],m[4],m[5]); return String(s); }
static String jesc(const String& s) { String o; for (char ch : s) { if (ch == '"' || ch == '\\') o += '\\'; o += ch; } return o; }
// HTML text/attribute escaping for the setup portal. jesc() covers JSON (stats
// endpoint); the portal builds HTML, and its inputs — a scanned SSID, the
// submitted WiFi name — are attacker-controllable during provisioning (the
// portal AP is open, and a nearby attacker can also broadcast an SSID of their
// choosing). Without escaping both, a crafted SSID/name is reflected script
// into the setup page, the same class as the dashboard XSS fixed earlier.
static String htmlEscape(const String& s) {
  String o; o.reserve(s.length());
  for (char ch : s) {
    switch (ch) {
      case '&':  o += "&amp;";  break;
      case '<':  o += "&lt;";   break;
      case '>':  o += "&gt;";   break;
      case '"':  o += "&quot;"; break;
      case '\'': o += "&#39;";  break;
      default:   o += ch;
    }
  }
  return o;
}

#include "page.h"   // dashboard HTML (PROGMEM) — see issue #6

static void handleStats() {
  uint32_t up = millis() / 1000;
  char ut[24]; snprintf(ut, sizeof(ut), "%lud %luh %lum", up/86400, (up%86400)/3600, (up%3600)/60);
  String j = "{\"ip\":\"" + WiFi.localIP().toString() + "\",\"blocked\":" + totalBlocked + ",\"allowed\":" + totalAllowed +
             ",\"domains\":" + numHashes + ",\"rssi\":" + WiFi.RSSI() + ",\"temp\":" + String(tempSafe(), 1) +
             ",\"heap\":" + ESP.getFreeHeap() + ",\"uptime\":\"" + ut + "\"" +
             ",\"dns\":\"" + upstreamDns.toString() + "\",\"dnsSource\":\"" + upstreamSource + "\"" +
             ",\"upurl\":\"" + jesc(updateUrl) + "\",\"upiv\":" + updateIntervalH + ",\"upstat\":\"" + jesc(updateStatus) + "\"" +
             ",\"chits\":" + dnsCacheHits + ",\"cmiss\":" + dnsCacheMisses + ",\"csize\":" + (unsigned)DNS_CACHE_SLOTS +
             ",\"blocking\":" + (blockingOn ? "true" : "false") +
             ",\"resumeIn\":" + (uint32_t)(!blockingOn && resumeAt ? (resumeAt - millis()) / 1000 : 0) +
             ",\"defcreds\":" + ((strcmp(WEB_PASS, "CHANGE_ME_WEB_PASSWORD") == 0 || strcmp(OTA_PASS, "CHANGE_ME_OTA_PASSWORD") == 0) ? "true" : "false") +
             ",\"clients\":[";
  for (int i = 0; i < numClients; i++) { Dev& c = clients[i]; IPAddress ip(c.ip);
    j += (i ? "," : ""); j += "{\"ip\":\"" + ip.toString() + "\",\"mac\":\"" + macStr(c.mac) + "\",\"blocked\":" + c.blocked + ",\"allowed\":" + c.allowed + ",\"banned\":" + (c.banned?"true":"false") + "}"; }
  j += "],\"custom\":[";
  for (int i = 0; i < numCustom; i++) { j += (i ? "," : ""); j += "\"" + jesc(customDom[i]) + "\""; }
  j += "]}";
  web.send(200, "application/json", j);
}
// Upstream shipped every state-changing/OTA endpoint with zero authentication —
// anyone on the LAN could reflash firmware or rewrite the blocklist. Gate them.
//
// Basic Auth alone isn't enough here: these are GET endpoints with side effects,
// and browsers auto-attach cached Basic Auth credentials to *any* request to an
// already-authenticated origin — including one triggered by a completely
// unrelated page the victim's browser visits later (e.g. <img src="http://
// c3adblock.local/forgetwifi">). That's CSRF, and it defeats the LAN-attacker
// threat model entirely: the attacker doesn't need network access, just to get
// the victim's browser to fire one request. A custom header can't be attached
// by a plain <img>/<form> CSRF vector (only same-origin fetch() can set it, and
// that's exactly what the dashboard's own JS does), so requiring one blocks the
// drive-by case without needing TLS, cookies, or a token endpoint.
static const char* CSRF_HEADER = "X-Requested-With";
static const char* CSRF_VALUE  = "c3-adblock";
static bool requireAuth() {
  if (web.header(CSRF_HEADER) != CSRF_VALUE) { web.send(403, "text/plain", "missing CSRF header"); return false; }
  if (web.authenticate(WEB_USER, WEB_PASS)) return true;
  web.requestAuthentication();
  return false;
}
static void handleBan() {
  if (!requireAuth()) return;
  IPAddress ip; if (ip.fromString(web.arg("ip"))) { Dev* c = getClient((uint32_t)ip); if (c) { c->banned = !c->banned; saveBanned(); } }
  web.send(200, "text/plain", "ok");
}

// ---------- blocklist swap (shared by upload + remote fetch) ----------
// A new list is written to /blocklist.new and only replaces the live list after it
// validates. If the filesystem has room for both, the live list stays in use the whole
// time (and survives a bad/truncated download). Only when space is short is the live
// list freed first; then a rejected download leaves the device fail-open (forwarding,
// no blocking) until the next good update.
static void reopenBlocklist() {
  blocklist = LittleFS.open(BLOCKLIST_PATH, "r");
  numHashes = blocklist ? blocklist.size() / HASH_BYTES : 0;
  buildFlashIndex();
  cacheClear();          // answers cached under the old list may now be wrong
}
static size_t fsFree() {
#if defined(ESP8266)
  FSInfo i; LittleFS.info(i); return i.totalBytes - i.usedBytes;
#else
  return LittleFS.totalBytes() - LittleFS.usedBytes();
#endif
}
static bool swapKeptLive = false;                    // live list still open during this swap?
static void beginBlocklistSwap(size_t expected) {    // expected = incoming size, 0 if unknown
  LittleFS.remove("/blocklist.new");
  if (!expected && blocklist) expected = blocklist.size();   // unknown: assume similar size
  swapKeptLive = expected && fsFree() > expected + 16384;     // 16 KB littlefs slack
  if (!swapKeptLive) {                               // no room for both: free the old list
    if (blocklist) blocklist.close();
    numHashes = 0;
    LittleFS.remove(BLOCKLIST_PATH);
  }
  Serial.printf("[swap] incoming ~%u B, free %u B -> %s\n", (unsigned)expected, (unsigned)fsFree(),
                swapKeptLive ? "keeping live list during update" : "freed live list first");
}
// Valid = non-empty, whole 5-byte entries, complete (if the size was announced), and
// strictly ascending. The ordering check rejects HTML error pages, other forks' formats
// and corrupted files, which the old "size % 5 == 0" test let through.
static bool validBlocklistFile(const char* path, size_t expectSize, String& why) {
  File f = LittleFS.open(path, "r");
  if (!f) { why = "missing"; return false; }
  size_t sz = f.size();
  if (!sz || sz % HASH_BYTES) { f.close(); why = "size " + String((unsigned)sz) + " not a multiple of 5"; return false; }
  if (expectSize && sz != expectSize) { f.close(); why = "truncated (" + String((unsigned)sz) + "/" + String((unsigned)expectSize) + " B)"; return false; }
  uint8_t b[HASH_BYTES * 100]; uint64_t prev = 0; bool first = true; size_t idx = 0;
  while (f.available()) {
    int n = f.read(b, sizeof(b)); if (n <= 0) break;
    for (int k = 0; k + HASH_BYTES <= n; k += HASH_BYTES, idx++) {
      uint64_t v = unpackHash(b + k);
      if (!first && v <= prev) { f.close(); why = "not a sorted blocklist (entry " + String((unsigned)idx) + ")"; return false; }
      prev = v; first = false;
    }
  }
  f.close(); return true;
}
static bool commitNewBlocklist(size_t expectSize, String& why) {   // /blocklist.new -> live
  bool ok = validBlocklistFile("/blocklist.new", expectSize, why);
  if (ok) {
    if (blocklist) blocklist.close();
    LittleFS.remove(BLOCKLIST_PATH);
    LittleFS.rename("/blocklist.new", BLOCKLIST_PATH);
  } else {
    LittleFS.remove("/blocklist.new");
    Serial.printf("[swap] rejected: %s%s\n", why.c_str(), swapKeptLive ? " (kept current list)" : "");
    if (swapKeptLive) return false;                  // live list never left; nothing to reopen
  }
  reopenBlocklist();
  return ok;
}

// ---------- OTA blocklist update (browser upload) ----------
static bool upOk = false;
static String upWhy;
static bool upAuthOk = false;
static File upFile;
static void handleUploadDone() {
  if (!upAuthOk) { web.requestAuthentication(); return; }
  web.send(upOk ? 200 : 500, "text/plain", upOk ? String("ok") : "rejected: " + upWhy);
}
static void handleUpload() {
  HTTPUpload& u = web.upload();
  switch (u.status) {
    case UPLOAD_FILE_START:
      upAuthOk = web.header(CSRF_HEADER) == CSRF_VALUE && web.authenticate(WEB_USER, WEB_PASS);
      if (!upAuthOk) { Serial.println("[ota] blocklist upload: auth/CSRF check failed"); break; }
#if defined(ESP8266)
      upOk = false; beginBlocklistSwap(0);            // size unknown here: estimated from the live list
#else
      upOk = false; beginBlocklistSwap(web.clientContentLength());
#endif
      upFile = LittleFS.open("/blocklist.new", "w");
      Serial.printf("[ota] receiving %s\n", u.filename.c_str());
      break;
    case UPLOAD_FILE_WRITE:
      if (upAuthOk && upFile) upFile.write(u.buf, u.currentSize);
      break;
    case UPLOAD_FILE_END:
      if (!upAuthOk) break;
      if (upFile) upFile.close();
      upOk = commitNewBlocklist(0, upWhy);
      Serial.printf("[ota] %s -> %u domains\n", upOk ? "OK" : "REJECTED", numHashes);
      break;
    case UPLOAD_FILE_ABORTED:
      if (!upAuthOk) break;
      if (upFile) upFile.close();
      LittleFS.remove("/blocklist.new"); if (!swapKeptLive) reopenBlocklist();
      Serial.println("[ota] aborted");
      break;
  }
}

// ---------- remote blocklist auto-update ----------
static void loadUpdateCfg() {
  File f = LittleFS.open("/update.cfg", "r"); if (!f) return;
  updateUrl = f.readStringUntil('\n'); updateUrl.trim();
  String iv = f.readStringUntil('\n'); iv.trim(); if (iv.length()) updateIntervalH = iv.toInt();
  f.close(); if (updateIntervalH < 1) updateIntervalH = 1;
}
static void saveUpdateCfg() {
  File f = LittleFS.open("/update.cfg", "w"); if (!f) return;
  f.println(updateUrl); f.println(updateIntervalH); f.close();
}
static bool fetchBlocklist(String url) {
  url.trim(); if (!url.length()) { updateStatus = "no url set"; return false; }
  Serial.printf("[remote] GET %s\n", url.c_str());
  WiFiClientSecure cs;
#if defined(ESP8266)
  // ESP8266 BearSSL: allowSelfSignedCerts() accepts ONLY self-signed certs, and
  // GitHub's release CDN serves a CA-signed chain -> that call would fail the
  // handshake. setInsecure() exists in this core and skips verification outright,
  // which is what the ESP32 build does (blocklist isn't secret).
  cs.setInsecure();
  cs.setBufferSizes(8192, 1024);   // trim BearSSL RAM (core default is 16384/512;
                                    // 2048 would overflow on a ~4 KB cert record)
#else
  cs.setInsecure();                // blocklist isn't secret -> skip cert pinning
#endif
  WiFiClient cl;
  HTTPClient http; http.setTimeout(20000);
  http.setFollowRedirects(HTTPC_STRICT_FOLLOW_REDIRECTS);  // GitHub release -> CDN redirect
  bool https = url.startsWith("https");
  if (!(https ? http.begin(cs, url) : http.begin(cl, url))) { updateStatus = "begin failed"; return false; }
  int code = http.GET();
  if (code != HTTP_CODE_OK) { http.end(); updateStatus = "HTTP " + String(code); Serial.printf("[remote] %s\n", updateStatus.c_str()); return false; }
  int len = http.getSize();
  beginBlocklistSwap(len > 0 ? (size_t)len : 0);
  File f = LittleFS.open("/blocklist.new", "w");
  if (!f) { http.end(); updateStatus = "fs open failed"; if (!swapKeptLive) reopenBlocklist(); return false; }
  WiFiClient* stream = http.getStreamPtr(); uint8_t b[1024]; size_t total = 0; uint32_t idle = millis();
  while (http.connected() && (len < 0 || (int)total < len)) {
    size_t avail = stream->available();
    if (avail) { int n = stream->readBytes(b, avail > sizeof(b) ? sizeof(b) : avail); if (n > 0) { f.write(b, n); total += n; idle = millis(); } }
    else { if (millis() - idle > 15000) break; delay(2); }
  }
  f.close(); http.end();
  String why;
  bool ok = commitNewBlocklist(len > 0 ? (size_t)len : 0, why);
  updateStatus = ok ? ("ok: " + String(numHashes) + " domains")
                    : ("rejected: " + why + (swapKeptLive ? " (kept current list)" : ""));
  Serial.printf("[remote] %s\n", updateStatus.c_str());
  return ok;
}

// ---------- firmware OTA (browser upload of firmware.bin -> reboot) ----------
static bool fwAuthOk = false;
static void handleFwUpdateDone() {
  if (!fwAuthOk) { web.requestAuthentication(); return; }
  bool ok = !Update.hasError();
  web.send(ok ? 200 : 500, "text/plain", ok ? "ok, rebooting" : "firmware update failed");
  if (ok) { delay(300); ESP.restart(); }
}
static void handleFwUpload() {
  HTTPUpload& u = web.upload();
  if (u.status == UPLOAD_FILE_START) {
    fwAuthOk = web.header(CSRF_HEADER) == CSRF_VALUE && web.authenticate(WEB_USER, WEB_PASS);
    if (!fwAuthOk) { Serial.println("[fw-ota] auth/CSRF check failed, rejecting flash"); return; }
    Serial.printf("[fw-ota] %s\n", u.filename.c_str());
#if defined(ESP8266)
    // The ESP8266 Updater stages the image at (end of sketch space - size) and needs a
    // real size up front: UPDATE_SIZE_UNKNOWN overflows the sector rounding to 0, which
    // would stage the image on top of the LittleFS partition. Use the free sketch
    // space instead, exactly like the core's own WebUpdate example.
    uint32_t sz = (ESP.getFreeSketchSpace() - 0x1000) & 0xFFFFF000;
    if (!Update.begin(sz)) Update.printError(Serial);
#else
    if (!Update.begin(UPDATE_SIZE_UNKNOWN)) Update.printError(Serial);
#endif
  } else if (u.status == UPLOAD_FILE_WRITE) {
    if (!fwAuthOk) return;
    if (Update.write(u.buf, u.currentSize) != u.currentSize) Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_END) {
    if (!fwAuthOk) return;
    if (Update.end(true)) Serial.printf("[fw-ota] %u bytes OK\n", u.totalSize);
    else Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_ABORTED) {
    if (!fwAuthOk) return;
#if defined(ESP8266)
    Update.end(false);   // the ESP8266 Updater has no abort(): end(false) resets the
                         // updater state without staging the image
#else
    Update.abort();
#endif
    Serial.println("[fw-ota] aborted");
  }
}

// ---------- WiFi provisioning (captive portal) ----------
// Try provisioned NVS creds first, then the compile-time secrets.h creds as a
// fallback (so the maintainer's own device + source builders keep working). If
// neither connects, fall through to the config portal.
static bool hasCreds() {
  // Read-write open so the namespace gets created; reading a key that was never
  // written still makes esp-idf log "nvs_get_str ... NOT_FOUND" at ERROR level
  // on first boot. That is the expected empty-NVS case, so skip the probe
  // entirely when we already have compile-time credentials to fall back on.
  if (WIFI_SSID && *WIFI_SSID && strcmp(WIFI_SSID, "YOUR_WIFI_SSID") != 0) return true;
  prefs.begin("wifi", false); bool nvs = prefs.getString("ssid", "").length() > 0; prefs.end();
  return nvs;
}
static bool connectWiFi() {
  prefs.begin("wifi", false);
  String ss = prefs.getString("ssid", "");
  String pw = prefs.getString("pass", "");
  prefs.end();
  const char* ssid = ss.length() ? ss.c_str() : WIFI_SSID;
  const char* pass = ss.length() ? pw.c_str() : WIFI_PASS;
  if (!ssid || !*ssid || strcmp(ssid, "YOUR_WIFI_SSID") == 0) return false;  // unconfigured
  Serial.printf("WiFi: connecting to \"%s\"%s\n", ssid, ss.length() ? " (provisioned)" : " (secrets.h)");
  WiFi.mode(WIFI_STA); WiFi.setSleep(false); WiFi.begin(ssid, pass);
#if defined(WIFI_TX_POWER) && !defined(ESP8266)
  WiFi.setTxPower((wifi_power_t)WIFI_TX_POWER);    // e.g. -DWIFI_TX_POWER=WIFI_POWER_8_5dBm
#endif
  uint32_t t0 = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < 30000) { delay(250); Serial.print("."); }
  Serial.println();
#if CONFIG_IDF_TARGET_ESP32C3 && !defined(WIFI_TX_POWER)
  // Some C3 SuperMini boards have a badly matched antenna and only work at reduced TX
  // power (#50). If full power didn't connect, retry once at 8.5 dBm before giving up.
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("WiFi: retrying at 8.5 dBm (C3 SuperMini antenna quirk)");
    WiFi.disconnect(); delay(200); WiFi.begin(ssid, pass); WiFi.setTxPower(WIFI_POWER_8_5dBm);
    t0 = millis();
    while (WiFi.status() != WL_CONNECTED && millis() - t0 < 20000) { delay(250); Serial.print("."); }
    Serial.println();
  }
#endif
  return WiFi.status() == WL_CONNECTED;
}

static void handlePortalRoot() {
  String html =
    "<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
    "<title>S3 AdBlock setup</title>"
    "<body style='font:16px system-ui,sans-serif;max-width:420px;margin:36px auto;padding:0 16px;background:#0d1117;color:#c9d1d9'>"
    "<h2>&#128737; S3 AdBlock &mdash; WiFi setup</h2>"
    "<p style='color:#8b949e'>Pick your network and enter its password. The device restarts and joins it.</p>"
    "<form method=POST action=/wifisave>"
    // A real <select> is usable on every phone; the datalist this used to be
    // renders an affordance in several in-app browsers but no list, so picking
    // a network looked impossible. Typing the name still covers hidden APs.
    "<select name=s style='width:100%;box-sizing:border-box;padding:11px;margin:6px 0;border-radius:6px;border:1px solid #30363d;background:#161b22;color:#c9d1d9'>" + portalOpts + "</select>"
    "<input name=s2 placeholder='or type the WiFi name' style='width:100%;box-sizing:border-box;padding:11px;margin:6px 0;border-radius:6px;border:1px solid #30363d;background:#161b22;color:#c9d1d9'>"
    "<input name=p type=password placeholder='Password' style='width:100%;box-sizing:border-box;padding:11px;margin:6px 0;border-radius:6px;border:1px solid #30363d;background:#161b22;color:#c9d1d9'>"
    "<button style='width:100%;padding:12px;margin-top:8px;border-radius:6px;border:0;background:#3fb950;color:#000;font-weight:600;cursor:pointer'>Connect</button>"
    "</form></body>";
  web.send(200, "text/html", html);
}
static void handleWifiSave() {
  String ss = web.arg("s2"); ss.trim();          // typed name wins
  if (!ss.length()) ss = web.arg("s");           // ...otherwise the picked one
  String pw = web.arg("p");
  if (!ss.length()) { web.send(400, "text/plain", "missing WiFi name"); return; }
  prefs.begin("wifi", false); prefs.putString("ssid", ss); prefs.putString("pass", pw); prefs.end();
  web.send(200, "text/html", "<!doctype html><meta charset=utf-8><body style='font:16px system-ui;text-align:center;margin-top:60px'>"
                             "&#9989; Saved. Restarting and joining <b>" + htmlEscape(ss) + "</b>&hellip;<br><br>"
                             "Reconnect your phone to your normal WiFi, then find the box at <b>s3adblock.local</b>.</body>");
  delay(900); ESP.restart();
}
// Never returns — blocks in the portal loop until creds are saved (then reboots).
static void startConfigPortal() {
  // Bring the radio up before the first scan. An unconfigured device gets here
  // straight from connectWiFi() without any WiFi call, and the first scan right
  // after boot can come back empty - which left the network list with no
  // entries at all. Start the station, then retry a few times.
  WiFi.mode(WIFI_STA);
  delay(200);
  int n = 0;
  for (int attempt = 1; attempt <= 3 && n <= 0; attempt++) {
    if (attempt > 1) delay(700);
    n = WiFi.scanNetworks();
    Serial.printf("[setup] scan %d/3: %d networks\n", attempt, n);
  }
  portalOpts = "<option value=''>-- pick your network --</option>";
  for (int i = 0; i < n && i < 15; i++) {
    const String s = WiFi.SSID(i);
    portalOpts += "<option value='" + htmlEscape(s) + "'>" + htmlEscape(s) + "</option>";
  }
  uint8_t mac[6]; WiFi.macAddress(mac);
  char ap[24]; snprintf(ap, sizeof(ap), "S3-AdBlock-%02X%02X", mac[4], mac[5]);
  WiFi.mode(WIFI_AP); WiFi.softAP(ap);
#if CONFIG_IDF_TARGET_ESP32C3
  // C3 SuperMini antenna quirk (#50) hides the AP at full power. The S3's
  // antenna is fine, and dialing it down there would only shorten the setup range.
  WiFi.setTxPower(WIFI_POWER_8_5dBm);
#endif
  IPAddress apIP = WiFi.softAPIP();
  dnsPortal.start(53, "*", apIP);              // catch-all -> phones pop the captive portal
  web.on("/", handlePortalRoot);
  web.on("/wifisave", HTTP_POST, handleWifiSave);
  web.onNotFound(handlePortalRoot);            // any captive-portal probe -> the form
  web.begin();
  Serial.printf("\n[setup] No WiFi. Join open network \"%s\" and a setup page pops up (or http://%s)\n",
                ap, apIP.toString().c_str());
  // A configured device that merely failed to join (router rebooting, weak signal) must not
  // get stuck here: if nobody is using the portal, reboot and retry WiFi every 3 minutes.
  const bool configured = hasCreds();
  uint32_t t0 = millis();
  while (true) {
    dnsPortal.processNextRequest(); web.handleClient(); delay(2);
    if (WiFi.softAPgetStationNum() > 0) t0 = millis();          // someone is setting it up
    if (configured && millis() - t0 > 180000UL) { Serial.println("[setup] retrying WiFi"); ESP.restart(); }
  }
}

void setup() {
  Serial.begin(115200); delay(300);
#if defined(ARDUINO_USB_CDC_ON_BOOT) && ARDUINO_USB_CDC_ON_BOOT && !defined(ESP8266)
  // Only when `Serial` is the native USB CDC: with no host attached the core
  // waits up to 100 ms per write for the host to drain the buffer, which would
  // stall the DNS loop on a headless dongle. On UART0 (the CH343 build) writes
  // are already non-blocking and there is no USB host to wait for.
  Serial.setTxTimeoutMs(0);
#endif
  Serial.println("\n[s3-adblock] booting");
  Serial.flush();          // UART is buffered; make sure this lands before the long init
#if defined(ESP8266)
  if (!LittleFS.begin()) Serial.println("LittleFS FAILED");  // ESP8266's begin() takes no args and auto-formats
#else
  if (!LittleFS.begin(true)) Serial.println("LittleFS FAILED");
#endif
  blocklist = LittleFS.open(BLOCKLIST_PATH, "r");
  if (blocklist) {
    numHashes = blocklist.size() / HASH_BYTES;
    Serial.printf("blocklist: %u domains\n", numHashes);
    buildFlashIndex();
  }
  initStateFiles();                             // create absent state files before reading them
#if !defined(ESP8266)
  // Seed the NVS "wifi" namespace on first boot. Reading an unwritten key makes
  // the Arduino Preferences wrapper log "nvs_get_str ... NOT_FOUND" at ERROR
  // level (it bypasses esp_log_level_set), which reads like a fault. Writing
  // empty strings once makes every later read succeed silently.
  {
    prefs.begin("wifi", false);
    if (!prefs.isKey("ssid")) { prefs.putString("ssid", ""); prefs.putString("pass", ""); }
    prefs.end();
  }
#endif
  loadCustom(); loadBanned(); loadUpdateCfg(); upstreamLoad();
  Serial.printf("[mem] free heap %u bytes\n", (unsigned)ESP.getFreeHeap());
  // S3 has 320 KB of internal SRAM and this firmware deliberately keeps the
  // blocklist in flash, so these numbers are the ones to watch for leaks.
  Serial.printf("[hw] %s rev%u, %u MB flash, %u MB PSRAM (unused)\n",
                ESP.getChipModel(), (unsigned)ESP.getChipRevision(),
                (unsigned)(ESP.getFlashChipSize() / (1024 * 1024)),
                (unsigned)(ESP.getPsramSize() / (1024 * 1024)));
  Serial.printf("[idx] %d entries x %d max range -> ceiling %u domains\n",
                INDEX_ENTRIES, MAX_RANGE, (unsigned)INDEX_ENTRIES * MAX_RANGE);
#if defined(ARDUINO_USB_CDC_ON_BOOT) && ARDUINO_USB_CDC_ON_BOOT && !defined(ESP8266)
  Serial.println("[uart] Serial = native USB-CDC; send USBSerial output to a second host if needed");
#else
  Serial.println("[uart] Serial = UART0 (GPIO43 TX / GPIO44 RX) @115200 - CH343 bridge");
#endif

  // Hold BOOT at power-on to wipe saved WiFi and force the setup portal.
  // ESP32-S3 DevKitC-1 and the C3 SuperMini both put BOOT on GPIO0; the C3
  // devkit-m-1 uses GPIO9. Classic ESP32 is GPIO0 as well.
#if defined(ESP8266)
  const int BOOT_PIN = 0;     // ESP8266 FLASH button (GPIO0)
#elif CONFIG_IDF_TARGET_ESP32C3
  const int BOOT_PIN = 9;     // C3 devkit-m-1 BOOT button
#else
  const int BOOT_PIN = 0;     // ESP32-S3 / classic ESP32 BOOT button
#endif
  pinMode(BOOT_PIN, INPUT_PULLUP);
  if (digitalRead(BOOT_PIN) == LOW) { delay(60);
    if (digitalRead(BOOT_PIN) == LOW) { prefs.begin("wifi", false); prefs.clear(); prefs.end();
      Serial.println("[setup] BOOT held -> cleared saved WiFi"); } }

  if (!connectWiFi()) startConfigPortal();   // portal blocks + reboots on save; returns only when connected
  Serial.printf("WiFi up: %s\n", WiFi.localIP().toString().c_str());
  upstreamApply();                              // DHCP is up now (matters for "router" mode)
  Serial.printf("upstream DNS: %s (%s)\n", upstreamDns.toString().c_str(), upstreamSource);
  if (MDNS.begin("s3adblock")) { MDNS.addService("http", "tcp", 80); Serial.println("dashboard: http://s3adblock.local"); }

  if (strcmp(WEB_PASS, "CHANGE_ME_WEB_PASSWORD") == 0 || strcmp(OTA_PASS, "CHANGE_ME_OTA_PASSWORD") == 0)
    Serial.println("[WARN] secrets.h still has placeholder WEB_PASS/OTA_PASS — those are public "
                    "(they're in the repo's example file). Set real values before trusting this "
                    "device on a network you don't fully control.");

  dnsServer.begin(DNS_PORT); upstreamCli.begin(0);
#if defined(ESP8266)
  web.collectHeaders(CSRF_HEADER);       // ESP8266's collectHeaders is variadic
#else
  { const char* hdrs[] = { CSRF_HEADER }; web.collectHeaders(hdrs, 1); }
#endif  // needed for requireAuth()'s CSRF check
  web.on("/", []() { web.send_P(200, "text/html", PAGE); });
  web.on("/stats.json", handleStats);
  web.on("/ban", handleBan);
  web.on("/addblock", []() { if (!requireAuth()) return; addCustom(web.arg("d")); cacheClear(); web.send(200, "text/plain", "ok"); });
  web.on("/unblock", []() { if (!requireAuth()) return; removeCustom(web.arg("d")); cacheClear(); web.send(200, "text/plain", "ok"); });
  web.on("/pause", []() {                    // /pause?s=300  (0 or absent = indefinite)
    if (!requireAuth()) return;
    long s = web.hasArg("s") ? web.arg("s").toInt() : 0;
    blockingOn = false; resumeAt = (s > 0) ? millis() + (uint32_t)s * 1000UL : 0;
    web.send(200, "text/plain", "paused");
  });
  web.on("/resume", []() { if (!requireAuth()) return; blockingOn = true; resumeAt = 0; cacheClear(); web.send(200, "text/plain", "resumed"); });
  web.on("/forgetwifi", []() { if (!requireAuth()) return; web.send(200, "text/plain", "cleared — rebooting into setup portal");
    prefs.begin("wifi", false); prefs.clear(); prefs.end(); delay(500); ESP.restart(); });
  web.on("/upload", HTTP_POST, handleUploadDone, handleUpload);      // blocklist OTA (auth inside handleUpload)
  web.on("/update", HTTP_POST, handleFwUpdateDone, handleFwUpload);  // firmware OTA (auth inside handleFwUpload)
  web.on("/fetchnow", []() { if (!requireAuth()) return; fetchBlocklist(updateUrl); web.send(200, "text/plain", updateStatus); });
  web.on("/setupdate", []() {
    if (!requireAuth()) return;
    if (web.hasArg("u")) updateUrl = web.arg("u");
    if (web.hasArg("h")) { updateIntervalH = web.arg("h").toInt(); if (updateIntervalH < 1) updateIntervalH = 1; }
    saveUpdateCfg(); web.send(200, "text/plain", "ok");
  });
  web.on("/setdns", []() {               // /setdns?ip=x.x.x.x | ?router=1 | ?reset=1 (built-in)
    if (!requireAuth()) return;
    if (web.hasArg("reset")) upstreamMode = UP_BUILTIN;
    else if (web.hasArg("router")) upstreamMode = UP_ROUTER;
    else {
      IPAddress v;
      if (!v.fromString(web.arg("ip"))) { web.send(400, "text/plain", "not an IPv4 address"); return; }
      if (!usableResolver(v)) { web.send(400, "text/plain", "0.0.0.0 / broadcast is not a resolver"); return; }
      if (v == WiFi.localIP()) { web.send(400, "text/plain", "that is this device; pick another resolver"); return; }
      upstreamSaved = v; upstreamMode = UP_CUSTOM;
    }
    upstreamSave(); upstreamApply(); cacheClear();
    Serial.printf("[dns] upstream -> %s (%s)\n", upstreamDns.toString().c_str(), upstreamSource);
    web.send(200, "text/plain", upstreamDns.toString());
  });
  web.begin();
  ArduinoOTA.setHostname("s3adblock");   // pio run -t upload --upload-port s3adblock.local
  ArduinoOTA.setPassword(OTA_PASS);      // network OTA was unauthenticated upstream
  ArduinoOTA.begin();
  Serial.println("DNS :53 + dashboard :80 + OTA up");
}

void loop() {
  ArduinoOTA.handle();
  web.handleClient();
  bool busy = handleDns();
  if (!blockingOn && resumeAt && (int32_t)(millis() - resumeAt) >= 0) { blockingOn = true; resumeAt = 0; cacheClear(); }
  if (updateUrl.length()) {               // periodic remote blocklist auto-update
    uint32_t now = millis();
    if (lastCheckMs == 0) lastCheckMs = now;   // skip an immediate fetch on boot
    else if (now - lastCheckMs >= updateIntervalH * 3600000UL) { lastCheckMs = now; fetchBlocklist(updateUrl); }
  }
  if (!busy) delay(1);   // sleep only when idle: full speed under load, cool when quiet
}
