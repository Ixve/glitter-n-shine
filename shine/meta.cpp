

#include "meta.h"

#include <windows.h>
#include <winhttp.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <optional>
#include <string>
#include <vector>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "advapi32.lib")

#ifndef WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL
#define WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL 133
#endif

static const int MASK_SIZE = 0x284;
static const int SECTION_COUNT = 32;
static const int SECTION_FIRST = 8;
static const int SECTION_STRIDE = 12;
static const size_t TABLE_END = SECTION_FIRST + SECTION_COUNT * SECTION_STRIDE;
static const uint8_t NATIVE_VERSION = 107;

static const int SEC_EVENTS = 3;
static const int SEC_PROPERTIES = 4;
static const int SEC_METHODS = 5;
static const int SEC_FIELDS = 11;
static const int SEC_GENERIC_CONTAINERS = 14;
static const int SEC_NESTED_TYPES = 15;
static const int SEC_INTERFACE_OFFSETS = 18;
static const int SEC_TYPE_DEFINITIONS = 19;

static uint32_t rd32(const uint8_t *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
         ((uint32_t)p[3] << 24);
}

static void wr32(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)(v);
  p[1] = (uint8_t)(v >> 8);
  p[2] = (uint8_t)(v >> 16);
  p[3] = (uint8_t)(v >> 24);
}

static std::string field(const std::string &json, const char *name) {
  std::string search = std::string("\"") + name + "\"";
  size_t pos = json.find(search);
  if (pos == std::string::npos)
    return {};
  pos += search.size();
  while (pos < json.size() && isspace(static_cast<unsigned char>(json[pos])))
    ++pos;
  if (pos >= json.size() || json[pos++] != ':')
    return {};
  while (pos < json.size() && isspace(static_cast<unsigned char>(json[pos])))
    ++pos;
  if (pos >= json.size() || json[pos++] != '"')
    return {};
  std::string out;
  for (size_t i = pos; i < json.size(); ++i) {
    if (json[i] == '\\' && i + 1 < json.size()) {
      out += json[++i];
      continue;
    }
    if (json[i] == '"')
      break;
    out += json[i];
  }
  return out;
}

static std::optional<std::vector<uint8_t>>
deshuffle(const std::vector<uint8_t> &input) {
  if (input.size() < 4)
    return std::nullopt;

  std::vector<uint8_t> buf(input);
  size_t startEntry = buf.size() % 0xAAB;
  size_t tableSize = startEntry + buf.size();

  std::vector<uint64_t> table(tableSize);
  uint64_t cursor = 0x65F6D;
  for (size_t i = 0; i < tableSize; ++i) {
    table[i] = (0x18C985ULL * cursor++ + 0x3D07C92BULL) % 0x8ED7A18DULL;
    if (cursor > 0xA53F260DDB0ULL)
      cursor = 0;
  }

  for (size_t i = 1; i < buf.size(); ++i) {
    size_t j = (size_t)(table[i + startEntry] % (uint64_t)i);
    std::swap(buf[i], buf[j]);
  }

  int32_t sz;
  memcpy(&sz, buf.data(), 4);
  if (sz < 0 || (size_t)(4 + sz) > buf.size())
    return std::nullopt;
  return std::vector<uint8_t>(buf.begin() + 4, buf.begin() + 4 + sz);
}

static uint32_t mix(uint32_t v) {
  v = v % 0x8B6u;
  v = v * 0x16579Fu;
  v = v + 0x3CF8479Fu;
  v = (uint32_t)((uint64_t)v % 0xC465321Cu);
  return v;
}

static bool header(std::vector<uint8_t> &m) {
  printf("[?] Unmasking header (0x%X)...\n", MASK_SIZE);
  fflush(stdout);
  if (m.size() < (size_t)MASK_SIZE * 2)
    return false;
  for (int i = 0; i < MASK_SIZE; ++i)
    m[i] ^= m[i + MASK_SIZE];
  return true;
}

static uint32_t nibble(uint32_t v) {
  uint32_t s8 = (uint32_t)(8u * (v & 0xF1111111u));
  uint32_t sr3 = (v >> 3) & 0x11111111u;
  uint32_t p1 = (((v & 0x66666666u) | s8 | sr3) >> 2) & 0x33333333u;
  uint32_t p2 = (uint32_t)(4u * ((v & 0x62222222u) | (s8 & 0xF3333333u) | sr3));
  return p1 | p2;
}

struct Env {
  uint32_t key;
  std::string version;
};

static std::optional<Env> envelope(std::vector<uint8_t> &m) {
  printf("[?] Decoding header envelope...\n");
  fflush(stdout);
  if (m.size() < 8)
    return std::nullopt;
  uint32_t offset = rd32(m.data());
  uint32_t size = rd32(m.data() + 4);
  if (offset < 8 || offset > 0x180 || size < 1 || size > 0x100 ||
      (size_t)offset + size > m.size())
    return std::nullopt;

  for (uint32_t i = 0; i < size / 4; ++i) {
    size_t p = (size_t)offset + i * 4;
    wr32(m.data() + p, nibble(rd32(m.data() + p)));
  }

  Env e;
  e.key = rd32(m.data() + offset);
  for (size_t i = (size_t)offset + 4; i < m.size() && m[i]; ++i)
    e.version += (char)m[i];

  memset(m.data(), 0, 8);
  if (e.version.empty())
    return std::nullopt;
  return e;
}

static DWORD post(const std::string &body, const std::string &session,
                  std::vector<uint8_t> &out) {
  out.clear();
  HINTERNET hSess =
      WinHttpOpen(nullptr, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                  WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
  if (!hSess)
    return 0;
  WinHttpSetTimeouts(hSess, 60000, 60000, 60000, 120000);
  DWORD noHttp2 = 0;
  WinHttpSetOption(hSess, WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL, &noHttp2,
                   sizeof(noHttp2));

  HINTERNET hConn = WinHttpConnect(hSess, L"gw-pvp.escapefromtarkov.com",
                                   INTERNET_DEFAULT_HTTPS_PORT, 0);
  HINTERNET hReq =
      hConn ? WinHttpOpenRequest(hConn, L"POST", L"/client/metadata", nullptr,
                                 WINHTTP_NO_REFERER,
                                 WINHTTP_DEFAULT_ACCEPT_TYPES,
                                 WINHTTP_FLAG_SECURE)
            : nullptr;
  if (!hReq) {
    if (hConn)
      WinHttpCloseHandle(hConn);
    WinHttpCloseHandle(hSess);
    return 0;
  }

  std::wstring hdrs = L"Connection: Keep-Alive\r\nContent-Type: application/json\r\nCookie: PHPSESSID=";
  hdrs.append(session.begin(), session.end());
  hdrs += L"\r\n";
  WinHttpAddRequestHeaders(hReq, hdrs.c_str(), (DWORD)-1,
                           WINHTTP_ADDREQ_FLAG_ADD |
                               WINHTTP_ADDREQ_FLAG_REPLACE);

  DWORD status = 0;
  if (WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                         (LPVOID)body.data(), (DWORD)body.size(),
                         (DWORD)body.size(), 0) &&
      WinHttpReceiveResponse(hReq, nullptr)) {
    DWORD statusSize = sizeof(status);
    WinHttpQueryHeaders(hReq,
                        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &status, &statusSize,
                        WINHTTP_NO_HEADER_INDEX);
    DWORD avail = 0;
    while (status >= 200 && status < 300 &&
           WinHttpQueryDataAvailable(hReq, &avail) && avail > 0) {
      size_t off = out.size();
      if (avail > 256 * 1024 * 1024ULL - off)
        break;
      out.resize(off + avail);
      DWORD rd = 0;
      if (!WinHttpReadData(hReq, out.data() + off, avail, &rd))
        break;
      out.resize(off + rd);
    }
  }

  WinHttpCloseHandle(hReq);
  WinHttpCloseHandle(hConn);
  WinHttpCloseHandle(hSess);
  return status;
}

static std::string fetch(const std::string &version,
                         const std::string &requestKey,
                         const std::string &session) {
  printf("[?] Fetching stripped header bytes from server...\n");
  fflush(stdout);

  std::string body =
      "{\"version\":\"" + version + "\",\"key\":\"" + requestKey + "\"}";

  const int ATTEMPTS = 6;
  for (int attempt = 1; attempt <= ATTEMPTS; ++attempt) {
    std::vector<uint8_t> raw;
    DWORD status = post(body, session, raw);

    if (status >= 200 && status < 300 && !raw.empty()) {
      auto deshuffled = deshuffle(raw);
      if (deshuffled) {
        std::string json(deshuffled->begin(), deshuffled->end());
        std::string value = field(json, "value");
        if (!value.empty())
          return value;
        printf("[-] Response missing 'value' field\n");
      } else {
        printf("[-] Failed to deshuffle /client/metadata response\n");
      }
    } else {
      printf("[-] /client/metadata HTTP %lu (attempt %d/%d)\n", status, attempt,
             ATTEMPTS);
    }
    fflush(stdout);
    if (attempt < ATTEMPTS)
      Sleep((DWORD)attempt * 3000);
  }
  return {};
}

static std::optional<std::vector<uint8_t>>
layout(std::string value, uint32_t subKey, uint32_t key) {
  uint32_t expected = 40 + mix(key) % 40;
  if (value.size() != (size_t)expected * 2) {
    printf("[-] Layout value is %zu hex chars, expected %u bytes\n",
           value.size(), expected);
    return std::nullopt;
  }
  uint32_t swap = mix(subKey);
  for (size_t i = 1; i < value.size(); ++i) {
    size_t j = (size_t)(swap % (uint32_t)(i + 1));
    std::swap(value[i], value[j]);
  }
  std::vector<uint8_t> out(value.size() / 2);
  for (size_t i = 0; i < out.size(); ++i) {
    char hi = value[i * 2], lo = value[i * 2 + 1];
    if (!isxdigit((unsigned char)hi) || !isxdigit((unsigned char)lo))
      return std::nullopt;
    char pair[3] = {hi, lo, 0};
    out[i] = (uint8_t)strtoul(pair, nullptr, 16);
  }
  return out;
}

static void decryptBody(std::vector<uint8_t> &m,
                        const std::vector<uint8_t> &hb) {
  uint8_t b[4] = {0xAA, 0xFF, 0x19, 0x69};
  for (size_t i = 0; i < hb.size(); ++i)
    b[i & 3] ^= hb[i];
  uint32_t bodyKey = rd32(b);
  printf("[+] Body key: 0x%08X\n", bodyKey);
  fflush(stdout);

  std::vector<uint8_t> ks(m.size());
  for (size_t i = 0; i < ks.size(); ++i)
    ks[i] = (uint8_t)(i + 2 * (i / 0xFE) + 1);

  if (ks.size() > 1) {
    uint64_t swap =
        (0x3CF8479FULL + 0x16579FULL * (bodyKey % 0x8B6ULL)) % 0xC465321CULL;
    for (size_t i = ks.size() - 1; i > 0; --i) {
      size_t j = (size_t)(swap % (uint64_t)(i + 1));
      std::swap(ks[i], ks[j]);
    }
  }

  for (size_t i = (size_t)MASK_SIZE; i < m.size(); ++i)
    m[i] ^= ks[i];
}

static bool reinsert(std::vector<uint8_t> &m, const std::vector<uint8_t> &hb,
                     uint32_t key) {
  printf("[?] Reinserting %zu stripped header bytes...\n", hb.size());
  fflush(stdout);
  int count = (int)hb.size();
  const int CAND_FIRST = 8, CAND_COUNT = 388;
  if (count <= 0 || count > CAND_COUNT ||
      m.size() < (size_t)(CAND_FIRST + CAND_COUNT) + (size_t)count)
    return false;

  std::vector<int> available;
  for (int i = 0; i < CAND_COUNT; ++i)
    available.push_back(CAND_FIRST + i);
  std::vector<int> positions;
  uint32_t seed = key;
  for (int i = 0; i < count; ++i) {
    seed = mix(seed);
    int idx = (int)(seed % (uint32_t)available.size());
    positions.push_back(available[idx]);
    available.erase(available.begin() + idx);
  }
  std::sort(positions.begin(), positions.end());

  size_t used = m.size() - count;
  for (int i = 0; i < count; ++i) {
    int offset = positions[i];
    if ((size_t)offset > used)
      return false;
    memmove(m.data() + offset + 1, m.data() + offset, used - (size_t)offset);
    m[offset] = hb[i];
    ++used;
  }
  return true;
}

static uint32_t slot(const std::vector<uint8_t> &m, int sec, int which) {
  return rd32(m.data() + SECTION_FIRST + sec * SECTION_STRIDE + which * 4);
}

static bool validate(const std::vector<uint8_t> &m) {
  if (m.size() < TABLE_END)
    return false;
  bool ok = true;
  for (int i = 0; i < SECTION_COUNT; ++i) {
    uint32_t off = slot(m, i, 0), sz = slot(m, i, 1);
    if (sz && ((size_t)off < TABLE_END || (size_t)off + sz > m.size())) {
      printf("[-] section %02d out of range: off=0x%X size=0x%X\n", i, off, sz);
      ok = false;
    }
  }
  return ok;
}

static bool reorder(std::vector<uint8_t> &m, uint32_t key) {
  printf("[?] Reordering type definitions (v106)...\n");
  fflush(stdout);

  uint32_t tdOff = slot(m, SEC_TYPE_DEFINITIONS, 0);
  uint32_t tdSize = slot(m, SEC_TYPE_DEFINITIONS, 1);
  uint32_t tdCount = slot(m, SEC_TYPE_DEFINITIONS, 2);
  if (!tdCount || tdSize % tdCount || (size_t)tdOff + tdSize > m.size()) {
    printf("[-] bad typedef section: off=0x%X sz=0x%X cnt=%u\n", tdOff, tdSize,
           tdCount);
    return false;
  }
  int recordSize = (int)(tdSize / tdCount);

  auto width = [&](int sec) {
    uint32_t c = slot(m, sec, 2);
    return c <= 0xFF ? 1 : c <= 0xFFFF ? 2 : 4;
  };
  uint32_t ioSize = slot(m, SEC_INTERFACE_OFFSETS, 1);
  uint32_t ioCount = slot(m, SEC_INTERFACE_OFFSETS, 2);
  if (!ioCount) {
    printf("[-] interfaceOffsets.count=0\n");
    return false;
  }
  int T = (int)(ioSize / ioCount) - 4;
  if (T != 1 && T != 2 && T != 4) {
    printf("[-] bad TypeIndex width %d (ioSize=%u ioCount=%u)\n", T, ioSize,
           ioCount);
    return false;
  }
  int G = width(SEC_GENERIC_CONTAINERS);
  int F = width(SEC_FIELDS);
  int M = width(SEC_METHODS);
  int E = width(SEC_EVENTS);
  int P = width(SEC_PROPERTIES);
  int N = width(SEC_NESTED_TYPES);
  int I = width(SEC_INTERFACE_OFFSETS);
  printf("[+] v106 typedef widths T=%d G=%d F=%d M=%d E=%d P=%d N=%d I=%d\n", T,
         G, F, M, E, P, N, I);

  const int TD = 25;
  int sizes[TD] = {4, 4, T, T, T, G, 4, F, M, E, P, N, I,
                   4, I, 2, 2, 2, 2, 2, 2, 2, 2, 4, 4};
  int sum = 0;
  for (int i = 0; i < TD; ++i)
    sum += sizes[i];
  if (sum != recordSize) {
    printf("[-] v106 field sum %d != record %d\n", sum, recordSize);
    return false;
  }

  uint32_t swap = mix(key);
  int order[TD];
  for (int i = 0; i < TD; ++i)
    order[i] = i;
  for (int i = 0; i < TD; ++i) {
    int from = TD - 1 - i;
    int to = (int)(swap % (uint32_t)(from + 1));
    std::swap(order[from], order[to]);
  }

  int offs[TD] = {};
  int running = 0;
  for (int i = 0; i < TD; ++i) {
    offs[order[i]] = running;
    running += sizes[order[i]];
  }

  std::vector<uint8_t> tmp(recordSize);
  for (uint32_t rel = 0; rel < tdSize; rel += recordSize) {
    uint8_t *entry = m.data() + tdOff + rel;
    int dst = 0;
    for (int f = 0; f < TD; ++f) {
      memcpy(tmp.data() + dst, entry + offs[f], sizes[f]);
      dst += sizes[f];
    }
    memcpy(entry, tmp.data(), recordSize);
  }
  return true;
}

static void normalize(std::vector<uint8_t> &m) {
  if (m.size() < TABLE_END)
    return;
  struct Raw {
    uint32_t a, b, c;
  };
  Raw raw[SECTION_COUNT];
  for (int i = 0; i < SECTION_COUNT; ++i)
    raw[i] = {slot(m, i, 0), slot(m, i, 1), slot(m, i, 2)};
  for (int i = 0; i < SECTION_COUNT; ++i) {
    uint8_t *p = m.data() + SECTION_FIRST + i * SECTION_STRIDE;
    wr32(p, raw[i].b);
    wr32(p + 4, raw[i].c);
    wr32(p + 8, i + 1 < SECTION_COUNT ? raw[i + 1].a : raw[i].c / 4);
  }
}

static void scrub(std::vector<uint8_t> &m) {
  if (m.size() <= TABLE_END)
    return;

  uint32_t first = 0xFFFFFFFFu;
  for (int i = 0; i < SECTION_COUNT; ++i) {
    uint32_t off = slot(m, i, 0), sz = slot(m, i, 1);
    if (sz && off && off < first)
      first = off;
  }
  static const size_t MAX_PAD = 0x1000;
  if (first == 0xFFFFFFFFu || (size_t)first <= TABLE_END ||
      (size_t)first > m.size() || (size_t)first - TABLE_END > MAX_PAD) {
    printf("[-] Refusing to scrub header padding (earliest section %u, table "
           "ends %zu)\n",
           first, TABLE_END);
    fflush(stdout);
    return;
  }

  size_t wiped = (size_t)first - TABLE_END;
  memset(m.data() + TABLE_END, 0, wiped);
  printf("[+] Cleared %zu bytes of BSG header padding\n", wiped);
  fflush(stdout);
}

static bool save(const std::wstring &path, const std::vector<uint8_t> &data) {
  char a[MAX_PATH * 2] = {};
  WideCharToMultiByte(CP_ACP, 0, path.c_str(), -1, a, sizeof(a), nullptr, nullptr);
  HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                         FILE_ATTRIBUTE_NORMAL, nullptr);
  if (h == INVALID_HANDLE_VALUE) {
    printf("[-] Cannot create %s (err=%lu)\n", a, GetLastError());
    fflush(stdout);
    return false;
  }
  DWORD wrote = 0;
  BOOL ok = WriteFile(h, data.data(), (DWORD)data.size(), &wrote, nullptr) &&
            FlushFileBuffers(h) && wrote == data.size();
  CloseHandle(h);
  if (!ok) {
    DeleteFileW(path.c_str());
    printf("[-] Failed to write %s\n", a);
  } else {
    printf("[+] Wrote %s (%zu bytes)\n", a, data.size());
  }
  fflush(stdout);
  return ok;
}

namespace meta {
bool decrypt(std::vector<uint8_t> metadata, uint64_t fileTime,
             const std::string &session, const wchar_t *outputDir,
             const wchar_t *) {
  if (session.empty()) {
    printf("[-] No game session supplied\n");
    fflush(stdout);
    return false;
  }
  if (metadata.size() < 0x400) {
    printf("[-] Metadata too small (%zu bytes)\n", metadata.size());
    fflush(stdout);
    return false;
  }

  std::wstring dir = outputDir;
  if (!dir.empty() && dir.back() != L'\\')
    dir += L'\\';

  save(dir + L"encrypted_global-metadata.dat", metadata);

  printf("[?] Decrypting global-metadata.dat (%zu bytes)\n", metadata.size());
  fflush(stdout);

  if (rd32(metadata.data()) == 0xFAB11BAFu) {
    printf("[+] Input already decrypted; writing as native output.\n");
    fflush(stdout);
    return save(dir + L"global-metadata.dat", metadata);
  }

  uint32_t subKey = (mix((uint32_t)(fileTime & 0xFFFFFFFF)) % 0xA) + 5;
  printf("[+] File time: 0x%016llX  subKey: %u\n", (unsigned long long)fileTime,
         subKey);
  fflush(stdout);

  if (!header(metadata)) {
    printf("[-] Header unmask failed\n");
    fflush(stdout);
    return false;
  }
  auto env = envelope(metadata);
  if (!env) {
    printf("[-] Invalid encrypted metadata header\n");
    fflush(stdout);
    return false;
  }
  std::string requestKey = std::to_string(mix(env->key + subKey));
  printf("[+] Version: %s  key: 0x%08X  requestKey: %s\n", env->version.c_str(),
         env->key, requestKey.c_str());
  fflush(stdout);

  std::string value = fetch(env->version, requestKey, session);
  if (value.empty()) {
    printf("[-] Failed to obtain stripped header bytes from server\n");
    fflush(stdout);
    return false;
  }
  auto hb = layout(value, subKey, env->key);
  if (!hb) {
    printf("[-] Invalid layout value from server\n");
    fflush(stdout);
    return false;
  }
  printf("[+] Stripped header bytes: %zu\n", hb->size());
  fflush(stdout);

  decryptBody(metadata, *hb);
  if (!reinsert(metadata, *hb, env->key)) {
    printf("[-] Header reinsertion failed\n");
    fflush(stdout);
    return false;
  }

  normalize(metadata);
  if (!validate(metadata))
    printf("[-] section table still out of range after normalisation\n");
  if (!reorder(metadata, env->key))
    printf("[!!!] v106 typedef reorder failed\n");
  scrub(metadata);
  wr32(metadata.data(), 0xFAB11BAFu);
  metadata[4] = NATIVE_VERSION;
  metadata[5] = metadata[6] = metadata[7] = 0;

  return save(dir + L"global-metadata.dat", metadata);
}
}
