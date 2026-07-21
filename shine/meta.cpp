

#include "meta.h"

#include <windows.h>
#include <winhttp.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "advapi32.lib")

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

static uint32_t mix(uint32_t v) {
  v = v % 0x8BAu;
  v = v * 0x1657A1u;
  v = v + 0x3CF8479Fu;
  v = v % 0xC4653218u;
  return v;
}

static std::string cstr(const uint8_t *buf, size_t bufLen, size_t start) {
  std::string out;
  for (size_t i = start; i < bufLen && buf[i]; ++i)
    out += (char)buf[i];
  return out;
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
    table[i] = (1624453ULL * cursor++ + 1023920427ULL) % 0x8ED7A18DULL;
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

static std::wstring find_meta() {
  constexpr const wchar_t *base =
      L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall";
  constexpr const wchar_t *rel =
      L"EscapeFromTarkov_Data\\il2cpp_data\\Metadata\\global-metadata.dat";
  const HKEY roots[] = {HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER};
  const REGSAM views[] = {KEY_WOW64_32KEY, KEY_WOW64_64KEY};
  for (HKEY root : roots) {
    for (REGSAM view : views) {
      HKEY list = nullptr;
      if (RegOpenKeyExW(root, base, 0, KEY_READ | view, &list) != ERROR_SUCCESS)
        continue;
      wchar_t name[256];
      for (DWORD i = 0;; ++i) {
        DWORD len = static_cast<DWORD>(std::size(name));
        if (RegEnumKeyExW(list, i, name, &len, nullptr, nullptr, nullptr,
                          nullptr) != ERROR_SUCCESS)
          break;
        HKEY key = nullptr;
        if (RegOpenKeyExW(list, name, 0, KEY_READ, &key) != ERROR_SUCCESS)
          continue;
        wchar_t title[512] = {};
        DWORD titleSize = sizeof(title);
        RegQueryValueExW(key, L"DisplayName", nullptr, nullptr,
                         reinterpret_cast<BYTE *>(title), &titleSize);
        if (wcsstr(title, L"Escape from Tarkov")) {
          DWORD size = 0;
          DWORD type = 0;
          if (RegQueryValueExW(key, L"InstallLocation", nullptr, &type, nullptr,
                               &size) == ERROR_SUCCESS &&
              (type == REG_SZ || type == REG_EXPAND_SZ) &&
              size >= sizeof(wchar_t)) {
            std::wstring dir(size / sizeof(wchar_t), L'\0');
            if (RegQueryValueExW(key, L"InstallLocation", nullptr, &type,
                                 reinterpret_cast<BYTE *>(dir.data()),
                                 &size) == ERROR_SUCCESS) {
              dir.resize(wcsnlen_s(dir.c_str(), dir.size()));
              std::filesystem::path path = std::filesystem::path(dir) / rel;
              if (std::filesystem::is_regular_file(path)) {
                RegCloseKey(key);
                RegCloseKey(list);
                return path.wstring();
              }
            }
          }
        }
        RegCloseKey(key);
      }
      RegCloseKey(list);
    }
  }
  return {};
}

static bool header(std::vector<uint8_t> &m, size_t size) {
  printf("[?] Decrypting header...\n");
  fflush(stdout);
  if (!size || m.size() < size * 2)
    return false;
  for (size_t i = 0; i < size; ++i)
    m[i] ^= m[i + size];
  return true;
}

static uint32_t nibble(uint32_t v) {
  uint32_t s8 = (uint32_t)(8u * (v & 0xF1111111u));
  uint32_t sr3 = (v >> 3) & 0x11111111u;

  uint32_t p1 = (((v & 0x66666666u) | s8 | sr3) >> 2) & 0x33333333u;
  uint32_t p2 = (uint32_t)(4u * ((v & 0x62222222u) | (s8 & 0xF3333333u) | sr3));
  return p1 | p2;
}

struct Ver {
  uint32_t key;
  std::string version;
  std::string requestKey;
};

static std::optional<Ver> version(std::vector<uint8_t> &m, uint32_t subKey) {
  printf("[?] Extracting version and key...\n");
  fflush(stdout);

  if (m.size() < 8)
    return std::nullopt;
  uint32_t size = rd32(m.data());
  uint32_t offset = rd32(m.data() + 4);
  if (size < 4 || size % 4 || offset > m.size() || size > m.size() - offset)
    return std::nullopt;
  uint32_t count = size / 4;
  uint32_t key = 0;

  for (uint32_t i = 0; i < count; ++i) {
    size_t pos = (size_t)offset + i * 4;
    uint32_t v = rd32(m.data() + pos);
    v = nibble(v);
    wr32(m.data() + pos, v);
    if (i == 0)
      key = v;
  }

  std::string version = cstr(m.data(), m.size(), (size_t)offset + 4);
  if (version.empty())
    return std::nullopt;
  std::string requestKey = std::to_string(mix(key + subKey));

  return Ver{key, version, requestKey};
}

static void restore(std::vector<uint8_t> &m) {
  printf("[?] Restoring IL2CPP header...\n");
  fflush(stdout);
  wr32(m.data(), 0xFAB11BAFu);
  wr32(m.data() + 4, 0x1Fu);
}

struct Prop {
  uint32_t dataSize, dataOffset;
};

static std::vector<Prop>
fetch(uint32_t subKey, const std::string &version,
                        const std::string &requestKey,
                        const std::string &session,
                        const wchar_t *userAgent) {
  printf("[?] Fetching section layout from server...\n");
  fflush(stdout);

  std::string body =
      "{\"version\":\"" + version + "\",\"key\":\"" + requestKey + "\"}";

  HINTERNET hSess =
      WinHttpOpen(userAgent, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                  WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
  if (!hSess)
    return {};

  HINTERNET hConn = WinHttpConnect(hSess, L"gw-pvp.escapefromtarkov.com",
                                   INTERNET_DEFAULT_HTTPS_PORT, 0);
  HINTERNET hReq =
      hConn
          ? WinHttpOpenRequest(hConn, L"POST", L"/client/metadata", nullptr,
                               WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                               WINHTTP_FLAG_SECURE)
          : nullptr;

  if (!hReq) {
    if (hConn)
      WinHttpCloseHandle(hConn);
    WinHttpCloseHandle(hSess);
    return {};
  }

  std::wstring hdrs = L"Cookie: PHPSESSID=";
  hdrs.append(session.begin(), session.end());
  hdrs += L"\r\nContent-Type: application/json\r\n";
  BOOL added = WinHttpAddRequestHeaders(hReq, hdrs.c_str(), (DWORD)-1,
                                        WINHTTP_ADDREQ_FLAG_ADD |
                                            WINHTTP_ADDREQ_FLAG_REPLACE);

  BOOL sent = added && WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                          (LPVOID)body.data(), (DWORD)body.size(),
                                          (DWORD)body.size(), 0);

  std::vector<uint8_t> rawResponse;
  if (sent && WinHttpReceiveResponse(hReq, nullptr)) {
    DWORD status = 0;
    DWORD statusSize = sizeof(status);
    if (WinHttpQueryHeaders(hReq, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &status, &statusSize,
                            WINHTTP_NO_HEADER_INDEX) && status >= 200 && status < 300) {
      DWORD avail = 0;
      while (WinHttpQueryDataAvailable(hReq, &avail) && avail > 0) {
        size_t off = rawResponse.size();
        if (avail > 256 * 1024 * 1024ULL - off) {
          rawResponse.clear();
          break;
        }
        rawResponse.resize(off + avail);
        DWORD rd = 0;
        if (!WinHttpReadData(hReq, rawResponse.data() + off, avail, &rd)) {
          rawResponse.clear();
          break;
        }
        rawResponse.resize(off + rd);
      }
    }
  }

  WinHttpCloseHandle(hReq);
  WinHttpCloseHandle(hConn);
  WinHttpCloseHandle(hSess);

  auto deshuffled = deshuffle(rawResponse);
  if (!deshuffled) {
    printf("[-] Failed to deshuffle /client/metadata response\n");
    fflush(stdout);
    return {};
  }

  std::string json(deshuffled->begin(), deshuffled->end());
  std::string value = field(json, "value");
  if (value.empty()) {
    printf("[-] Server response missing 'value' field\n");
    fflush(stdout);
    return {};
  }

  uint32_t transformed = mix(subKey);
  for (size_t i = 0; i < value.size(); ++i) {
    size_t j = (size_t)((uint32_t)transformed % (uint32_t)(i + 1));
    std::swap(value[i], value[j]);
  }

  if (value.size() % 16 != 0) {
    printf("[-] Invalid metadata value length (%zu)\n", value.size());
    fflush(stdout);
    return {};
  }

  size_t propCount = value.size() / 16;
  if (!propCount || propCount > 31)
    return {};
  std::vector<Prop> props;
  props.reserve(propCount);

  for (size_t i = 0; i < propCount; ++i) {
    const char *part = value.data() + i * 16;
    for (size_t j = 0; j < 16; ++j)
      if (!isxdigit(static_cast<unsigned char>(part[j])))
        return {};
    char sizeText[9] = {};
    char offsetText[9] = {};
    memcpy(sizeText, part, 8);
    memcpy(offsetText, part + 8, 8);
    uint32_t dataSize = static_cast<uint32_t>(strtoul(sizeText, nullptr, 16));
    uint32_t dataOffset = static_cast<uint32_t>(strtoul(offsetText, nullptr, 16));
    printf("[+] Section %02zu: offset=0x%08X  size=0x%08X\n", i, dataOffset,
           dataSize);
    props.push_back({dataSize, dataOffset});
  }
  fflush(stdout);

  return props;
}

static uint32_t list_key(const std::vector<Prop> &props) {
  uint8_t b0 = 0xAA, b1 = 0xAA, b2 = 0xAA, b3 = 0xAA;
  for (const auto &p : props) {
    b0 ^= (uint8_t)((p.dataSize & 0xFF) ^ ((p.dataOffset >> 24) & 0xFF));
    b1 ^= (uint8_t)(((p.dataSize >> 8) & 0xFF) ^ ((p.dataOffset >> 16) & 0xFF));
    b2 ^= (uint8_t)(((p.dataSize >> 16) & 0xFF) ^ ((p.dataOffset >> 8) & 0xFF));
    b3 ^= (uint8_t)((p.dataOffset & 0xFF) ^ ((p.dataSize >> 24) & 0xFF));
  }
  return (uint32_t)b0 | ((uint32_t)b1 << 8) | ((uint32_t)b2 << 16) |
         ((uint32_t)b3 << 24);
}

static void permute(std::vector<uint8_t> &buf,
                                    uint32_t secretKey) {
  if (buf.size() <= 1)
    return;

  constexpr uint64_t KM = 0x8BA;
  constexpr uint64_t MUL = 0x1657A1;
  constexpr uint64_t ADD = 0x3CF8479F;
  constexpr uint64_t FM = 0xC4653218;

  uint64_t reduced = (uint64_t)secretKey % KM;
  uint64_t swapBase = (ADD + MUL * reduced) % FM;

  for (size_t i = buf.size() - 1; i > 0; --i) {
    size_t j = (size_t)(swapBase % (uint64_t)(i + 1));
    std::swap(buf[i], buf[j]);
  }
}

static void decrypt_body(std::vector<uint8_t> &m,
                                  const std::vector<Prop> &props,
                                  int headerSize) {
  printf("[?] Decrypting metadata body...\n");
  fflush(stdout);

  uint32_t hlKey = list_key(props);
  printf("[+] Header list key: 0x%08X\n", hlKey);
  fflush(stdout);

  std::vector<uint8_t> ks(m.size());
  for (size_t i = 0; i < ks.size(); ++i)
    ks[i] = (uint8_t)(i + 2 * (i / 0xFE) + 1);

  permute(ks, hlKey);

  for (size_t i = (size_t)headerSize; i < m.size(); ++i)
    m[i] ^= ks[i];
}

static bool reinsert(std::vector<uint8_t> &m, const std::vector<Prop> &props,
                     uint32_t key) {
  printf("[?] Reinserting headers...\n");
  fflush(stdout);

  const int N = 31;
  if (props.empty() || props.size() > N || m.size() < 8 * N + 8 ||
      m.size() < 8 * props.size())
    return false;

  uint32_t transformed = mix(key);

  std::vector<int> available;
  for (int i = 1; i <= N; ++i)
    available.push_back(i);

  std::vector<int> positions;
  for (size_t i = 0; i < props.size(); ++i) {
    int index = (int)((uint32_t)transformed % (uint32_t)(N - (int)i));
    positions.push_back(available[index]);
    available.erase(available.begin() + index);
  }
  std::sort(positions.begin(), positions.end());

  int usedSize = (int)m.size() - 8 * (int)positions.size();
  for (size_t i = 0; i < positions.size(); ++i) {
    int offset = positions[i] * 8;
    if (offset < 0 || offset > usedSize)
      return false;
    memmove(m.data() + offset + 8, m.data() + offset,
            (size_t)(usedSize - offset));
    wr32(m.data() + offset, props[i].dataSize);
    wr32(m.data() + offset + 4, props[i].dataOffset);
    usedSize += 8;
  }

  for (int i = 0; i < N; ++i) {
    int base = 8 + i * 8;
    uint32_t dSize = rd32(m.data() + base);
    uint32_t dOff = rd32(m.data() + base + 4);
    wr32(m.data() + base, dOff);
    wr32(m.data() + base + 4, dSize);
  }
  return true;
}

static bool reorder(std::vector<uint8_t> &m, uint32_t key) {
  printf("[?] Reordering type definitions...\n");
  fflush(stdout);

  constexpr int FIELD_COUNT = 26;
  constexpr int TD_OFFSET_POS = 160;
  constexpr int TD_SIZE_POS = 164;
  constexpr int TD_STRUCT_SIZE = 88;
  if (m.size() < TD_SIZE_POS + 4)
    return false;

  static const int FIELD_SIZES[FIELD_COUNT] = {4, 4, 4, 4, 4, 4, 4, 4, 4,
                                               4, 4, 4, 4, 4, 4, 4, 2, 2,
                                               2, 2, 2, 2, 2, 2, 4, 4};

  uint32_t transformed = mix(key);

  int fieldOrder[FIELD_COUNT];
  for (int i = 0; i < FIELD_COUNT; ++i)
    fieldOrder[i] = i;
  for (int i = 0; i < FIELD_COUNT; ++i) {
    int from = FIELD_COUNT - 1 - i;
    int to = (int)((uint32_t)transformed % (uint32_t)(from + 1));
    std::swap(fieldOrder[from], fieldOrder[to]);
  }

  int fieldOffsets[FIELD_COUNT] = {};
  int running = 0;
  for (int i = 0; i < FIELD_COUNT; ++i) {
    int f = fieldOrder[i];
    fieldOffsets[f] = running;
    running += FIELD_SIZES[f];
  }

  uint32_t rawOffset = rd32(m.data() + TD_OFFSET_POS);
  uint32_t rawSize = rd32(m.data() + TD_SIZE_POS);
  if (rawSize % TD_STRUCT_SIZE || rawOffset > m.size() ||
      rawSize > m.size() - rawOffset)
    return false;

  std::vector<uint8_t> tmp(TD_STRUCT_SIZE);
  for (uint32_t rel = 0; rel < rawSize; rel += TD_STRUCT_SIZE) {
    size_t entryBase = rawOffset + rel;
    int dst = 0;
    for (int field = 0; field < FIELD_COUNT; ++field) {
      int sz = FIELD_SIZES[field];
      memcpy(tmp.data() + dst, m.data() + entryBase + fieldOffsets[field],
             (size_t)sz);
      dst += sz;
    }
    memcpy(m.data() + entryBase, tmp.data(), TD_STRUCT_SIZE);
  }
  return true;
}

namespace meta {
void run(const std::vector<uint8_t> &decodedJson, const wchar_t *outputDir, const wchar_t *userAgent) {

  std::string json(decodedJson.begin(), decodedJson.end());
  std::string session = field(json, "session");
  if (session.empty()) {
    printf("[-] Could not parse session key from response JSON\n");
    fflush(stdout);
    return;
  }
  printf("[?] Searching for EscapeFromTarkov...\n");
  fflush(stdout);
  std::wstring metaPath = find_meta();
  if (metaPath.empty()) {
    printf("[-] Could not locate global-metadata.dat\n");
    fflush(stdout);
    return;
  }
  char metaPathA[MAX_PATH * 2] = {};
  WideCharToMultiByte(CP_ACP, 0, metaPath.c_str(), -1, metaPathA,
                      sizeof(metaPathA), nullptr, nullptr);
  printf("[+] EFT:     %s\n", metaPathA);
  fflush(stdout);

  HANDLE hFile =
      CreateFileW(metaPath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                  OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (hFile == INVALID_HANDLE_VALUE) {
    printf("[-] Cannot open global-metadata.dat (err=%lu)\n", GetLastError());
    fflush(stdout);
    return;
  }

  FILETIME ftCreate = {};
  uint64_t fileTime = ((uint64_t)ftCreate.dwHighDateTime << 32) |
                      (uint64_t)ftCreate.dwLowDateTime;

  LARGE_INTEGER fileSize = {};
  if (!GetFileTime(hFile, &ftCreate, nullptr, nullptr) ||
      !GetFileSizeEx(hFile, &fileSize) || fileSize.QuadPart < 0x400 ||
      fileSize.QuadPart > MAXDWORD) {
    CloseHandle(hFile);
    printf("[-] Invalid global-metadata.dat\n");
    fflush(stdout);
    return;
  }
  fileTime = ((uint64_t)ftCreate.dwHighDateTime << 32) |
             (uint64_t)ftCreate.dwLowDateTime;
  std::vector<uint8_t> metadata((size_t)fileSize.QuadPart);
  DWORD bytesRead = 0;
  BOOL read = ReadFile(hFile, metadata.data(), (DWORD)fileSize.QuadPart,
                       &bytesRead, nullptr);
  CloseHandle(hFile);

  if (!read || bytesRead != (DWORD)fileSize.QuadPart) {
    printf("[-] Partial read of global-metadata.dat\n");
    fflush(stdout);
    return;
  }
  printf("[?] Loaded global-metadata.dat (%zu bytes)\n", metadata.size());
  fflush(stdout);

  if (rd32(metadata.data()) == 0xFAB11BAFu) {
    printf("[+] Metadata already decrypted - skipping\n");
    fflush(stdout);
    return;
  }

  uint32_t subKey =
      (mix((uint32_t)(fileTime & 0xFFFFFFFF)) % 0xA) + 5;
  printf("[+] File time: 0x%016llX  subKey: %u\n", (unsigned long long)fileTime,
         subKey);
  fflush(stdout);

  const int HEADER_SIZE = 0x200;
  if (!header(metadata, HEADER_SIZE))
    return;

  auto vi = version(metadata, subKey);
  if (!vi) {
    printf("[-] Invalid encrypted metadata header\n");
    fflush(stdout);
    return;
  }
  printf("[+] Version:     %s\n", vi->version.c_str());
  printf("[+] Request key: %s\n", vi->requestKey.c_str());
  printf("[+] Raw key:     0x%08X\n", vi->key);
  fflush(stdout);

  restore(metadata);

  auto props = fetch(subKey, vi->version, vi->requestKey, session, userAgent);
  if (props.empty()) {
    printf("[-] Failed to obtain header properties from server\n");
    fflush(stdout);
    return;
  }
  printf("[+] Server returned %zu sections\n", props.size());
  fflush(stdout);

  decrypt_body(metadata, props, HEADER_SIZE);

  if (!reinsert(metadata, props, vi->key)) {
    printf("[-] Invalid metadata sections\n");
    fflush(stdout);
    return;
  }

  if (!reorder(metadata, vi->key)) {
    printf("[-] Invalid type definitions\n");
    fflush(stdout);
    return;
  }

  std::wstring outPath = outputDir;
  if (!outPath.empty() && outPath.back() != L'\\')
    outPath += L'\\';
  outPath += L"global-metadata.dat";

  char outPathA[MAX_PATH * 2] = {};
  WideCharToMultiByte(CP_ACP, 0, outPath.c_str(), -1, outPathA,
                      sizeof(outPathA), nullptr, nullptr);
  printf("[?] Writing global-metadata.dat to %s...\n", outPathA);
  fflush(stdout);

  HANDLE hOut = CreateFileW(outPath.c_str(), GENERIC_WRITE, 0, nullptr,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (hOut == INVALID_HANDLE_VALUE) {
    printf("[-] Cannot create output file (err=%lu)\n", GetLastError());
    fflush(stdout);
    return;
  }
  DWORD written = 0;
  BOOL wrote = WriteFile(hOut, metadata.data(), (DWORD)metadata.size(), &written,
                         nullptr);
  BOOL flushed = FlushFileBuffers(hOut);
  CloseHandle(hOut);

  if (!wrote || !flushed || written != metadata.size()) {
    DeleteFileW(outPath.c_str());
    printf("[-] Failed to write output file\n");
    fflush(stdout);
    return;
  }

  printf("[+] Done. (%zu bytes written)\n", (size_t)written);
  fflush(stdout);
}
}
