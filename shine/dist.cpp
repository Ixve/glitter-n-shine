#include "dist.h"
#include "decode.h"

#include <windows.h>
#include <winhttp.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>

#pragma comment(lib, "winhttp.lib")

namespace {

constexpr const wchar_t *LAUNCHER_HOST = L"launcher.escapefromtarkov.com";
constexpr const wchar_t *DEFAULT_LAUNCHER_VER = L"15.0.0.4574";

struct Mirror {
  const wchar_t *host;
  INTERNET_PORT port;
  bool secure;
};

const Mirror MIRRORS[] = {
    {L"cdn-11.eft-store.com", INTERNET_DEFAULT_HTTP_PORT, false},
    {L"cdn-14.eft-store.com", INTERNET_DEFAULT_HTTPS_PORT, true},
    {L"node06-101.eft-store.com", INTERNET_DEFAULT_HTTPS_PORT, true},
    {L"node06-102.eft-store.com", INTERNET_DEFAULT_HTTPS_PORT, true},
    {L"node06-103.eft-store.com", INTERNET_DEFAULT_HTTPS_PORT, true},
    {L"node06-104.eft-store.com", INTERNET_DEFAULT_HTTPS_PORT, true},
    {L"node06-105.eft-store.com", INTERNET_DEFAULT_HTTPS_PORT, true},
};

std::wstring widen(const std::string &s) {
  return std::wstring(s.begin(), s.end());
}

bool http_get(const wchar_t *host, INTERNET_PORT port, bool secure,
              const std::wstring &path, const dist::Auth &auth,
              std::vector<uint8_t> &body, uint64_t *lastModified) {
  body.clear();
  const wchar_t *ua =
      auth.userAgent.empty() ? L"BsgLauncher" : auth.userAgent.c_str();

  HINTERNET hs = WinHttpOpen(ua, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                             WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
  if (!hs)
    return false;

  HINTERNET hc = WinHttpConnect(hs, host, port, 0);
  HINTERNET hr = hc ? WinHttpOpenRequest(hc, L"GET", path.c_str(), nullptr,
                                         WINHTTP_NO_REFERER,
                                         WINHTTP_DEFAULT_ACCEPT_TYPES,
                                         secure ? WINHTTP_FLAG_SECURE : 0)
                    : nullptr;
  if (!hr) {
    if (hc)
      WinHttpCloseHandle(hc);
    WinHttpCloseHandle(hs);
    return false;
  }

  std::wstring headers;
  if (!auth.bearer.empty()) {
    headers += L"Authorization: Bearer ";
    headers += widen(auth.bearer);
    headers += L"\r\n";
  }
  if (!auth.phpsessid.empty()) {
    headers += L"Cookie: PHPSESSID=";
    headers += widen(auth.phpsessid);
    headers += L"\r\n";
  }
  if (!headers.empty())
    WinHttpAddRequestHeaders(hr, headers.c_str(), (DWORD)-1,
                             WINHTTP_ADDREQ_FLAG_ADD |
                                 WINHTTP_ADDREQ_FLAG_REPLACE);

  bool ok = WinHttpSendRequest(hr, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                               WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
            WinHttpReceiveResponse(hr, nullptr);

  DWORD status = 0, statusLen = sizeof(status);
  if (ok)
    WinHttpQueryHeaders(hr,
                        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &status, &statusLen,
                        WINHTTP_NO_HEADER_INDEX);

  if (ok && lastModified) {
    SYSTEMTIME st = {};
    DWORD stLen = sizeof(st);
    if (WinHttpQueryHeaders(
            hr, WINHTTP_QUERY_LAST_MODIFIED | WINHTTP_QUERY_FLAG_SYSTEMTIME,
            WINHTTP_HEADER_NAME_BY_INDEX, &st, &stLen,
            WINHTTP_NO_HEADER_INDEX)) {
      FILETIME ft = {};
      if (SystemTimeToFileTime(&st, &ft))
        *lastModified =
            ((uint64_t)ft.dwHighDateTime << 32) | (uint64_t)ft.dwLowDateTime;
    }
  }

  bool good = ok && status >= 200 && status < 300;
  if (good) {
    DWORD avail = 0;
    while (WinHttpQueryDataAvailable(hr, &avail) && avail > 0) {
      size_t off = body.size();
      if (avail > 256u * 1024 * 1024 - off) {
        good = false;
        break;
      }
      body.resize(off + avail);
      DWORD read = 0;
      if (!WinHttpReadData(hr, body.data() + off, avail, &read)) {
        good = false;
        break;
      }
      body.resize(off + read);
    }
  }

  WinHttpCloseHandle(hr);
  WinHttpCloseHandle(hc);
  WinHttpCloseHandle(hs);
  return good;
}

std::string jstr(const std::string &json, const char *name, size_t from = 0) {
  std::string key = std::string("\"") + name + "\"";
  size_t pos = json.find(key, from);
  if (pos == std::string::npos)
    return {};
  pos += key.size();
  while (pos < json.size() && (unsigned char)json[pos] <= ' ')
    ++pos;
  if (pos >= json.size() || json[pos++] != ':')
    return {};
  while (pos < json.size() && (unsigned char)json[pos] <= ' ')
    ++pos;
  if (pos >= json.size() || json[pos++] != '"')
    return {};
  std::string out;
  for (size_t i = pos; i < json.size(); ++i) {
    char c = json[i];
    if (c == '\\' && i + 1 < json.size()) {
      char n = json[++i];
      out += (n == '/') ? '/' : n;
      continue;
    }
    if (c == '"')
      break;
    out += c;
  }
  return out;
}

int cmpver(const std::string &a, const std::string &b) {
  size_t ia = 0, ib = 0;
  while (ia < a.size() || ib < b.size()) {
    unsigned long va = strtoul(a.c_str() + ia, nullptr, 10);
    unsigned long vb = strtoul(b.c_str() + ib, nullptr, 10);
    if (va != vb)
      return va < vb ? -1 : 1;
    size_t na = a.find('.', ia);
    size_t nb = b.find('.', ib);
    ia = (na == std::string::npos) ? a.size() : na + 1;
    ib = (nb == std::string::npos) ? b.size() : nb + 1;
  }
  return 0;
}

std::wstring launcher_ver(const dist::Auth &auth) {
  return auth.launcherVer.empty() ? std::wstring(DEFAULT_LAUNCHER_VER)
                                  : widen(auth.launcherVer);
}

std::string get_json(const std::wstring &path, const dist::Auth &auth) {
  std::vector<uint8_t> raw;
  if (!http_get(LAUNCHER_HOST, INTERNET_DEFAULT_HTTPS_PORT, true, path, auth,
                raw, nullptr))
    return {};
  std::vector<uint8_t> dec = decode::run(raw);
  const std::vector<uint8_t> &j = dec.empty() ? raw : dec;
  return std::string(j.begin(), j.end());
}

} // namespace

namespace dist {

std::string latest_version(const Auth &auth) {
  std::wstring path =
      L"/launcher/game-updates/eft?branch=live&launcherVersion=" +
      launcher_ver(auth) + L"&provider=bsg";
  std::string json = get_json(path, auth);
  if (json.empty())
    return {};

  std::string best;
  size_t from = 0;
  for (;;) {
    size_t at = json.find("\"version\"", from);
    if (at == std::string::npos)
      break;
    std::string v = jstr(json, "version", at);
    from = at + 9;
    if (v.empty())
      continue;
    if (best.empty() || cmpver(v, best) > 0)
      best = v;
  }
  return best;
}

std::string installation_uri(const Auth &auth, const std::string &version) {
  std::wstring path =
      L"/launcher/game-installation/eft?branch=live&version=" + widen(version) +
      L"&launcherVersion=" + launcher_ver(auth) + L"&provider=bsg";
  std::string json = get_json(path, auth);
  if (json.empty())
    return {};
  return jstr(json, "unpackedUri");
}

bool download(const std::string &unpackedUri, const char *rel, Metadata &out) {
  if (unpackedUri.empty())
    return false;
  std::wstring path = widen(unpackedUri + rel);
  dist::Auth none;

  for (const Mirror &m : MIRRORS) {
    if (http_get(m.host, m.port, m.secure, path, none, out.bytes,
                 &out.fileTime) &&
        out.bytes.size() > 0)
      return true;
    printf("[?] Mirror %ls unavailable, trying next...\n", m.host);
    fflush(stdout);
  }
  return false;
}

} // namespace dist
