

#include "decode.h"
#include "meta.h"

#define SECURITY_WIN32
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <security.h>
#include <sspi.h>
#include <string>
#include <vector>
#include <winhttp.h>

#include "../deps/detours/detours.h"

static constexpr const char *route = "launcher/game/start";

thread_local bool replaying = false;

static const void *scan(const void *hay, size_t hlen, const void *needle,
                            size_t nlen) {
  if (!hay || !needle || nlen == 0 || hlen < nlen)
    return nullptr;
  const auto *h = static_cast<const unsigned char *>(hay);
  const auto *n = static_cast<const unsigned char *>(needle);
  for (size_t i = 0; i <= hlen - nlen; ++i)
    if (memcmp(h + i, n, nlen) == 0)
      return h + i;
  return nullptr;
}

static std::string header(const std::string &hdrs,
                                     const char *name) {
  std::string key(name);
  for (auto &c : key)
    c = (char)tolower((unsigned char)c);

  size_t pos = 0;
  while (pos < hdrs.size()) {
    size_t end = hdrs.find("\r\n", pos);
    if (end == std::string::npos)
      break;
    std::string line = hdrs.substr(pos, end - pos);
    pos = end + 2;
    if (line.empty())
      break;

    size_t colon = line.find(':');
    if (colon == std::string::npos)
      continue;

    std::string k = line.substr(0, colon);
    for (auto &c : k)
      c = (char)tolower((unsigned char)c);
    if (k == key) {
      size_t v = colon + 1;
      while (v < line.size() && line[v] == ' ')
        ++v;
      return line.substr(v);
    }
  }
  return {};
}

static void request(const std::string &hdrs, std::string &method,
                               std::string &path) {
  size_t eol = hdrs.find("\r\n");
  std::string line = (eol != std::string::npos) ? hdrs.substr(0, eol) : hdrs;
  size_t s1 = line.find(' ');
  size_t s2 =
      (s1 != std::string::npos) ? line.find(' ', s1 + 1) : std::string::npos;
  if (s1 == std::string::npos)
    return;
  method = line.substr(0, s1);
  path = (s2 != std::string::npos) ? line.substr(s1 + 1, s2 - s1 - 1)
                                   : line.substr(s1 + 1);
}

static std::wstring extra(const std::string &hdrs) {
  std::wstring result;
  size_t pos = 0;

  size_t end = hdrs.find("\r\n");
  if (end == std::string::npos)
    return result;
  pos = end + 2;

  while (pos < hdrs.size()) {
    end = hdrs.find("\r\n", pos);
    if (end == std::string::npos)
      break;
    std::string line = hdrs.substr(pos, end - pos);
    pos = end + 2;
    if (line.empty())
      break;

    auto startsWith = [&](const char *prefix) {
      return _strnicmp(line.c_str(), prefix, strlen(prefix)) == 0;
    };
    if (startsWith("Host:"))
      continue;
    if (startsWith("Content-Length:"))
      continue;
    if (startsWith("Accept-Encoding:"))
      continue;

    result.append(line.begin(), line.end());
    result += L"\r\n";
  }
  return result;
}

struct Replay {
  std::string headers;
  std::string body;
};

static DWORD WINAPI replay(LPVOID param) {
  replaying = true;

  auto *p = static_cast<Replay *>(param);
  std::string hdrs = std::move(p->headers);
  std::string body = std::move(p->body);
  delete p;

  std::string method, path, host;
  request(hdrs, method, path);
  host = header(hdrs, "Host");
  std::wstring extraHeaders = extra(hdrs);

  if (host.empty() || path.empty()) {
    printf("[-] Failed to parse host/path from captured headers\n");
    fflush(stdout);
    return 1;
  }

  std::wstring whost(host.begin(), host.end());
  std::wstring wpath(path.begin(), path.end());
  std::wstring wmethod(method.begin(), method.end());

  printf("[?] Replaying...\n");
  fflush(stdout);

  std::string ua = header(hdrs, "User-Agent");
  std::wstring wua(ua.begin(), ua.end());
  if (wua.empty())
    wua = L"BSG Launcher";

  HINTERNET hSession =
      WinHttpOpen(wua.c_str(), WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                  WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);

  if (!hSession) {
    printf("[-] WinHttpOpen failed\n");
    fflush(stdout);
    return 1;
  }

  HINTERNET hConnect =
      WinHttpConnect(hSession, whost.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0);

  HINTERNET hRequest =
      hConnect ? WinHttpOpenRequest(hConnect, wmethod.c_str(), wpath.c_str(),
                                    nullptr, WINHTTP_NO_REFERER,
                                    WINHTTP_DEFAULT_ACCEPT_TYPES,
                                    WINHTTP_FLAG_SECURE)
               : nullptr;

  if (!hRequest) {
    if (hConnect)
      WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    printf("[-] WinHttpOpenRequest failed\n");
    fflush(stdout);
    return 1;
  }

  if (!extraHeaders.empty())
    WinHttpAddRequestHeaders(hRequest, extraHeaders.c_str(), (DWORD)-1,
                             WINHTTP_ADDREQ_FLAG_ADD |
                                 WINHTTP_ADDREQ_FLAG_REPLACE);

  BOOL sent = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                 body.empty() ? nullptr : (LPVOID)body.data(),
                                 (DWORD)body.size(), (DWORD)body.size(), 0);

  std::vector<char> responseBody;

  if (sent && WinHttpReceiveResponse(hRequest, nullptr)) {
    DWORD status = 0, statusLen = sizeof(status);
    WinHttpQueryHeaders(hRequest,
                        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &status, &statusLen,
                        WINHTTP_NO_HEADER_INDEX);
    printf("[+] Received response - %lu\n", status);
    fflush(stdout);

    DWORD avail = 0;
    while (WinHttpQueryDataAvailable(hRequest, &avail) && avail > 0) {
      size_t offset = responseBody.size();
      responseBody.resize(offset + avail);
      DWORD read = 0;
      if (!WinHttpReadData(hRequest, responseBody.data() + offset, avail,
                           &read))
        break;
      responseBody.resize(offset + read);
    }
  } else {
  }

  WinHttpCloseHandle(hRequest);
  WinHttpCloseHandle(hConnect);
  WinHttpCloseHandle(hSession);

  if (!responseBody.empty()) {
    printf("[?] Decrypting...\n");
    fflush(stdout);
    std::vector<uint8_t> raw(responseBody.begin(), responseBody.end());
    std::vector<uint8_t> decoded = decode::run(raw);

    const std::vector<uint8_t> &jsonData = decoded.empty() ? raw : decoded;

    wchar_t outDir[MAX_PATH * 2] = {};
    if (GetEnvironmentVariableW(L"SHINE_OUT", outDir, MAX_PATH * 2) == 0)
      GetTempPathW(MAX_PATH * 2, outDir);

    meta::run(jsonData, outDir, wua.c_str());
  }
  fflush(stdout);

  return 0;
}

static void start(std::string headers, std::string body) {
  auto *p = new Replay{std::move(headers), std::move(body)};
  HANDLE thread = CreateThread(nullptr, 0, replay, p, 0, nullptr);
  if (thread)
    CloseHandle(thread);
  else {
    delete p;
    printf("[-] Replay thread failed (err=%lu)\n", GetLastError());
    fflush(stdout);
  }
}

static CRITICAL_SECTION g_cs;

enum class Phase { IDLE, WAIT_BODY, DONE };
static Phase phase = Phase::IDLE;
static ULONG_PTR ctxLower = 0;
static ULONG_PTR ctxUpper = 0;
static std::string headers;

static bool same(PCtxtHandle p) {
  return p && p->dwLower == ctxLower && p->dwUpper == ctxUpper;
}

using EncryptFn = SECURITY_STATUS(SEC_ENTRY *)(PCtxtHandle, ULONG,
                                                      PSecBufferDesc, ULONG);

static EncryptFn encrypt = nullptr;

static SECURITY_STATUS SEC_ENTRY hook(PCtxtHandle phContext,
                                                  ULONG fQOP,
                                                  PSecBufferDesc pMessage,
                                                  ULONG MessageSeqNo) {

  if (replaying)
    return encrypt(phContext, fQOP, pMessage, MessageSeqNo);

  for (ULONG i = 0; i < pMessage->cBuffers; ++i) {
    SecBuffer *sb = &pMessage->pBuffers[i];
    if (sb->BufferType != SECBUFFER_DATA || sb->cbBuffer == 0 || !sb->pvBuffer)
      continue;

    const char *data = static_cast<const char *>(sb->pvBuffer);
    DWORD len = sb->cbBuffer;

    EnterCriticalSection(&g_cs);

    if (phase == Phase::IDLE) {
      if (scan(data, len, route, strlen(route))) {

        const char *eol =
            static_cast<const char *>(scan(data, len, "\r\n", 2));
        std::string firstLine(data, eol ? eol : data + len);
        size_t s1 = firstLine.find(' '), s2 = s1 != std::string::npos
                                                  ? firstLine.find(' ', s1 + 1)
                                                  : std::string::npos;
        std::string endpoint =
            (s1 != std::string::npos && s2 != std::string::npos)
                ? firstLine.substr(s1 + 1, s2 - s1 - 1)
                : route;
        printf("[+] Detected launch: %s\n", endpoint.c_str());
        fflush(stdout);

        headers.assign(data, len);

        const char *sep =
            static_cast<const char *>(scan(data, len, "\r\n\r\n", 4));

        if (sep && (sep + 4) < (data + len)) {

          const char *bodyPtr = sep + 4;
          DWORD bodyLen = (DWORD)(len - (DWORD)(bodyPtr - data));
          std::string body(bodyPtr, bodyLen);
          std::string captured = std::move(headers);
          phase = Phase::DONE;
          LeaveCriticalSection(&g_cs);

          printf("[+] Request blocked\n");
          fflush(stdout);
          start(std::move(captured), std::move(body));
          return SEC_E_ENCRYPT_FAILURE;
        } else {

          ctxLower = phContext ? phContext->dwLower : 0;
          ctxUpper = phContext ? phContext->dwUpper : 0;
          phase = Phase::WAIT_BODY;
          LeaveCriticalSection(&g_cs);

          return encrypt(phContext, fQOP, pMessage, MessageSeqNo);
        }
      }
    }

    else if (phase == Phase::WAIT_BODY && same(phContext)) {
      std::string body(data, len);
      std::string captured = std::move(headers);
      phase = Phase::DONE;
      LeaveCriticalSection(&g_cs);

      printf("[+] Request blocked\n");
      fflush(stdout);
      start(std::move(captured), std::move(body));
      return SEC_E_ENCRYPT_FAILURE;
    }

    LeaveCriticalSection(&g_cs);
  }

  return encrypt(phContext, fQOP, pMessage, MessageSeqNo);
}

static FARPROC resolve(const char *dll, const char *fn) {
  HMODULE h = GetModuleHandleA(dll);
  if (!h)
    h = LoadLibraryA(dll);
  return h ? GetProcAddress(h, fn) : nullptr;
}

static bool install() {
  InitializeCriticalSection(&g_cs);

  encrypt = reinterpret_cast<EncryptFn>(
      resolve("secur32.dll", "EncryptMessage"));
  if (!encrypt)
    encrypt = reinterpret_cast<EncryptFn>(
        resolve("sspicli.dll", "EncryptMessage"));
  if (!encrypt) {
    DeleteCriticalSection(&g_cs);
    return false;
  }

  void *address = reinterpret_cast<void *>(encrypt);
  if (DetourTransactionBegin() != NO_ERROR) {
    DeleteCriticalSection(&g_cs);
    return false;
  }
  if (DetourUpdateThread(GetCurrentThread()) != NO_ERROR ||
      DetourAttach(reinterpret_cast<PVOID *>(&encrypt),
                   hook) != NO_ERROR) {
    DetourTransactionAbort();
    DeleteCriticalSection(&g_cs);
    return false;
  }
  if (DetourTransactionCommit() != NO_ERROR) {
    DeleteCriticalSection(&g_cs);
    return false;
  }
  printf("=> Hooked EncryptMessage @ %p\n", address);
  fflush(stdout);
  return true;
}

static DWORD WINAPI init(void *) {
  AllocConsole();
  SetConsoleTitleA("shine");
  FILE *out = nullptr;
  freopen_s(&out, "conout$", "w", stdout);
  printf("[?] Loaded - hooking...\n");
  fflush(stdout);
  if (!install()) {
    printf("[-] Hook setup failed\n");
    fflush(stdout);
  }
  return 0;
}

BOOL APIENTRY DllMain(HMODULE mod, DWORD reason, LPVOID) {
  if (reason == DLL_PROCESS_ATTACH) {
    DisableThreadLibraryCalls(mod);
    HANDLE thread = CreateThread(nullptr, 0, init, nullptr, 0, nullptr);
    if (thread)
      CloseHandle(thread);
    else
      return FALSE;
  }
  return TRUE;
}
