#include "dist.h"
#include "meta.h"
#include "self.h"
#include "session.h"

#define SECURITY_WIN32
#include <windows.h>
#include <security.h>
#include <sspi.h>

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <string>
#include <vector>

#include "../deps/detours/detours.h"

HMODULE g_self = nullptr;

static dist::Auth g_auth;
static volatile LONG g_captured = 0;
static HANDLE g_authEvent = nullptr;

static std::string extract(const char *data, size_t len, const char *prefix,
                           const char *stops) {
  size_t plen = strlen(prefix);
  if (len < plen)
    return {};
  for (size_t i = 0; i + plen <= len; ++i) {
    if (memcmp(data + i, prefix, plen) == 0) {
      size_t s = i + plen;
      size_t e = s;
      while (e < len && !strchr(stops, data[e]))
        ++e;
      return std::string(data + s, e - s);
    }
  }
  return {};
}

static void try_capture(const char *data, size_t len) {
  if (g_captured)
    return;
  static const char *bearer = "Authorization: Bearer ";
  size_t blen = strlen(bearer);
  bool found = false;
  for (size_t i = 0; i + blen <= len; ++i)
    if (memcmp(data + i, bearer, blen) == 0) {
      found = true;
      break;
    }
  if (!found)
    return;

  if (InterlockedCompareExchange(&g_captured, 1, 0) != 0)
    return;

  g_auth.bearer = extract(data, len, "Authorization: Bearer ", "\r\n ");
  g_auth.phpsessid = extract(data, len, "Cookie: PHPSESSID=", "\r\n; ");
  std::string ua = extract(data, len, "User-Agent: ", "\r\n");
  g_auth.userAgent = std::wstring(ua.begin(), ua.end());
  g_auth.launcherVer = extract(data, len, "launcherVersion=", "\r\n& ");
  if (g_auth.launcherVer.empty()) {
    size_t slash = ua.find('/');
    if (slash != std::string::npos)
      g_auth.launcherVer = ua.substr(slash + 1);
  }

  printf("[+] Captured launcher auth (ver=%s, session=%s)\n",
         g_auth.launcherVer.c_str(), g_auth.phpsessid.empty() ? "no" : "yes");
  fflush(stdout);
  SetEvent(g_authEvent);
}

using EncryptFn = SECURITY_STATUS(SEC_ENTRY *)(PCtxtHandle, ULONG,
                                               PSecBufferDesc, ULONG);
static EncryptFn encrypt = nullptr;

static SECURITY_STATUS SEC_ENTRY hook(PCtxtHandle phContext, ULONG fQOP,
                                      PSecBufferDesc pMessage,
                                      ULONG MessageSeqNo) {
  if (!g_captured && pMessage) {
    for (ULONG i = 0; i < pMessage->cBuffers; ++i) {
      SecBuffer *sb = &pMessage->pBuffers[i];
      if (sb->BufferType == SECBUFFER_DATA && sb->cbBuffer && sb->pvBuffer)
        try_capture(static_cast<const char *>(sb->pvBuffer), sb->cbBuffer);
    }
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
  encrypt = reinterpret_cast<EncryptFn>(resolve("secur32.dll", "EncryptMessage"));
  if (!encrypt)
    encrypt = reinterpret_cast<EncryptFn>(resolve("sspicli.dll", "EncryptMessage"));
  if (!encrypt)
    return false;

  if (DetourTransactionBegin() != NO_ERROR)
    return false;
  if (DetourUpdateThread(GetCurrentThread()) != NO_ERROR ||
      DetourAttach(reinterpret_cast<PVOID *>(&encrypt), hook) != NO_ERROR) {
    DetourTransactionAbort();
    return false;
  }
  return DetourTransactionCommit() == NO_ERROR;
}

static BOOL CALLBACK hide_proc(HWND wnd, LPARAM) {
  if (wnd == GetConsoleWindow())
    return TRUE;
  DWORD pid = 0;
  GetWindowThreadProcessId(wnd, &pid);
  if (pid == GetCurrentProcessId() && IsWindowVisible(wnd))
    ShowWindow(wnd, SW_HIDE);
  return TRUE;
}

static DWORD WINAPI hider(void *) {
  for (int i = 0; i < 80; ++i) {
    EnumWindows(hide_proc, 0);
    Sleep(250);
  }
  return 0;
}

static std::wstring output_dir() {
  wchar_t tmp[MAX_PATH] = {};
  GetTempPathW(MAX_PATH, tmp);
  std::wstring f = std::wstring(tmp) + L"gns_out.txt";
  HANDLE h = CreateFileW(f.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                         OPEN_EXISTING, 0, nullptr);
  if (h != INVALID_HANDLE_VALUE) {
    LARGE_INTEGER sz = {};
    if (GetFileSizeEx(h, &sz) && sz.QuadPart >= (LONGLONG)sizeof(wchar_t) &&
        sz.QuadPart < 0x8000) {
      std::wstring s((size_t)(sz.QuadPart / sizeof(wchar_t)), L'\0');
      DWORD r = 0;
      BOOL ok = ReadFile(h, &s[0], (DWORD)(s.size() * sizeof(wchar_t)), &r,
                         nullptr);
      CloseHandle(h);
      if (ok) {
        s.resize(wcsnlen_s(s.c_str(), s.size()));
        if (!s.empty())
          return s;
      }
    } else {
      CloseHandle(h);
    }
  }

  wchar_t buf[MAX_PATH * 2] = {};
  if (GetEnvironmentVariableW(L"SHINE_OUT", buf, MAX_PATH * 2) > 0)
    return buf;
  if (GetEnvironmentVariableW(L"USERPROFILE", buf, MAX_PATH * 2) > 0)
    return std::wstring(buf) + L"\\Desktop";
  GetTempPathW(MAX_PATH * 2, buf);
  return buf;
}

static bool write_file(const std::wstring &path,
                       const std::vector<uint8_t> &data) {
  HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                         FILE_ATTRIBUTE_NORMAL, nullptr);
  if (h == INVALID_HANDLE_VALUE)
    return false;
  DWORD w = 0;
  BOOL ok = WriteFile(h, data.data(), (DWORD)data.size(), &w, nullptr) &&
            w == data.size();
  FlushFileBuffers(h);
  CloseHandle(h);
  return ok;
}

struct CiEntry {
  long long size;
  int checksum;
  bool found;
};

static CiEntry ci_lookup(const std::string &json, const char *key) {
  size_t p = json.find(key);
  if (p == std::string::npos)
    return {0, 0, false};
  p += strlen(key);
  long long size = _atoi64(json.c_str() + p);
  size_t c = json.find("\"Checksum\":", p);
  int checksum = (c == std::string::npos)
                     ? 0
                     : (int)strtol(json.c_str() + c + 11, nullptr, 10);
  return {size, checksum, true};
}

static bool byte_sum_file(const std::wstring &path, int &out) {
  HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                         OPEN_EXISTING, 0, nullptr);
  if (h == INVALID_HANDLE_VALUE)
    return false;
  std::vector<uint8_t> buf(1 << 20);
  uint32_t s = 0;
  DWORD r = 0;
  for (;;) {
    if (!ReadFile(h, buf.data(), (DWORD)buf.size(), &r, nullptr)) {
      CloseHandle(h);
      return false;
    }
    if (r == 0)
      break;
    for (DWORD i = 0; i < r; ++i)
      s += buf[i];
  }
  CloseHandle(h);
  out = (int)s;
  return true;
}

static void write_text(const std::wstring &path, const std::string &s) {
  HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                         FILE_ATTRIBUTE_NORMAL, nullptr);
  if (h == INVALID_HANDLE_VALUE)
    return;
  DWORD w = 0;
  WriteFile(h, s.data(), (DWORD)s.size(), &w, nullptr);
  CloseHandle(h);
}

static std::string read_text(const std::wstring &path) {
  HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                         OPEN_EXISTING, 0, nullptr);
  if (h == INVALID_HANDLE_VALUE)
    return {};
  char buf[64] = {};
  DWORD r = 0;
  ReadFile(h, buf, sizeof(buf) - 1, &r, nullptr);
  CloseHandle(h);
  return std::string(buf, r);
}

static bool is_decrypted(const std::wstring &path) {
  HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                         OPEN_EXISTING, 0, nullptr);
  if (h == INVALID_HANDLE_VALUE)
    return false;
  uint8_t hdr[4] = {};
  DWORD r = 0;
  BOOL ok = ReadFile(h, hdr, 4, &r, nullptr) && r == 4;
  CloseHandle(h);
  if (!ok)
    return false;
  uint32_t magic = (uint32_t)hdr[0] | ((uint32_t)hdr[1] << 8) |
                   ((uint32_t)hdr[2] << 16) | ((uint32_t)hdr[3] << 24);
  return magic == 0xFAB11BAFu;
}

static long long file_size(const std::wstring &path) {
  WIN32_FILE_ATTRIBUTE_DATA fad = {};
  if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &fad))
    return -1;
  if (fad.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
    return -1;
  return ((long long)fad.nFileSizeHigh << 32) | fad.nFileSizeLow;
}

static bool read_file(const std::wstring &path, std::vector<uint8_t> &out) {
  HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                         OPEN_EXISTING, 0, nullptr);
  if (h == INVALID_HANDLE_VALUE)
    return false;
  LARGE_INTEGER sz = {};
  if (!GetFileSizeEx(h, &sz) || sz.QuadPart < 0 ||
      sz.QuadPart > 0x30000000) {
    CloseHandle(h);
    return false;
  }
  out.resize((size_t)sz.QuadPart);
  DWORD rd = 0;
  BOOL ok = out.empty() ||
            (ReadFile(h, out.data(), (DWORD)sz.QuadPart, &rd, nullptr) &&
             rd == sz.QuadPart);
  CloseHandle(h);
  return ok;
}

static std::wstring find_eft_install() {
  constexpr const wchar_t *base =
      L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall";
  const HKEY roots[] = {HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER};
  const REGSAM views[] = {KEY_WOW64_32KEY, KEY_WOW64_64KEY};
  for (HKEY root : roots) {
    for (REGSAM view : views) {
      HKEY list = nullptr;
      if (RegOpenKeyExW(root, base, 0, KEY_READ | view, &list) != ERROR_SUCCESS)
        continue;
      wchar_t name[256];
      for (DWORD i = 0;; ++i) {
        DWORD len = (DWORD)(sizeof(name) / sizeof(name[0]));
        if (RegEnumKeyExW(list, i, name, &len, nullptr, nullptr, nullptr,
                          nullptr) != ERROR_SUCCESS)
          break;
        HKEY key = nullptr;
        if (RegOpenKeyExW(list, name, 0, KEY_READ, &key) != ERROR_SUCCESS)
          continue;
        wchar_t title[512] = {};
        DWORD ts = sizeof(title);
        RegQueryValueExW(key, L"DisplayName", nullptr, nullptr, (BYTE *)title,
                         &ts);
        if (wcsstr(title, L"Escape from Tarkov")) {
          DWORD type = 0, size = 0;
          if (RegQueryValueExW(key, L"InstallLocation", nullptr, &type, nullptr,
                               &size) == ERROR_SUCCESS &&
              (type == REG_SZ || type == REG_EXPAND_SZ) &&
              size >= sizeof(wchar_t)) {
            std::wstring dir(size / sizeof(wchar_t), L'\0');
            if (RegQueryValueExW(key, L"InstallLocation", nullptr, &type,
                                 (BYTE *)dir.data(), &size) == ERROR_SUCCESS) {
              dir.resize(wcsnlen_s(dir.c_str(), dir.size()));
              RegCloseKey(key);
              RegCloseKey(list);
              return dir;
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

static DWORD WINAPI worker(void *) {
  if (WaitForSingleObject(g_authEvent, 120000) != WAIT_OBJECT_0) {
    printf("[-] Timed out capturing launcher auth\n");
    fflush(stdout);
    return 1;
  }
  dist::Auth auth = g_auth;

  std::string version;
  {
    char v[64] = {};
    if (GetEnvironmentVariableA("GLITTER_VERSION", v, sizeof(v)) > 0)
      version = v;
  }
  if (version.empty()) {
    printf("[?] Resolving version...\n");
    fflush(stdout);
    for (int i = 0; i < 30 && version.empty(); ++i) {
      version = dist::latest_version(auth);
      if (version.empty())
        Sleep(2000);
    }
  }
  if (version.empty()) {
    printf("[-] Could not determine target version\n");
    fflush(stdout);
    return 1;
  }
  printf("[+] Version: %s\n", version.c_str());
  fflush(stdout);

  printf("[?] Resolving distribution...\n");
  fflush(stdout);
  std::string uri;
  for (int i = 0; i < 15 && uri.empty(); ++i) {
    uri = dist::installation_uri(auth, version);
    if (uri.empty())
      Sleep(2000);
  }
  if (uri.empty()) {
    printf("[-] Could not resolve distribution path\n");
    fflush(stdout);
    return 1;
  }

  std::wstring base = output_dir();
  std::wstring installDir = find_eft_install();
  const wchar_t *ua =
      g_auth.userAgent.empty() ? L"BsgLauncher" : g_auth.userAgent.c_str();

  printf("[?] Fetching consistency manifest...\n");
  fflush(stdout);
  std::string ciJson;
  {
    dist::Metadata ci;
    if (dist::download(uri, "/ConsistencyInfo", ci))
      ciJson.assign(ci.bytes.begin(), ci.bytes.end());
  }
  if (ciJson.empty()) {
    printf("[-] Could not fetch consistency manifest\n");
    fflush(stdout);
    return 1;
  }

  const struct {
    const char *cdnRel;
    const wchar_t *destRel;
    const char *ciKey;
    bool meta;
  } items[] = {
      {"/EscapeFromTarkov_Data/il2cpp_data/Metadata/global-metadata.dat",
       L"EscapeFromTarkov_Data\\il2cpp_data\\Metadata\\global-metadata.dat",
       "global-metadata.dat\",\"Size\":", true},
      {"/GameAssembly.dll", L"GameAssembly.dll",
       "GameAssembly.dll\",\"Size\":", false},
      {"/UnityPlayer.dll", L"UnityPlayer.dll", "UnityPlayer.dll\",\"Size\":",
       false},
      {"/EscapeFromTarkov.exe", L"EscapeFromTarkov.exe",
       "EscapeFromTarkov.exe\",\"Size\":", false},
      {"/EscapeFromTarkov_Data/globalgamemanagers",
       L"EscapeFromTarkov_Data\\globalgamemanagers",
       "globalgamemanagers\",\"Size\":", false},
  };

  std::string gameSession;
  bool haveSession = false;

  for (const auto &it : items) {
    std::wstring dst = base + L"\\" + it.destRel;
    std::wstring installPath =
        installDir.empty() ? std::wstring() : installDir + L"\\" + it.destRel;
    std::wstring sidecar = dst + L".ci";
    CiEntry e = ci_lookup(ciJson, it.ciKey);
    std::error_code ec;

    bool current = false;
    if (e.found) {
      if (it.meta) {
        current = file_size(dst) >= 0 && is_decrypted(dst) &&
                  read_text(sidecar) == std::to_string(e.checksum);
      } else {
        int sum = 0;
        current = file_size(dst) == e.size && byte_sum_file(dst, sum) &&
                  sum == e.checksum;
      }
    }
    if (current) {
      printf("[=] Up to date: %ls\n", it.destRel);
      fflush(stdout);
      continue;
    }

    std::filesystem::create_directories(
        std::filesystem::path(dst).parent_path(), ec);

    bool installOk = false;
    if (!installPath.empty() && e.found && file_size(installPath) == e.size) {
      int sum = 0;
      installOk = byte_sum_file(installPath, sum) && sum == e.checksum;
    }

    if (it.meta) {
      std::vector<uint8_t> enc;
      uint64_t fileTime = 0;
      if (installOk && read_file(installPath, enc)) {
        WIN32_FILE_ATTRIBUTE_DATA fad = {};
        if (GetFileAttributesExW(installPath.c_str(), GetFileExInfoStandard,
                                 &fad))
          fileTime = ((uint64_t)fad.ftLastWriteTime.dwHighDateTime << 32) |
                     fad.ftLastWriteTime.dwLowDateTime;
        printf("[+] Using installed metadata\n");
        fflush(stdout);
      } else {
        printf("[?] Downloading metadata...\n");
        fflush(stdout);
        dist::Metadata m;
        if (!dist::download(uri, it.cdnRel, m)) {
          printf("[-] Failed to download metadata\n");
          fflush(stdout);
          continue;
        }
        enc = std::move(m.bytes);
        fileTime = m.fileTime;
      }

      if (!haveSession) {
        printf("[?] Requesting new session...\n");
        fflush(stdout);
        for (int i = 0; i < 30 && gameSession.empty(); ++i) {
          gameSession = session::mint(version);
          if (gameSession.empty())
            Sleep(2000);
        }
        if (gameSession.empty()) {
          printf("[-] Could not request session\n");
          fflush(stdout);
          continue;
        }
        printf("[+] Session: %s\n", gameSession.c_str());
        fflush(stdout);
        haveSession = true;
      }

      std::wstring metaDir =
          std::filesystem::path(dst).parent_path().wstring();
      if (file_size(dst) >= 0 && !is_decrypted(dst)) {
        std::wstring encBak = metaDir + L"\\encrypted_global-metadata.dat";
        MoveFileExW(dst.c_str(), encBak.c_str(), MOVEFILE_REPLACE_EXISTING);
      }
      if (meta::decrypt(std::move(enc), fileTime, gameSession, metaDir.c_str(),
                        ua) &&
          e.found)
        write_text(sidecar, std::to_string(e.checksum));
    } else {
      std::vector<uint8_t> data;
      bool got = false;
      if (installOk && read_file(installPath, data)) {
        printf("[+] Copied from install: %ls\n", it.destRel);
        got = true;
      } else {
        printf("[?] Downloading %ls...\n", it.destRel);
        fflush(stdout);
        dist::Metadata f;
        if (dist::download(uri, it.cdnRel, f)) {
          data = std::move(f.bytes);
          printf("[+] Downloaded %ls (%zu bytes)\n", it.destRel, data.size());
          got = true;
        } else {
          printf("[-] Failed to download %ls\n", it.destRel);
        }
      }
      if (got && !write_file(dst, data))
        printf("[-] Failed to write %ls\n", it.destRel);
      fflush(stdout);
    }
  }

  printf("[+] Done\n");
  fflush(stdout);
  return 0;
}

static DWORD WINAPI init(void *) {
  AllocConsole();
  SetConsoleTitleW(L"shine");
  FILE *out = nullptr;
  freopen_s(&out, "CONOUT$", "w", stdout);

  HANDLE nul = CreateFileW(L"NUL", GENERIC_WRITE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                           OPEN_EXISTING, 0, nullptr);
  if (nul != INVALID_HANDLE_VALUE)
    SetStdHandle(STD_OUTPUT_HANDLE, nul);

  printf("[?] Attached\n");
  fflush(stdout);

  g_authEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);

  HANDLE h = CreateThread(nullptr, 0, hider, nullptr, 0, nullptr);
  if (h)
    CloseHandle(h);

  if (!install()) {
    printf("[-] Hook failed\n");
    fflush(stdout);
    return 1;
  }

  h = CreateThread(nullptr, 0, worker, nullptr, 0, nullptr);
  if (h)
    CloseHandle(h);
  return 0;
}

BOOL APIENTRY DllMain(HMODULE mod, DWORD reason, LPVOID) {
  if (reason == DLL_PROCESS_ATTACH) {
    g_self = mod;
    DisableThreadLibraryCalls(mod);
    HANDLE thread = CreateThread(nullptr, 0, init, nullptr, 0, nullptr);
    if (thread)
      CloseHandle(thread);
    else
      return FALSE;
  }
  return TRUE;
}
