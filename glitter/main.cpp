#include "res.h"
#include <windows.h>
#include <cstdio>
#include <filesystem>
#include <string>
#include <tlhelp32.h>
#include <vector>

static std::wstring val(HKEY key, const wchar_t *name) {
  DWORD size = 0;
  DWORD type = 0;
  if (RegQueryValueExW(key, name, nullptr, &type, nullptr, &size) !=
          ERROR_SUCCESS ||
      (type != REG_SZ && type != REG_EXPAND_SZ) || size < sizeof(wchar_t))
    return {};
  std::wstring text(size / sizeof(wchar_t), L'\0');
  if (RegQueryValueExW(key, name, nullptr, &type,
                       reinterpret_cast<BYTE *>(text.data()),
                       &size) != ERROR_SUCCESS)
    return {};
  text.resize(wcsnlen_s(text.c_str(), text.size()));
  if (type != REG_EXPAND_SZ)
    return text;
  DWORD need = ExpandEnvironmentStringsW(text.c_str(), nullptr, 0);
  if (!need)
    return {};
  std::wstring out(need, L'\0');
  if (!ExpandEnvironmentStringsW(text.c_str(), out.data(), need))
    return {};
  out.resize(wcsnlen_s(out.c_str(), out.size()));
  return out;
}

static std::filesystem::path find() {
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
        DWORD len = static_cast<DWORD>(std::size(name));
        if (RegEnumKeyExW(list, i, name, &len, nullptr, nullptr, nullptr,
                          nullptr) != ERROR_SUCCESS)
          break;
        HKEY key = nullptr;
        if (RegOpenKeyExW(list, name, 0, KEY_READ, &key) != ERROR_SUCCESS)
          continue;
        std::wstring title = val(key, L"DisplayName");
        std::wstring dir = val(key, L"InstallLocation");
        RegCloseKey(key);
        if (title.find(L"Battlestate Games Launcher") == std::wstring::npos ||
            dir.empty())
          continue;
        std::filesystem::path exe =
            std::filesystem::path(dir) / L"BsgLauncher.exe";
        if (std::filesystem::is_regular_file(exe)) {
          RegCloseKey(list);
          return exe;
        }
      }
      RegCloseKey(list);
    }
  }
  return {};
}

static std::filesystem::path drop() {
  HMODULE mod = GetModuleHandleW(nullptr);
  HRSRC res = FindResourceW(mod, MAKEINTRESOURCEW(IDR_DLL), RT_RCDATA);
  if (!res) {
    printf("[-] FindResource failed (err=%lu)\n", GetLastError());
    return {};
  }
  HGLOBAL mem = LoadResource(mod, res);
  if (!mem) {
    printf("[-] LoadResource failed (err=%lu)\n", GetLastError());
    return {};
  }
  void *data = LockResource(mem);
  DWORD size = SizeofResource(mod, res);
  if (!data || !size) {
    printf("[-] Resource is empty\n");
    return {};
  }
  std::filesystem::path file =
      std::filesystem::temp_directory_path() /
      (L"shine_" + std::to_wstring(GetCurrentProcessId()) + L".dll");
  HANDLE out = CreateFileW(file.c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, nullptr);
  if (out == INVALID_HANDLE_VALUE) {
    printf("[-] Cannot create temporary payload DLL\n");
    return {};
  }
  DWORD wrote = 0;
  BOOL ok = WriteFile(out, data, size, &wrote, nullptr);
  BOOL flushed = FlushFileBuffers(out);
  CloseHandle(out);
  if (!ok || !flushed || wrote != size) {
    printf("[-] Partial payload write (%lu/%lu)\n", wrote, size);
    DeleteFileW(file.c_str());
    return {};
  }
  return file;
}

static LPTHREAD_START_ROUTINE remote_load(DWORD pid) {
  HMODULE local = GetModuleHandleW(L"kernel32.dll");
  if (!local) return nullptr;
  return reinterpret_cast<LPTHREAD_START_ROUTINE>(GetProcAddress(local, "LoadLibraryW"));
}

static bool inject(HANDLE proc, DWORD pid, const std::filesystem::path &file) {
  std::wstring path = file.wstring();
  SIZE_T size = (path.size() + 1) * sizeof(wchar_t);
  void *remote = VirtualAllocEx(proc, nullptr, size, MEM_COMMIT | MEM_RESERVE,
                                PAGE_READWRITE);
  if (!remote) {
    printf("[-] VirtualAllocEx failed (err=%lu)\n", GetLastError());
    return false;
  }
  SIZE_T wrote = 0;
  if (!WriteProcessMemory(proc, remote, path.c_str(), size, &wrote) ||
      wrote != size) {
    printf("[-] WriteProcessMemory failed (err=%lu)\n", GetLastError());
    VirtualFreeEx(proc, remote, 0, MEM_RELEASE);
    return false;
  }
  LPTHREAD_START_ROUTINE load = remote_load(pid);
  if (!load) {
    printf("[-] Could not resolve remote LoadLibraryW (err=%lu)\n",
           GetLastError());
    VirtualFreeEx(proc, remote, 0, MEM_RELEASE);
    return false;
  }
  HANDLE thread =
      CreateRemoteThread(proc, nullptr, 0, load, remote, 0, nullptr);
  if (!thread) {
    printf("[-] CreateRemoteThread failed (err=%lu)\n", GetLastError());
    VirtualFreeEx(proc, remote, 0, MEM_RELEASE);
    return false;
  }
  DWORD wait = WaitForSingleObject(thread, 15000);
  DWORD code = 0;
  BOOL read = wait == WAIT_OBJECT_0 && GetExitCodeThread(thread, &code);
  CloseHandle(thread);
  VirtualFreeEx(proc, remote, 0, MEM_RELEASE);
  if (!read || !code || code == STILL_ACTIVE) {
    printf("[-] LoadLibraryW returned NULL in target process\n");
    return false;
  }
  return true;
}

int main() {
  SetConsoleTitleA("glitter");
  printf("[?] Searching for launcher...\n");
  std::filesystem::path exe = find();
  if (exe.empty()) {
    printf("[-] Could not find BSG Launcher - is it actually installed? "
           "(err=%lu)\n",
           GetLastError());
    return 1;
  }
  printf("[+] Found launcher: %ls\n\n", exe.c_str());
  printf("[?] Extracting payload\n");
  std::filesystem::path dll = drop();
  if (dll.empty()) {
    printf("[-] Payload extraction failed (err=%lu)\n", GetLastError());
    return 1;
  }
  printf("[+] DLL: %ls\n\n", dll.c_str());

  std::vector<wchar_t> self(32768);
  DWORD got =
      GetModuleFileNameW(nullptr, self.data(), static_cast<DWORD>(self.size()));
  if (!got || got == self.size()) {
    printf("[-] Could not resolve output directory (err=%lu)\n",
           GetLastError());
    DeleteFileW(dll.c_str());
    return 1;
  }
  std::filesystem::path out = std::filesystem::path(self.data()).parent_path();
  SetEnvironmentVariableW(L"SHINE_OUT", out.c_str());

  printf("[+] Starting launcher...\n");
  STARTUPINFOW si = {sizeof(si)};
  PROCESS_INFORMATION pi = {};
  std::wstring cmd = L"\"" + exe.wstring() + L"\"";
  std::vector<wchar_t> args(cmd.begin(), cmd.end());
  args.push_back(L'\0');
  BOOL made = CreateProcessW(exe.c_str(), args.data(), nullptr, nullptr, FALSE,
                             CREATE_SUSPENDED, nullptr,
                             exe.parent_path().c_str(), &si, &pi);
  SetEnvironmentVariableW(L"SHINE_OUT", nullptr);
  if (!made) {
    printf("[-] CreateProcess failed (err=%lu)\n", GetLastError());
    DeleteFileW(dll.c_str());
    return 1;
  }
  printf("[+] PID: %lu (suspended)\n\n", pi.dwProcessId);
  printf("[?] Injecting payload...\n");
  if (!inject(pi.hProcess, pi.dwProcessId, dll)) {
    TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    DeleteFileW(dll.c_str());
    printf("[-] Injection failure (err=%lu)\n", GetLastError());
    return 1;
  }
  DeleteFileW(dll.c_str());
  printf("[+] Payload injected\n\n");
  if (ResumeThread(pi.hThread) == static_cast<DWORD>(-1)) {
    printf("[-] ResumeThread failed (err=%lu)\n", GetLastError());
    TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 1;
  }
  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);
  printf("[+] Launcher running - injector exitting in ... \n");
  for (int i = 5; i >= 0; --i) {
    printf("%d...\n", i);
    if (i)
      Sleep(1000);
  }
  return 0;
}
