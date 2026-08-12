#include "res.h"
#include <windows.h>
#include <commctrl.h>
#include <cstdio>
#include <filesystem>
#include <shellapi.h>
#include <shobjidl.h>
#include <string>
#include <tlhelp32.h>
#include <vector>

#pragma comment(lib, "comctl32.lib")
#pragma comment(linker,                                                        \
                "\"/manifestdependency:type='win32' "                          \
                "name='Microsoft.Windows.Common-Controls' version='6.0.0.0' "  \
                "processorArchitecture='*' publicKeyToken='6595b64144ccf1df' "  \
                "language='*'\"")

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
  if (!res)
    return {};
  HGLOBAL mem = LoadResource(mod, res);
  if (!mem)
    return {};
  void *data = LockResource(mem);
  DWORD size = SizeofResource(mod, res);
  if (!data || !size)
    return {};
  std::filesystem::path file =
      std::filesystem::temp_directory_path() /
      (L"shine_" + std::to_wstring(GetCurrentProcessId()) + L".dll");
  HANDLE out = CreateFileW(file.c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, nullptr);
  if (out == INVALID_HANDLE_VALUE)
    return {};
  DWORD wrote = 0;
  BOOL ok = WriteFile(out, data, size, &wrote, nullptr);
  BOOL flushed = FlushFileBuffers(out);
  CloseHandle(out);
  if (!ok || !flushed || wrote != size) {
    DeleteFileW(file.c_str());
    return {};
  }
  return file;
}

static LPTHREAD_START_ROUTINE remote_load() {
  HMODULE local = GetModuleHandleW(L"kernel32.dll");
  if (!local)
    return nullptr;
  return reinterpret_cast<LPTHREAD_START_ROUTINE>(
      GetProcAddress(local, "LoadLibraryW"));
}

static bool inject(HANDLE proc, const std::filesystem::path &file) {
  std::wstring path = file.wstring();
  SIZE_T size = (path.size() + 1) * sizeof(wchar_t);
  void *remote = VirtualAllocEx(proc, nullptr, size, MEM_COMMIT | MEM_RESERVE,
                                PAGE_READWRITE);
  if (!remote)
    return false;
  SIZE_T wrote = 0;
  if (!WriteProcessMemory(proc, remote, path.c_str(), size, &wrote) ||
      wrote != size) {
    VirtualFreeEx(proc, remote, 0, MEM_RELEASE);
    return false;
  }
  LPTHREAD_START_ROUTINE load = remote_load();
  if (!load) {
    VirtualFreeEx(proc, remote, 0, MEM_RELEASE);
    return false;
  }
  HANDLE thread =
      CreateRemoteThread(proc, nullptr, 0, load, remote, 0, nullptr);
  if (!thread) {
    VirtualFreeEx(proc, remote, 0, MEM_RELEASE);
    return false;
  }
  DWORD wait = WaitForSingleObject(thread, 15000);
  DWORD code = 0;
  BOOL read = wait == WAIT_OBJECT_0 && GetExitCodeThread(thread, &code);
  CloseHandle(thread);
  VirtualFreeEx(proc, remote, 0, MEM_RELEASE);
  return read && code && code != STILL_ACTIVE;
}

static DWORD running_pid(const wchar_t *name) {
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snap == INVALID_HANDLE_VALUE)
    return 0;
  PROCESSENTRY32W pe = {sizeof(pe)};
  DWORD pid = 0;
  if (Process32FirstW(snap, &pe)) {
    do {
      if (_wcsicmp(pe.szExeFile, name) == 0) {
        pid = pe.th32ProcessID;
        break;
      }
    } while (Process32NextW(snap, &pe));
  }
  CloseHandle(snap);
  return pid;
}

static void kill_process(const wchar_t *name) {
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snap == INVALID_HANDLE_VALUE)
    return;
  PROCESSENTRY32W pe = {sizeof(pe)};
  if (Process32FirstW(snap, &pe)) {
    do {
      if (_wcsicmp(pe.szExeFile, name) == 0) {
        HANDLE p = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
        if (p) {
          TerminateProcess(p, 0);
          CloseHandle(p);
        }
      }
    } while (Process32NextW(snap, &pe));
  }
  CloseHandle(snap);
}

static DWORD wait_for_launcher(int seconds) {
  for (int i = 0; i < seconds; ++i) {
    DWORD pid = running_pid(L"BsgLauncher.exe");
    if (pid)
      return pid;
    Sleep(1000);
  }
  return 0;
}

static std::wstring select_folder() {
  std::wstring result;
  if (FAILED(CoInitializeEx(nullptr,
                            COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE)))
    return result;
  IFileOpenDialog *dlg = nullptr;
  if (SUCCEEDED(CoCreateInstance(CLSID_FileOpenDialog, nullptr,
                                 CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&dlg)))) {
    DWORD opts = 0;
    dlg->GetOptions(&opts);
    dlg->SetOptions(opts | FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM);
    dlg->SetTitle(L"Select Output Folder");
    if (SUCCEEDED(dlg->Show(nullptr))) {
      IShellItem *item = nullptr;
      if (SUCCEEDED(dlg->GetResult(&item))) {
        PWSTR path = nullptr;
        if (SUCCEEDED(item->GetDisplayName(SIGDN_FILESYSPATH, &path))) {
          result = path;
          CoTaskMemFree(path);
        }
        item->Release();
      }
    }
    dlg->Release();
  }
  CoUninitialize();
  return result;
}

static void write_out_path(const std::wstring &path) {
  wchar_t tmp[MAX_PATH] = {};
  GetTempPathW(MAX_PATH, tmp);
  std::wstring f = std::wstring(tmp) + L"gns_out.txt";
  HANDLE h = CreateFileW(f.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                         FILE_ATTRIBUTE_NORMAL, nullptr);
  if (h != INVALID_HANDLE_VALUE) {
    DWORD w = 0;
    WriteFile(h, path.c_str(), (DWORD)(path.size() * sizeof(wchar_t)), &w,
              nullptr);
    CloseHandle(h);
  }
}

static int choose_launcher() {
  TASKDIALOG_BUTTON buttons[] = {{101, L"Steam"}, {102, L"BSG"}};
  TASKDIALOGCONFIG cfg = {sizeof(cfg)};
  cfg.hInstance = GetModuleHandleW(nullptr);
  cfg.dwFlags = TDF_ALLOW_DIALOG_CANCELLATION;
  cfg.dwCommonButtons = 0;
  cfg.pszWindowTitle = L"glitter";
  cfg.pszMainInstruction = L"Select your launcher type";
  cfg.pButtons = buttons;
  cfg.cButtons = ARRAYSIZE(buttons);
  int pressed = 0;
  if (FAILED(TaskDialogIndirect(&cfg, &pressed, nullptr, nullptr)))
    return 0;
  return pressed;
}

static int attach(DWORD pid, const std::filesystem::path &dll) {
  HANDLE proc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                                PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
                                PROCESS_VM_READ,
                            FALSE, pid);
  if (!proc) {
    printf("[-] OpenProcess failed (err=%lu)\n", GetLastError());
    return 1;
  }
  bool ok = inject(proc, dll);
  CloseHandle(proc);
  if (!ok) {
    printf("[-] Injection failed (err=%lu)\n", GetLastError());
    return 1;
  }
  printf("[+] Injected\n");
  return 0;
}

static int launch_bsg(const std::filesystem::path &dll) {
  DWORD pid = running_pid(L"BsgLauncher.exe");
  if (pid) {
    printf("[+] Launcher already running (PID %lu)\n", pid);
    return attach(pid, dll);
  }

  std::filesystem::path exe = find();
  if (exe.empty()) {
    printf("[-] Could not find BSG Launcher\n");
    return 1;
  }

  STARTUPINFOW si = {sizeof(si)};
  PROCESS_INFORMATION pi = {};
  std::wstring cmd = L"\"" + exe.wstring() + L"\"";
  std::vector<wchar_t> args(cmd.begin(), cmd.end());
  args.push_back(L'\0');
  BOOL made = CreateProcessW(exe.c_str(), args.data(), nullptr, nullptr, FALSE,
                             CREATE_SUSPENDED, nullptr,
                             exe.parent_path().c_str(), &si, &pi);
  if (!made) {
    printf("[-] CreateProcess failed (err=%lu)\n", GetLastError());
    return 1;
  }

  if (!inject(pi.hProcess, dll)) {
    TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    printf("[-] Injection failed (err=%lu)\n", GetLastError());
    return 1;
  }
  ResumeThread(pi.hThread);
  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);
  printf("[+] Injected\n");
  return 0;
}

static int launch_steam(const std::filesystem::path &dll) {
  DWORD pid = running_pid(L"BsgLauncher.exe");
  if (!pid) {
    printf("[?] Starting via Steam...\n");
    ShellExecuteW(nullptr, L"open", L"steam://run/3932890", nullptr, nullptr,
                  SW_SHOWNORMAL);
    pid = wait_for_launcher(180);
  }
  if (!pid) {
    printf("[-] Launcher did not start\n");
    return 1;
  }
  printf("[+] Launcher running (PID %lu)\n", pid);
  return attach(pid, dll);
}

int main() {
  SetConsoleTitleW(L"glitter");

  int choice = choose_launcher();
  if (choice != 101 && choice != 102) {
    printf("[-] Cancelled\n");
    return 0;
  }

  std::wstring outFolder = select_folder();
  if (outFolder.empty()) {
    printf("[-] No output folder selected\n");
    return 0;
  }
  write_out_path(outFolder);

  kill_process(L"EscapeFromTarkov.exe");
  kill_process(L"BsgLauncher.exe");
  Sleep(500);

  std::filesystem::path dll = drop();
  if (dll.empty()) {
    printf("[-] Payload extraction failed\n");
    return 1;
  }

  int rc = (choice == 101) ? launch_steam(dll) : launch_bsg(dll);

  DeleteFileW(dll.c_str());
  for (int i = 3; i >= 0; --i) {
    printf("%d...\n", i);
    if (i)
      Sleep(1000);
  }
  return rc;
}
