#include "session.h"
#include "res.h"
#include "self.h"

#include <windows.h>
#include <comdef.h>
#include <metahost.h>

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#pragma comment(lib, "mscoree.lib")
#import <mscorlib.tlb> auto_rename rename("ReportEvent", "mscorlib_ReportEvent")

namespace {

bool runtime_host(ICorRuntimeHost **out) {
  *out = nullptr;
  ICLRMetaHost *meta = nullptr;
  if (FAILED(CLRCreateInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost,
                               (LPVOID *)&meta)) ||
      !meta)
    return false;

  ICLRRuntimeInfo *rt = nullptr;
  IEnumUnknown *e = nullptr;
  if (SUCCEEDED(meta->EnumerateLoadedRuntimes(GetCurrentProcess(), &e)) && e) {
    IUnknown *u = nullptr;
    ULONG fetched = 0;
    while (e->Next(1, &u, &fetched) == S_OK && u) {
      ICLRRuntimeInfo *cand = nullptr;
      if (SUCCEEDED(u->QueryInterface(IID_ICLRRuntimeInfo, (void **)&cand)) &&
          cand) {
        rt = cand;
        u->Release();
        break;
      }
      u->Release();
      u = nullptr;
    }
    e->Release();
  }

  bool ok = false;
  if (rt) {
    ICorRuntimeHost *host = nullptr;
    if (SUCCEEDED(rt->GetInterface(CLSID_CorRuntimeHost, IID_ICorRuntimeHost,
                                   (LPVOID *)&host)) &&
        host) {
      host->Start();
      *out = host;
      ok = true;
    }
    rt->Release();
  }
  meta->Release();
  return ok;
}

bool load_blob(std::vector<uint8_t> &out) {
  HRSRC r = FindResourceW(g_self, MAKEINTRESOURCEW(IDR_BRIDGE), RT_RCDATA);
  if (!r)
    return false;
  HGLOBAL m = LoadResource(g_self, r);
  DWORD n = SizeofResource(g_self, r);
  void *d = m ? LockResource(m) : nullptr;
  if (!d || !n)
    return false;
  out.assign((const uint8_t *)d, (const uint8_t *)d + n);
  return true;
}

std::string invoke(ICorRuntimeHost *host, const std::vector<uint8_t> &blob,
                   const std::string &version) {
  std::string result;
  IUnknown *domainUnk = nullptr;
  if (FAILED(host->GetDefaultDomain(&domainUnk)) || !domainUnk)
    return result;

  try {
    mscorlib::_AppDomainPtr domain;
    domainUnk->QueryInterface(__uuidof(mscorlib::_AppDomain), (void **)&domain);
    if (domain) {
      SAFEARRAY *sa = SafeArrayCreateVector(VT_UI1, 0, (ULONG)blob.size());
      void *p = nullptr;
      SafeArrayAccessData(sa, &p);
      memcpy(p, blob.data(), blob.size());
      SafeArrayUnaccessData(sa);

      mscorlib::_AssemblyPtr assembly = domain->Load_3(sa);
      SafeArrayDestroy(sa);

      mscorlib::_TypePtr type = assembly->GetType_2(_bstr_t(L"Shine.Bridge"));
      if (type) {
        std::wstring wver(version.begin(), version.end());
        SAFEARRAY *args = SafeArrayCreateVector(VT_VARIANT, 0, 1);
        VARIANT a;
        VariantInit(&a);
        a.vt = VT_BSTR;
        a.bstrVal = SysAllocString(wver.c_str());
        LONG ix = 0;
        SafeArrayPutElement(args, &ix, &a);
        VariantClear(&a);

        _variant_t target;
        _variant_t rv = type->InvokeMember_3(
            _bstr_t(L"Run"),
            (mscorlib::BindingFlags)(mscorlib::BindingFlags_InvokeMethod |
                                     mscorlib::BindingFlags_Static |
                                     mscorlib::BindingFlags_Public),
            nullptr, target, args);
        SafeArrayDestroy(args);

        if (rv.vt == VT_BSTR && rv.bstrVal) {
          std::wstring w(rv.bstrVal, SysStringLen(rv.bstrVal));
          result.assign(w.begin(), w.end());
        }
      }
    }
  } catch (const _com_error &e) {
    printf("[-] Managed invoke failed (hr=0x%08lX)\n", (unsigned long)e.Error());
    fflush(stdout);
  } catch (...) {
  }

  domainUnk->Release();
  return result;
}

} // namespace

namespace session {

std::string mint(const std::string &version) {
  std::vector<uint8_t> blob;
  if (!load_blob(blob))
    return {};

  ICorRuntimeHost *host = nullptr;
  if (!runtime_host(&host))
    return {};

  std::string result = invoke(host, blob, version);
  host->Release();

  if (result.rfind("OK|", 0) == 0)
    return result.substr(3);
  if (!result.empty()) {
    printf("[-] Session error: %s\n", result.c_str());
    fflush(stdout);
  }
  return {};
}

} // namespace session
