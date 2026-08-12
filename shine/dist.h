#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace dist {

struct Auth {
  std::string bearer;
  std::string phpsessid;
  std::string launcherVer;
  std::wstring userAgent;
};

struct Metadata {
  std::vector<uint8_t> bytes;
  uint64_t fileTime = 0;
};

std::string latest_version(const Auth &auth);
std::string installation_uri(const Auth &auth, const std::string &version);
bool download(const std::string &unpackedUri, const char *rel, Metadata &out);
}
