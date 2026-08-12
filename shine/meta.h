#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace meta {
bool decrypt(std::vector<uint8_t> metadata, uint64_t fileTime,
             const std::string &session, const wchar_t *outputDir,
             const wchar_t *userAgent);
}
