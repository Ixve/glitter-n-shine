#pragma once
#include <cstdint>
#include <vector>

namespace meta {

void run(const std::vector<uint8_t> &decodedJson, const wchar_t *outputDir, const wchar_t *userAgent);
}
