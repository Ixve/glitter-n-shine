

#include "decode.h"

#include <algorithm>
#include <windows.h>
#include <bcrypt.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <optional>
#include <string>
#include <vector>
#include <zlib.h>

#pragma comment(lib, "bcrypt.lib")

using Bytes = std::vector<uint8_t>;

static Bytes trim_zeros(const Bytes &data) {
  size_t len = data.size();
  while (len > 0 && data[len - 1] == 0)
    --len;
  return Bytes(data.begin(), data.begin() + len);
}

static Bytes trim_ws(const Bytes &data) {
  size_t len = data.size();
  while (len > 0) {
    uint8_t b = data[len - 1];
    if (b == 0 || b == 9 || b == 10 || b == 13 || b == 32)
      --len;
    else
      break;
  }
  return Bytes(data.begin(), data.begin() + len);
}

class JsonValidator {
public:
  explicit JsonValidator(const Bytes &data) : data_(data) {}

  bool parse_document() {
    skip_whitespace();
    if (position_ >= data_.size() ||
        (data_[position_] != '{' && data_[position_] != '['))
      return false;
    if (!parse_value(0))
      return false;
    skip_whitespace();
    return position_ == data_.size();
  }

private:
  static bool is_hex(uint8_t value) {
    return (value >= '0' && value <= '9') || (value >= 'a' && value <= 'f') ||
           (value >= 'A' && value <= 'F');
  }

  static uint16_t hex_quad(const uint8_t *value) {
    uint16_t result = 0;
    for (int i = 0; i < 4; ++i) {
      uint8_t digit = value[i];
      result = static_cast<uint16_t>(result << 4);
      if (digit >= '0' && digit <= '9')
        result |= digit - '0';
      else if (digit >= 'a' && digit <= 'f')
        result |= digit - 'a' + 10;
      else
        result |= digit - 'A' + 10;
    }
    return result;
  }

  void skip_whitespace() {
    while (position_ < data_.size()) {
      uint8_t value = data_[position_];
      if (value != ' ' && value != '\t' && value != '\r' && value != '\n')
        break;
      ++position_;
    }
  }

  bool consume(uint8_t expected) {
    if (position_ >= data_.size() || data_[position_] != expected)
      return false;
    ++position_;
    return true;
  }

  bool consume_literal(const char *literal) {
    size_t length = strlen(literal);
    if (position_ + length > data_.size() ||
        memcmp(data_.data() + position_, literal, length) != 0)
      return false;
    position_ += length;
    return true;
  }

  bool parse_value(size_t depth) {
    if (depth >= 64)
      return false;
    skip_whitespace();
    if (position_ >= data_.size())
      return false;

    switch (data_[position_]) {
    case '{':
      return parse_object(depth + 1);
    case '[':
      return parse_array(depth + 1);
    case '"':
      return parse_string();
    case 't':
      return consume_literal("true");
    case 'f':
      return consume_literal("false");
    case 'n':
      return consume_literal("null");
    default:
      return parse_number();
    }
  }

  bool parse_object(size_t depth) {
    if (!consume('{'))
      return false;
    skip_whitespace();
    if (consume('}'))
      return true;

    for (;;) {
      if (!parse_string())
        return false;
      skip_whitespace();
      if (!consume(':') || !parse_value(depth))
        return false;
      skip_whitespace();
      if (consume('}'))
        return true;
      if (!consume(','))
        return false;
      skip_whitespace();
    }
  }

  bool parse_array(size_t depth) {
    if (!consume('['))
      return false;
    skip_whitespace();
    if (consume(']'))
      return true;

    for (;;) {
      if (!parse_value(depth))
        return false;
      skip_whitespace();
      if (consume(']'))
        return true;
      if (!consume(','))
        return false;
    }
  }

  bool parse_string() {
    if (!consume('"'))
      return false;
    while (position_ < data_.size()) {
      uint8_t value = data_[position_++];
      if (value == '"')
        return true;
      if (value < 0x20)
        return false;
      if (value == '\\') {
        if (position_ >= data_.size())
          return false;
        uint8_t escape = data_[position_++];
        if (escape == '"' || escape == '\\' || escape == '/' || escape == 'b' ||
            escape == 'f' || escape == 'n' || escape == 'r' || escape == 't')
          continue;
        if (escape != 'u' || position_ + 4 > data_.size())
          return false;
        for (size_t i = 0; i < 4; ++i)
          if (!is_hex(data_[position_ + i]))
            return false;
        uint16_t codeUnit = hex_quad(data_.data() + position_);
        position_ += 4;
        if (codeUnit >= 0xD800 && codeUnit <= 0xDBFF) {
          if (position_ + 6 > data_.size() || data_[position_] != '\\' ||
              data_[position_ + 1] != 'u')
            return false;
          for (size_t i = 2; i < 6; ++i)
            if (!is_hex(data_[position_ + i]))
              return false;
          uint16_t low = hex_quad(data_.data() + position_ + 2);
          if (low < 0xDC00 || low > 0xDFFF)
            return false;
          position_ += 6;
        } else if (codeUnit >= 0xDC00 && codeUnit <= 0xDFFF) {
          return false;
        }
        continue;
      }
      if (value < 0x80)
        continue;
      if (!consume_utf8_tail(value))
        return false;
    }
    return false;
  }

  bool consume_utf8_tail(uint8_t first) {
    size_t continuationCount;
    uint32_t codePoint;
    uint32_t minimum;
    if ((first & 0xE0) == 0xC0) {
      continuationCount = 1;
      codePoint = first & 0x1F;
      minimum = 0x80;
    } else if ((first & 0xF0) == 0xE0) {
      continuationCount = 2;
      codePoint = first & 0x0F;
      minimum = 0x800;
    } else if ((first & 0xF8) == 0xF0) {
      continuationCount = 3;
      codePoint = first & 0x07;
      minimum = 0x10000;
    } else {
      return false;
    }

    if (position_ + continuationCount > data_.size())
      return false;
    for (size_t i = 0; i < continuationCount; ++i) {
      uint8_t continuation = data_[position_++];
      if ((continuation & 0xC0) != 0x80)
        return false;
      codePoint = (codePoint << 6) | (continuation & 0x3F);
    }
    return codePoint >= minimum && codePoint <= 0x10FFFF &&
           !(codePoint >= 0xD800 && codePoint <= 0xDFFF);
  }

  bool parse_number() {
    size_t start = position_;
    consume('-');
    if (position_ >= data_.size())
      return false;
    if (data_[position_] == '0') {
      ++position_;
      if (position_ < data_.size() && data_[position_] >= '0' &&
          data_[position_] <= '9')
        return false;
    } else {
      if (data_[position_] < '1' || data_[position_] > '9')
        return false;
      while (position_ < data_.size() && data_[position_] >= '0' &&
             data_[position_] <= '9')
        ++position_;
    }

    if (consume('.')) {
      size_t fractionStart = position_;
      while (position_ < data_.size() && data_[position_] >= '0' &&
             data_[position_] <= '9')
        ++position_;
      if (position_ == fractionStart)
        return false;
    }
    if (position_ < data_.size() &&
        (data_[position_] == 'e' || data_[position_] == 'E')) {
      ++position_;
      if (position_ < data_.size() &&
          (data_[position_] == '+' || data_[position_] == '-'))
        ++position_;
      size_t exponentStart = position_;
      while (position_ < data_.size() && data_[position_] >= '0' &&
             data_[position_] <= '9')
        ++position_;
      if (position_ == exponentStart)
        return false;
    }
    return position_ > start;
  }

  const Bytes &data_;
  size_t position_ = 0;
};

static bool looks_json(const Bytes &raw) {
  Bytes trimmed = trim_zeros(raw);
  return !trimmed.empty() && JsonValidator(trimmed).parse_document();
}

static bool looks_decoded(const Bytes &data) {
  Bytes t = trim_zeros(data);
  if (t.empty())
    return false;
  if (looks_json(t))
    return true;

  size_t sample = (t.size() < 4096) ? t.size() : 4096;
  size_t printable = 0;
  for (size_t i = 0; i < sample; ++i) {
    uint8_t v = t[i];
    if (v == 9 || v == 10 || v == 13 || (v >= 32 && v < 127))
      ++printable;
  }
  return printable >= sample * 95 / 100;
}

static int score(const Bytes &data) {
  return looks_json(data) ? 1000000 + (int)data.size() : (int)data.size();
}

static std::optional<Bytes> dechunk(const Bytes &data) {
  try {
    Bytes output;
    size_t pos = 0;
    while (pos < data.size()) {

      size_t lineEnd = pos;
      while (lineEnd < data.size() && data[lineEnd] != '\n')
        ++lineEnd;
      if (lineEnd >= data.size())
        return std::nullopt;

      std::string line(reinterpret_cast<const char *>(data.data()) + pos,
                       lineEnd - pos);

      while (!line.empty() && (line.back() == '\r' || line.back() == ' '))
        line.pop_back();
      auto semi = line.find(';');
      if (semi != std::string::npos)
        line = line.substr(0, semi);

      if (line.empty())
        return std::nullopt;
      char *end;
      long sz = strtol(line.c_str(), &end, 16);
      if (*end != '\0' || sz < 0)
        return std::nullopt;

      pos = lineEnd + 1;
      if (sz == 0)
        return output;
      if (pos + (size_t)sz > data.size())
        return std::nullopt;

      output.insert(output.end(), data.begin() + pos, data.begin() + pos + sz);
      pos += sz;
      if (pos < data.size() && data[pos] == '\r')
        ++pos;
      if (pos < data.size() && data[pos] == '\n')
        ++pos;
    }
    return std::nullopt;
  } catch (...) {
    return std::nullopt;
  }
}

static std::optional<Bytes> deshuffle(const Bytes &input) {
  if (input.size() < 4)
    return std::nullopt;
  try {
    Bytes output = input;
    size_t startEntry = output.size() % 0xAAB;
    size_t tableSize = startEntry + output.size();

    std::vector<uint64_t> table(tableSize);
    uint64_t cursor = 0x65F6D;
    for (size_t i = 0; i < tableSize; ++i) {
      table[i] = (1624453ULL * cursor++ + 1023920427ULL) % 0x8ED7A18DULL;
      if (cursor > 0xA53F260DDB0ULL)
        cursor = 0;
    }

    for (size_t i = 1; i < output.size(); ++i) {
      size_t swapIdx = (size_t)(table[i + startEntry] % (uint64_t)i);
      std::swap(output[i], output[swapIdx]);
    }

    int32_t sz;
    memcpy(&sz, output.data(), 4);
    if (sz < 0 || (size_t)sz > output.size() - 4)
      return std::nullopt;
    return Bytes(output.begin() + 4, output.begin() + 4 + sz);
  } catch (...) {
    return std::nullopt;
  }
}

static std::optional<Bytes> decompress(const Bytes &input, bool gzip) {
  static constexpr size_t MaxCandidateSize = 256ULL * 1024 * 1024;
  if (input.empty() || input.size() > (std::numeric_limits<uInt>::max)())
    return std::nullopt;
  try {
    z_stream zs{};

    int wbits = gzip ? (15 + 16) : 15;
    if (inflateInit2(&zs, wbits) != Z_OK)
      return std::nullopt;

    zs.next_in = const_cast<Bytef *>(input.data());
    zs.avail_in = (uInt)input.size();

    Bytes output;
    output.reserve((std::min)(MaxCandidateSize, input.size() * 4));
    uint8_t buf[65536];

    int ret;
    do {
      zs.next_out = buf;
      zs.avail_out = sizeof(buf);
      ret = inflate(&zs, Z_NO_FLUSH);
      size_t produced = sizeof(buf) - zs.avail_out;
      if (produced > MaxCandidateSize - output.size()) {
        inflateEnd(&zs);
        return std::nullopt;
      }
      output.insert(output.end(), buf, buf + produced);
      if (ret == Z_STREAM_END)
        break;
      if (ret != Z_OK || (produced == 0 && zs.avail_in == 0)) {
        inflateEnd(&zs);
        return std::nullopt;
      }
    } while (true);

    inflateEnd(&zs);
    return output;
  } catch (...) {
    return std::nullopt;
  }
}

static constexpr const char *AES_KEY = "7*YabV3MfOfyE*lhI*l*Qx*q";

static std::optional<Bytes> decrypt_aes(const Bytes &input,
                                        const char *keyStr) {
  if (input.size() < 32 || (input.size() - 16) % 16 != 0)
    return std::nullopt;
  size_t keyLength = strlen(keyStr);
  if (keyLength != 16 && keyLength != 24 && keyLength != 32)
    return std::nullopt;
  try {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM,
                                                    nullptr, 0)))
      return std::nullopt;

    if (!BCRYPT_SUCCESS(BCryptSetProperty(
            hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
            (ULONG)((wcslen(BCRYPT_CHAIN_MODE_CBC) + 1) * sizeof(wchar_t)),
            0))) {
      BCryptCloseAlgorithmProvider(hAlg, 0);
      return std::nullopt;
    }

    std::vector<uint8_t> keyBytes(keyStr, keyStr + keyLength);
    BCRYPT_KEY_HANDLE hKey = nullptr;
    DWORD objLen = 0, retLen = 0;
    if (!BCRYPT_SUCCESS(BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
                                          (PUCHAR)&objLen, sizeof(objLen),
                                          &retLen, 0)) ||
        objLen == 0) {
      BCryptCloseAlgorithmProvider(hAlg, 0);
      return std::nullopt;
    }
    std::vector<uint8_t> keyObj(objLen);

    if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(
            hAlg, &hKey, keyObj.data(), objLen, keyBytes.data(),
            (ULONG)keyBytes.size(), 0))) {
      BCryptCloseAlgorithmProvider(hAlg, 0);
      return std::nullopt;
    }

    uint8_t iv[16];
    memcpy(iv, input.data(), 16);
    const uint8_t *cipher = input.data() + 16;
    ULONG cipherLen = (ULONG)(input.size() - 16);

    Bytes output(cipherLen);
    ULONG written = 0;
    NTSTATUS st =
        BCryptDecrypt(hKey, (PUCHAR)cipher, cipherLen, nullptr, iv, sizeof(iv),
                      output.data(), (ULONG)output.size(), &written, 0);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (!BCRYPT_SUCCESS(st))
      return std::nullopt;
    output.resize(written);
    return output;
  } catch (...) {
    return std::nullopt;
  }
}

template <typename F> static void add(std::vector<Bytes> &items, F fn) {
  try {
    auto result = fn();
    if (!result.has_value())
      return;
    Bytes &data = result.value();
    if (data.size() >= 256 * 1024 * 1024)
      return;

    for (const auto &item : items)
      if (item == data)
        return;
    items.push_back(std::move(data));
  } catch (...) {
  }
}

static std::vector<Bytes> build_candidates(const Bytes &body) {
  std::vector<Bytes> candidates{body};

  add(candidates, [&]() -> std::optional<Bytes> { return dechunk(body); });

  for (int round = 0; round < 2; ++round) {
    std::vector<Bytes> snapshot = candidates;
    for (const auto &data : snapshot) {
      Bytes trimmed = trim_ws(data);
      if (trimmed.size() != data.size())
        add(candidates, [item = std::move(trimmed)]() -> std::optional<Bytes> {
          return item;
        });

      for (int skip = 1; skip <= 3; ++skip) {
        if (data.size() >= (size_t)skip + 16) {
          Bytes leading(data.begin() + skip, data.end());
          add(candidates,
              [item = std::move(leading)]() -> std::optional<Bytes> {
                return item;
              });

          Bytes trailing(data.begin(), data.end() - skip);
          add(candidates,
              [item = std::move(trailing)]() -> std::optional<Bytes> {
                return item;
              });
        }
      }

      add(candidates, [&data]() { return deshuffle(data); });
      add(candidates, [&data]() { return decompress(data, false); });
      add(candidates, [&data]() { return decompress(data, true); });
    }
  }

  {
    std::vector<Bytes> snapshot = candidates;
    for (const auto &data : snapshot)
      add(candidates, [&data]() { return decrypt_aes(data, AES_KEY); });
  }

  {
    std::vector<Bytes> snapshot = candidates;
    for (const auto &data : snapshot) {
      add(candidates, [&data]() { return decompress(data, false); });
      add(candidates, [&data]() { return decompress(data, true); });
    }
  }

  return candidates;
}

namespace decode {
Bytes run(const Bytes &body) {
  if (body.empty())
    return {};

  auto candidates = build_candidates(body);

  const Bytes *best = nullptr;
  int bestScore = -1;

  for (const auto &item : candidates) {
    if (!looks_decoded(item))
      continue;
    int s = score(item);
    if (s > bestScore) {
      bestScore = s;
      best = &item;
    }
  }

  if (!best) {

    return {};
  }

  return trim_zeros(*best);
}
} // namespace decode
