/*******************************************************************************
 * Copyright (c) 2026 Edo Kesuma, github.com/sirkesuma
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0.
 *
 * SPDX-License-Identifier: EPL-2.0
 *
 * Contributors:
 *    Edo Kesuma - initial implementation for SECS/GEM communication
 ********************************************************************************/

#include "secsgemparser.h"

#include <stdio.h>
#include <string.h>
#include <variant>
#include <vector>
#include <string_view>
#include <cctype>
#include <string>
#include <charconv>
#include <iomanip>
#include <bit>
#include <span>

#include "forte/datatype.h"
#include "forte/util/devlog.h"
#include "forte/util/parameterParser.h"

using namespace std::string_literals;

namespace forte::com_infra::secsgem {

  TForteUInt32 CSecsgemParser::parseSystemBytes(const std::vector<std::byte> &paData) {
    TForteUInt32 value = 0;
    if (paData.size() < 10)
      return 0;

    auto bytes = std::span(paData).subspan(6, 4);

    if (!bigEndianBytesToNumber(bytes, value))
      return 0;

    return value;
  }

  TForteUInt32 CSecsgemParser::parseMessageLength(const std::vector<std::byte> &paData) {
    TForteUInt32 value = 0;
    if (paData.size() < 4)
      return 0;

    if (!bigEndianBytesToNumber(paData, value))
      return 0;

    return value;
  }

  TForteUInt16 CSecsgemParser::parseDeviceId(const std::vector<std::byte> &paData) {
    TForteUInt16 value = 0;
    if (paData.size() < 2)
      return 0;

    if (!bigEndianBytesToNumber(paData, value))
      return 0;

    return value;
  }

  ESType CSecsgemParser::parseSType(const std::vector<std::byte> &paData) {
    return static_cast<ESType>(paData[5]);
  }

  void CSecsgemParser::serializeMessage(HsmsMessage &paMessage) {
    paMessage.mPayload.assign(14, std::byte{0}); // Initialize space for Length bytes and Header bytes,

    // Parse SML message

    std::string_view msg = paMessage.mSmlMessage;
    size_t i = 0;

    i = msg.find_first_of("sS<", i);

    if (i != std::string::npos && tolower(msg[i]) == 's') {
      std::string_view str = scanNumeric(msg, ++i);
      i += str.size();
      parseNumber(str, &paMessage.mSecsStream);
    }

    if (i < msg.size() && std::tolower(msg[i]) == 'f') {
      std::string_view str = scanNumeric(msg, ++i);
      i += str.size();
      parseNumber(str, &paMessage.mSecsFunction);
    }

    i = msg.find_first_of("wW<", i);
    if (i != std::string::npos && tolower(msg[i]) == 'w') {
      paMessage.mWBit = true;
      i = msg.find_first_of("<", i);
    }

    if (msg[i] == '<') {
      auto tokens = smlLexer(msg.substr(i, msg.size() - i));
      size_t start = 0;
      smlItemParser(tokens, start, paMessage.mPayload);
    }

    // Serializing Header

    auto header = std::span(paMessage.mPayload).subspan(4, 10);

    auto deviceId = numberToBigEndianBytes(paMessage.mDeviceId);
    std::copy(deviceId.begin(), deviceId.end(), header.begin());

    header[2] = static_cast<std::byte>(paMessage.mSecsStream);
    if (paMessage.mWBit)
      header[2] |= std::byte{1} << 7;

    header[3] = static_cast<std::byte>(paMessage.mSecsFunction);

    header[4] = static_cast<std::byte>(paMessage.mPType);

    header[5] = static_cast<std::byte>(static_cast<uint8_t>(paMessage.mSType));

    auto systemBytes = numberToBigEndianBytes(paMessage.mSystemBytes);
    std::copy(systemBytes.begin(), systemBytes.end(), header.begin() + 6);

    TForteUInt32 msgLen = paMessage.mPayload.size() - 4; // Header + Message Length, exclude the length bytes itself.

    auto length = numberToBigEndianBytes(msgLen);
    std::copy(length.begin(), length.end(), paMessage.mPayload.begin());
  }

  void CSecsgemParser::parseMessage(HsmsMessage &paMessage) {
    auto header = std::span(paMessage.mPayload).subspan(0, 10);

    paMessage.mDeviceId = parseDeviceId(paMessage.mPayload);
    paMessage.mWBit = (header[2] & std::byte{0x80}) != std::byte{0};
    paMessage.mSecsStream = static_cast<TForteUInt8>(header[2] & std::byte{0x7F});
    paMessage.mSecsFunction = static_cast<TForteUInt8>(header[3]);
    paMessage.mPType = static_cast<TForteUInt8>(header[4]);
    paMessage.mSType = parseSType(paMessage.mPayload);
    paMessage.mSystemBytes = parseSystemBytes(paMessage.mPayload);

    std::byte *text = paMessage.mPayload.data() + 10;

    // Add program for parsing message text here.
    paMessage.mMessageText.resize(paMessage.mPayload.size() - 10);
    memcpy(paMessage.mMessageText.data(), paMessage.mPayload.data() + 10, paMessage.mPayload.size() - 10);
  }

  // SML to SECS-II Lexer & Parsing

  std::vector<CSecsgemParser::SmlToken> CSecsgemParser::smlLexer(std::string_view paSmlMessage) {
    std::vector<SmlToken> smlLexer;

    int i = 0;

    while (i < paSmlMessage.size()) {
      char c = paSmlMessage[i];
      switch (c) {
        case '<': {
          appendToken(smlLexer, e_Punctuator, e_LABrace);
          break;
        }
        case '>': {
          appendToken(smlLexer, e_Punctuator, e_RABrace);
          break;
        }
        case '[': {
          appendToken(smlLexer, e_Punctuator, e_LBBrace);
          break;
        }
        case ']': {
          appendToken(smlLexer, e_Punctuator, e_RBBrace);
          break;
        }
        case '.': {
          appendToken(smlLexer, e_Punctuator, e_End);
          break;
        }
        case '"': {
          std::string_view str = scanString(paSmlMessage, i);
          i = i + str.size();
          appendToken(smlLexer, e_Literal, str);
          continue;
        }
        default: {
          if (isalpha(c)) { // Keyword
            std::string_view str = scanAlphanumeric(paSmlMessage, i);
            i = i + str.size();
            appendToken(smlLexer, e_Keyword, stringToFormat(str));
            continue;
          } else if (isdigit(c) || c == '-') {
            if (paSmlMessage[i] == '0' && tolower(paSmlMessage[i + 1]) == 'x') { // Hex Number
              std::string_view str = scanAlphanumeric(paSmlMessage, i);
              i = i + str.size();
              appendToken(smlLexer, e_Literal, str);
              continue;
            } else { // Decimal Number
              std::string_view str = scanNumeric(paSmlMessage, i);
              i = i + str.size();
              appendToken(smlLexer, e_Literal, str);
              continue;
            }
          }
          break;
        }
      }
      i++;
    }
    return smlLexer;
  }

  bool CSecsgemParser::smlItemParser(std::vector<CSecsgemParser::SmlToken> paTokens,
                                     size_t &paOffset,
                                     std::vector<std::byte> &paBuffer) {
    size_t &i = paOffset;

    if (!isLeftAngleBrace(paTokens[i])) // Check opening bracket '<'
      return false;

    if (!paTokens[++i].mType == e_Keyword) { // Check for keyword after opening bracket
      return false;
    }

    EKeyword keyword = std::get<EKeyword>(paTokens[i].mLexeme); // Get keyword
    paBuffer.push_back(static_cast<std::byte>(keyword));

    size_t idx = paBuffer.size();

    int explicitCount = -1;

    if (isLeftBoxBrace(paTokens[++i])) { // Handle explicit count
      if (!(paTokens[++i].mType == e_Literal))
        return false;
      parseNumber(std::get<std::string_view>(paTokens[i++].mLexeme), &explicitCount);
      if (!isRightBoxBrace(paTokens[i++]))
        return false;
    }

    int implicitCount = 0;
    while (i < paTokens.size()) {
      if (isRightAngleBrace(paTokens[i]))
        break;

      if (keyword == e_L) {
        if (!smlItemParser(paTokens, i, paBuffer))
          return false;
        i++;
        implicitCount++;
        continue;
      }

      if (paTokens[i].mType != e_Literal)
        return false;

      std::string_view str = std::get<std::string_view>(paTokens[i].mLexeme);

      switch (keyword) {
        case e_A: {
          if (!(str[0] == '"' && str[str.size() - 1] == '"'))
            return false;

          str.remove_prefix(1);
          str.remove_suffix(1);
          const auto *begin = reinterpret_cast<const std::byte *>(str.data());
          const auto *end = begin + str.size();

          paBuffer.insert(paBuffer.end(), begin, end);
          implicitCount += str.size();

          if (paTokens[i + 1].mType == e_Literal) { // Add new line.
            paBuffer.push_back(std::byte{0x0A});
            paBuffer.push_back(std::byte{0x0D});
          }
          break;
        }
        case e_B: {
          if (!((str[0] == '0' && tolower(str[1]) == 'x') && str.size() == 4))
            return false;

          if (!parseAndAppend<uint8_t>(str, paBuffer))
            return false;
          break;
        }
        case e_U8: {
          if (!parseAndAppend<uint64_t>(str, paBuffer))
            return false;
          break;
        }
        case e_U1: {
          if (!parseAndAppend<uint8_t>(str, paBuffer))
            return false;
          break;
        }
        case e_U2: {
          if (!parseAndAppend<uint16_t>(str, paBuffer))
            return false;
          break;
        }
        case e_U4: {
          if (!parseAndAppend<uint32_t>(str, paBuffer))
            return false;
          break;
        }
        case e_I8: {
          if (!parseAndAppend<int64_t>(str, paBuffer))
            return false;
          break;
        }
        case e_I1: {
          if (!parseAndAppend<int8_t>(str, paBuffer))
            return false;
          break;
        }
        case e_I2: {
          if (!parseAndAppend<int16_t>(str, paBuffer))
            return false;
          break;
        }
        case e_I4: {
          if (!parseAndAppend<int32_t>(str, paBuffer))
            return false;
          break;
        }
        case e_F4: {
          if (!parseAndAppend<float>(str, paBuffer))
            return false;
          break;
        }
        case e_F8: {
          if (!parseAndAppend<double>(str, paBuffer))
            return false;
          break;
        }
      }
      if (keyword != e_A)
        implicitCount++;
      i++;
    }

    if (explicitCount >= 0 && explicitCount != implicitCount)
      return false;

    uint32_t dataSize = (keyword == e_L) ? implicitCount : paBuffer.size() - idx;
    auto lengthBytes = numberToBigEndianBytes(dataSize);
    if (dataSize <= 0xFF) {
      paBuffer[idx - 1] |= std::byte{0x01};
      paBuffer.insert(paBuffer.begin() + idx, lengthBytes.end() - 1, lengthBytes.end());
    } else if (0xFF < dataSize && dataSize <= 0xFFFF) {
      paBuffer[idx - 1] |= std::byte{0x02};
      paBuffer.insert(paBuffer.begin() + idx, lengthBytes.end() - 2, lengthBytes.end());

    } else if (0xFFFF < dataSize && dataSize <= 0xFFFFFF) {
      paBuffer[idx - 1] |= std::byte{0x03};
      paBuffer.insert(paBuffer.begin() + idx, lengthBytes.end() - 3, lengthBytes.end());
    }

    if (i < paTokens.size() && isRightAngleBrace(paTokens[i]))
      return true;

    return false;
  }
  // Helper functions

  std::string_view CSecsgemParser::scanAlphanumeric(std::string_view paString, int paOffset) {
    int i = paOffset;
    while (i < paString.size() && isalnum(paString[i])) {
      i++;
    };
    return paString.substr(paOffset, i - paOffset);
  }

  std::string_view CSecsgemParser::scanNumeric(std::string_view paString, int paOffset) {
    int i = paString[paOffset] != '-' ? paOffset : paOffset + 1;
    while (i < paString.size() && (isdigit(paString[i]) || paString[i] == '.')) {
      i++;
    };
    return paString.substr(paOffset, i - paOffset);
  }

  std::string_view CSecsgemParser::scanString(std::string_view paString, int paOffset) {
    if (paOffset >= paString.size() || paString[paOffset] != '"') {
      return "";
    }

    int i = paOffset + 1;
    bool isEscaped = false;

    while (i < paString.size()) {
      if (isEscaped) {
        isEscaped = false;
      } else if (paString[i] == '\\') {
        isEscaped = true;
      } else if (paString[i] == '"') {
        return paString.substr(paOffset, (i - paOffset) + 1);
      }
      i++;
    }
    return paString.substr(paOffset);
  }

  template<std::integral T>
  bool CSecsgemParser::parseNumber(std::string_view paString, T *paResult) {
    T value;
    int base = 10;

    if (paString.size() > 2 && paString[0] == '0' && tolower(paString[1]) == 'x') {
      base = 16;
      paString.remove_prefix(2);
    }

    auto [ptr, ec] = std::from_chars(paString.data(), paString.data() + paString.size(), value, base);

    if (ec == std::errc{}) {
      if (paResult)
        *paResult = value;
      return true;
    }
    return false;
  }

  template<std::floating_point T>
  bool CSecsgemParser::parseNumber(std::string_view paString, T *paResult) {
    T value;

    auto [ptr, ec] = std::from_chars(paString.data(), paString.data() + paString.size(), value);

    if (ec == std::errc{}) {
      if (paResult)
        *paResult = value;
      return true;
    }
    return false;
  }

  template<typename T>
  std::vector<std::byte> CSecsgemParser::numberToBigEndianBytes(T paValue) {
    const std::byte *ptr = reinterpret_cast<const std::byte *>(&paValue);
    std::vector<std::byte> result(ptr, ptr + sizeof(T));

    if constexpr (std::endian::native == std::endian::little) {
      std::reverse(result.begin(), result.end());
    }
    return result;
  }

  template<typename T>
  bool CSecsgemParser::bigEndianBytesToNumber(std::span<const std::byte> paBuffer, T &paResult) {
    if (paBuffer.size() < sizeof(T)) {
      return false;
    }

    T result;
    std::memcpy(&result, paBuffer.data(), sizeof(T));

    if constexpr (std::endian::native == std::endian::little) {
      auto *ptr = reinterpret_cast<std::byte *>(&result);
      std::reverse(ptr, ptr + sizeof(T));
    }

    paResult = result;
    return true;
  }

  template<typename T>
  bool CSecsgemParser::parseAndAppend(std::string_view paString, std::vector<std::byte> &paBuffer) {
    T value;
    if (!parseNumber(paString, &value))
      return false;

    auto bytes = numberToBigEndianBytes(value);
    paBuffer.insert(paBuffer.end(), bytes.begin(), bytes.end());
    return true;
  }

  template<typename T>
  T forte::com_infra::secsgem::CSecsgemParser::decodeItem(std::span<const std::byte> paBuffer) {
    if constexpr (std::is_same_v<T, CIEC_BYTE>) {
      uint8_t var;
      bigEndianBytesToNumber(paBuffer, var);
      return CIEC_BYTE(var);
    }
    if constexpr (std::is_same_v<T, CIEC_BOOL>) {
      uint8_t var;
      bigEndianBytesToNumber(paBuffer, var);
      return CIEC_BOOL(var);
    }
    if constexpr (std::is_same_v<T, CIEC_INT>) {
      int16_t var;
      bigEndianBytesToNumber(paBuffer, var);
      return CIEC_INT(var);
    }
    if constexpr (std::is_same_v<T, CIEC_DINT>) {
      int32_t var;
      bigEndianBytesToNumber(paBuffer, var);
      return CIEC_DINT(var);
    }
    if constexpr (std::is_same_v<T, CIEC_USINT>) {
      uint8_t var;
      bigEndianBytesToNumber(paBuffer, var);
      return CIEC_USINT(var);
    }
    if constexpr (std::is_same_v<T, CIEC_UINT>) {
      uint16_t var;
      bigEndianBytesToNumber(paBuffer, var);
      return CIEC_UINT(var);
    }
    if constexpr (std::is_same_v<T, CIEC_UDINT>) {
      uint32_t var;
      bigEndianBytesToNumber(paBuffer, var);
      return CIEC_UDINT(var);
    }
    if constexpr (std::is_same_v<T, CIEC_STRING>) {
      std::string var(reinterpret_cast<const char *>(paBuffer.data()), paBuffer.size());
      return CIEC_STRING(var);
    }
  }

  bool CSecsgemParser::deserializeMessageText(const std::vector<std::byte> &paBytes,
                                              size_t &paOffset,
                                              std::vector<DataItem> &paItems) {
    size_t &i = paOffset;
    DataItem item;
    item.mType = static_cast<EKeyword>(paBytes[i] & std::byte{0b1111'1100});
    uint8_t lengthByteSize = static_cast<size_t>(paBytes[i] & std::byte{0b0000'0011});

    i++;

    switch (lengthByteSize) {
      case 1: {
        item.mSize = std::to_integer<size_t>(paBytes[i]);
        i++;
        break;
      }
      case 2: {
        item.mSize = std::to_integer<size_t>(paBytes[i]) << 8 | std::to_integer<size_t>(paBytes[i + 1]);
        i += 2;
        break;
      }
      case 3: {
        item.mSize = std::to_integer<size_t>(paBytes[i]) << 16 | std::to_integer<size_t>(paBytes[i + 1]) << 8 |
                     std::to_integer<size_t>(paBytes[i + 2]);
        i += 3;
        break;
      }
      default: return false;
    }

    if (item.mType == e_L) { // perform recursive for list
      paItems.push_back(item);
      for (int j = 0; j < item.mSize; j++) {
        deserializeMessageText(paBytes, i, paItems);
      }

    } else {
      item.mData = std::span(paBytes).subspan(i, item.mSize);
      paItems.push_back(item);
      i += item.mSize;
    }
    return true;
  }
} // namespace forte::com_infra::secsgem
