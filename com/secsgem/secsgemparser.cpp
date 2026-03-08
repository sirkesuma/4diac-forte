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

  ESType CSecsgemParser::parseSessionType(const std::span<std::byte> paHeader) {
    ESType sessionType = e_InvalidSession;
    if (paHeader.size() == 10) {
      if (paHeader[5] < std::byte{0x8} || paHeader[5] == std::byte{0x9}) {
        sessionType = static_cast<ESType>(paHeader[5]);
      }
    }
    return sessionType;
  }

  TForteUInt16 CSecsgemParser::parseDeviceId(const std::span<std::byte> paHeader) {
    TForteUInt16 value = 0;
    if (paHeader.size() == 10) {
      auto bytes = paHeader.subspan(0, 2);
      if (!bigEndianBytesToNumber(bytes, value))
        value = 0;
    }
    return value;
  }

  TForteUInt32 CSecsgemParser::parseSystemBytes(const std::span<std::byte> paHeader) {
    TForteUInt32 value = 0;
    if (paHeader.size() == 10) {
      auto bytes = std::span(paHeader).subspan(6, 4);
      if (!bigEndianBytesToNumber(bytes, value))
        value = 0;
    }
    return value;
  }

  TForteUInt8 CSecsgemParser::parseSecsStream(const std::span<std::byte> paHeader) {
    TForteUInt8 value = 0;
    if (paHeader.size() == 0) {
      value = static_cast<uint8_t>(paHeader[2] & std::byte{0b0111'1111});
    }
    return value;
  }

  TForteUInt8 CSecsgemParser::parseSecsFunction(const std::span<std::byte> paHeader) {
    TForteUInt8 value = 0;
    if (paHeader.size() == 10) {
      value = static_cast<uint8_t>(paHeader[3]);
    }
    return value;
  }

  bool CSecsgemParser::parseWaitBit(const std::span<std::byte> paHeader) {
    auto byte2 = paHeader[2];
    auto wbit = (byte2 & std::byte{0b1000'0000}) >> 7;
    if (wbit == std::byte(0x01)) {
      return true;
    }
    return false;
  }

  std::vector<std::byte> CSecsgemParser::encodeMessage(ESType paSType,
                                                       TForteUInt32 paSystemBytes,
                                                       TForteUInt16 paDeviceId,
                                                       std::string_view paSmlMessage) {
    std::vector<std::byte> msg;
    msg.assign(14, std::byte{0}); // initial assignment for lengt + header bytes
    auto header = std::span(msg).subspan(4, 10);

    auto deviceId = numberToBigEndianBytes(paDeviceId);
    std::copy(deviceId.begin(), deviceId.end(), header.begin()); // set device ID

    header[5] = static_cast<std::byte>(paSType); // set session type

    auto systemBytes = numberToBigEndianBytes(paSystemBytes);
    std::copy(systemBytes.begin(), systemBytes.end(), header.begin() + 6); // set system bytes

    if (paSType == e_Data) {
      size_t i = 0;
      i = paSmlMessage.find_first_of("sS<", i);

      if (i != std::string::npos && tolower(paSmlMessage[i]) == 's') {
        std::string_view str = scanNumeric(paSmlMessage, ++i);
        i += str.size();
        TForteUInt8 stream;
        parseNumber(str, &stream);
        header[2] = static_cast<std::byte>(stream); // set secs stream
      }

      if (i < paSmlMessage.size() && std::tolower(paSmlMessage[i]) == 'f') {
        std::string_view str = scanNumeric(paSmlMessage, ++i);
        i += str.size();
        TForteUInt8 function;
        parseNumber(str, &function);
        header[3] = static_cast<std::byte>(function); // set secs function
      }

      i = paSmlMessage.find_first_of("wW<", i);
      if (i != std::string::npos && tolower(paSmlMessage[i]) == 'w') {
        header[2] |= std::byte{1} << 7; // set WBit
        i = paSmlMessage.find_first_of("<", i);
      }

      if (paSmlMessage[i] == '<') {
        auto tokens = smlLexer(paSmlMessage.substr(i, paSmlMessage.size() - i));
        size_t start = 0;
        smlItemParser(tokens, start, msg); // add message text
      }
    }

    TForteUInt32 msgLen = msg.size() - 4; // Header + Message Length, exclude the length bytes itself.
    auto length = numberToBigEndianBytes(msgLen);
    std::copy(length.begin(), length.end(), msg.begin()); // set message length

    return msg;
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
  void CSecsgemParser::bigEndianBytesToNumberString(std::span<const std::byte> paBuffer, std::string &paStr) {
    T value;
    bigEndianBytesToNumber(paBuffer, value);
    paStr = std::to_string(value);
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

  std::string CSecsgemParser::decodeMessage(const std::span<std::byte> paData) {
    std::string smlMessage;

    uint8_t stream = static_cast<uint8_t>(paData[2] & std::byte{0b0111'1111});
    smlMessage.append("S" + std::to_string(stream));

    uint8_t function = static_cast<uint8_t>(paData[3]);
    smlMessage.append("F" + std::to_string(function) + " ");

    if ((paData[2] & std::byte{0b1000'0000}) >> 7 == std::byte{0x01}) {
      smlMessage.append("[W] ");
    }

    size_t offset = 0;
    auto messageContent = std::span(paData).subspan(10, paData.size() - 10);
    if (!decodeSecs2(messageContent, offset, smlMessage))
      smlMessage.append(" .");
    return smlMessage;

    return "";
  }

  bool CSecsgemParser::decodeSecs2(const std::span<std::byte> paSecs2, size_t &paOffset, std::string &paSml) {
    size_t &i = paOffset;
    auto format = static_cast<EKeyword>(paSecs2[i] & std::byte{0b1111'1100});
    uint8_t numberOfLengthBytes = static_cast<uint8_t>(paSecs2[i] & std::byte{0b0000'0011});

    paSml.append("< ");
    paSml.append(formatToString(format));

    i++;

    uint32_t dataLength;
    switch (numberOfLengthBytes) {
      case 1: {
        dataLength = std::to_integer<size_t>(paSecs2[i]);
        i++;
        break;
      }
      case 2: {
        dataLength = std::to_integer<size_t>(paSecs2[i]) << 8 | std::to_integer<size_t>(paSecs2[i + 1]);
        i += 2;
        break;
      }
      case 3: {
        dataLength = std::to_integer<size_t>(paSecs2[i]) << 16 | std::to_integer<size_t>(paSecs2[i + 1]) << 8 |
                     std::to_integer<size_t>(paSecs2[i + 2]);
        i += 3;
        break;
      }
      default: return false;
    }

    auto formatSize = getFormatSize(format);
    paSml.append(" [" + std::to_string(dataLength / formatSize) + "] ");

    if (format == e_L) {
      for (int j = 0; j < dataLength; j++) {
        decodeSecs2(paSecs2, i, paSml);
      }
    } else if (format == e_A) {
      auto raw = std::span(paSecs2).subspan(i, dataLength);
      paSml.append("\"" + std::string(reinterpret_cast<const char *>(raw.data()), raw.size()) + "\"");
      i += dataLength;
    } else {
      for (int k = 0; k * formatSize < dataLength; k++) {
        std::string valStr;
        auto buffer = std::span(paSecs2).subspan(i, formatSize);
        switch (format) {
          case e_B: {
            bigEndianBytesToNumberString<uint8_t>(buffer, valStr);
            break;
          }
          case e_U1: {
            bigEndianBytesToNumberString<uint8_t>(buffer, valStr);
            break;
          }
          case e_U2: {
            bigEndianBytesToNumberString<uint16_t>(buffer, valStr);
            break;
          }
          case e_U4: {
            bigEndianBytesToNumberString<uint32_t>(buffer, valStr);
            break;
          }
          case e_I2: {
            bigEndianBytesToNumberString<int16_t>(buffer, valStr);
            break;
          }
          case e_I4: {
            bigEndianBytesToNumberString<int32_t>(buffer, valStr);
            break;
          }
          case e_F4: {
            bigEndianBytesToNumberString<float>(buffer, valStr);
            break;
          }
          case e_F8: {
            bigEndianBytesToNumberString<double>(buffer, valStr);
            break;
          }
        }
        paSml.append(" " + valStr);
        i += formatSize;
      }
    }

    paSml.append(" >");

    return false;
  }
} // namespace forte::com_infra::secsgem
