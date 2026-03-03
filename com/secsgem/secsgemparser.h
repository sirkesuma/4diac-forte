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

#pragma once

#include "forte/datatypes/forte_string.h"
#include "secsgemlayer.h"
#include "secsgemhandler.h"
#include "secsgemtypes.h"
#include <stdio.h>
#include <vector>
#include <variant>

namespace forte::com_infra::secsgem {

  class CSecsgemParser {
    public:
      static TForteUInt32 parseSystemBytes(const std::vector<std::byte> &paData);
      static TForteUInt32 parseMessageLength(const std::vector<std::byte> &paData);
      static TForteUInt16 parseDeviceId(const std::vector<std::byte> &paData);
      static ESType parseSType(const std::vector<std::byte> &paData);

      static void serializeMessage(HsmsMessage &paMessage);
      static void parseMessage(HsmsMessage &paMessage);

      template<typename T>
      static void parseData(const std::vector<std::byte> &paContent, CIEC_ANY *paData) {
        T data;
        size_t offset = 0;
        std::vector<DataItem> items;
        deserializeMessageText(paContent, offset, items);
        if (mapDataItem(items, data)) {
          if (nullptr != paData)
            paData->setValue(data);
        }
      }

    private:
      enum ETokenType { e_Punctuator, e_Keyword, e_Literal };
      enum EKeyword {
        e_L = 0x00,
        e_B = 0x20,
        e_BOOLEAN = 0x24,
        e_A = 0x40,
        e_J = 0x44,
        e_I8 = 0x60,
        e_I1 = 0x64,
        e_I2 = 0x68,
        e_I4 = 0x70,
        e_F8 = 0x80,
        e_F4 = 0x90,
        e_U8 = 0xA0,
        e_U1 = 0xA4,
        e_U2 = 0xA8,
        e_U4 = 0xB0,
        e_Invalid = 0xFF,
      };

      struct FormatPair {
          EKeyword mFormat;
          std::string_view mStr;
      };

      static constexpr std::array<FormatPair, 15> FormatPairs{{
          {EKeyword::e_L, "L"},
          {EKeyword::e_B, "B"},
          {EKeyword::e_BOOLEAN, "BOOLEAN"},
          {EKeyword::e_A, "A"},
          {EKeyword::e_J, "J"},
          {EKeyword::e_I8, "I8"},
          {EKeyword::e_I1, "I1"},
          {EKeyword::e_I2, "I2"},
          {EKeyword::e_I4, "I4"},
          {EKeyword::e_F8, "F8"},
          {EKeyword::e_F4, "F4"},
          {EKeyword::e_U8, "U8"},
          {EKeyword::e_U1, "U1"},
          {EKeyword::e_U2, "U2"},
          {EKeyword::e_U4, "U4"},
      }};

      static constexpr EKeyword stringToFormat(std::string_view paStr) {
        for (auto &&p : FormatPairs) {
          if (p.mStr == paStr)
            return p.mFormat;
        }
        return e_Invalid;
      }

      static constexpr std::string_view formatToString(EKeyword paFormat) {
        for (auto &&p : FormatPairs) {
          if (p.mFormat == paFormat)
            return p.mStr;
        }
        return {};
      }

      enum EPunctuator { e_LABrace, e_RABrace, e_LBBrace, e_RBBrace, e_End };

      struct SmlToken {
          ETokenType mType;
          std::variant<std::string_view, EKeyword, EPunctuator> mLexeme;
      };

      static std::vector<SmlToken> smlLexer(std::string_view paSmlMessage);

      static bool smlItemParser(std::vector<SmlToken> paTokens, size_t &paOffset, std::vector<std::byte> &paBuffer);

      static inline void appendToken(std::vector<SmlToken> &paToken,
                                     ETokenType paType,
                                     std::variant<std::string_view, EKeyword, EPunctuator> paLexeme) {
        SmlToken token = {paType, paLexeme};
        paToken.emplace_back(token);
      }

      static std::string_view scanAlphanumeric(std::string_view paString, int paOffset);

      static std::string_view scanNumeric(std::string_view paString, int paOffset);

      static std::string_view scanString(std::string_view paString, int paOffset);

      template<std::integral T>
      static bool parseNumber(std::string_view paString, T *paResult);

      template<std::floating_point T>
      static bool parseNumber(std::string_view paString, T *paResult);

      template<typename T>
      static std::vector<std::byte> numberToBigEndianBytes(T paValue);

      template<typename T>
      static bool bigEndianBytesToNumber(std::span<const std::byte> paBuffer, T &paResult);

      template<typename T>
      static bool parseAndAppend(std::string_view paString, std::vector<std::byte> &paBuffer);

      template<typename T>
      static T decodeItem(std::span<const std::byte> paBuffer);

      static inline bool isPunctuator(const SmlToken &paToken, EPunctuator paPunctuator) {
        if (paToken.mType != e_Punctuator)
          return false;
        return (std::get<EPunctuator>(paToken.mLexeme) == paPunctuator);
      }

      static inline bool isLeftAngleBrace(const SmlToken &paToken) {
        return isPunctuator(paToken, e_LABrace);
      }

      static inline bool isRightAngleBrace(const SmlToken &paToken) {
        return isPunctuator(paToken, e_RABrace);
      }

      static inline bool isLeftBoxBrace(const SmlToken &paToken) {
        return isPunctuator(paToken, e_LBBrace);
      }

      static inline bool isRightBoxBrace(const SmlToken &paToken) {
        return isPunctuator(paToken, e_RBBrace);
      }

      struct DataItem {
          EKeyword mType;
          TForteUInt32 mSize;
          std::span<const std::byte> mData;
      };

      static bool
      deserializeMessageText(const std::vector<std::byte> &paBytes, size_t &paOffset, std::vector<DataItem> &paItems);
  };
} // namespace forte::com_infra::secsgem
