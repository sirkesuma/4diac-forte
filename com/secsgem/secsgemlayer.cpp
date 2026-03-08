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

#include "secsgemlayer.h"
#include "secsgemparser.h"
#include "forte/util/devlog.h"
#include <string.h>
#include "forte/cominfra/basecommfb.h"
#include "secsgemhandler.h"
#include "forte/cominfra/comtypes.h"
#include "forte/util/string_utils.h"
#include "forte/cominfra/comlayersmanager.h"
#include "secsgemtypes.h"
#include <forte/iec61131_functions.h>
#include <regex>

using namespace std::literals;
using namespace forte::literals;

namespace forte::com_infra::secsgem {
  namespace {
    [[maybe_unused]] const ComLayerManager::EntryImpl<CSecsgemComLayer> entry("secsgem"_STRID);
  }

  CSecsgemComLayer::CSecsgemComLayer(CComLayer *paUpperLayer, CBaseCommFB *paComFB) :
      CComLayer(paUpperLayer, paComFB),
      mInterruptResp(e_Nothing),
      mCorrectlyInitialized(false) {
    mDeviceId = 0;
    mExpectedStream = 0;
    mExpectedFunction = 0;
    mSessionType = e_Data;
  }

  CSecsgemComLayer::~CSecsgemComLayer() {
    closeConnection();
  }

  EComResponse CSecsgemComLayer::openConnection(char *paLayerParameter) {
    EComResponse eRetVal = e_InitInvalidId;
    if (checkSDsAndRDsType()) {
      switch (mFb->getComServiceType()) {
        case e_Server: eRetVal = initActiveListenLayer(paLayerParameter); break;
        case e_Client: eRetVal = initActiveSendLayer(paLayerParameter); break;
        default:
          // e_Publisher and e_Subscriber
          eRetVal = e_ProcessDataInvalidObject;
          break;
      }
    }
    mCorrectlyInitialized = (eRetVal == e_InitOk);
    return eRetVal;
  }

  EComResponse CSecsgemComLayer::initActiveSendLayer(char *paLayerParameter) {
    EComResponse eRetVal = e_InitInvalidId;
    util::CParameterParser parser(paLayerParameter, ';', 4); // IP:PORT;DeviceId;Mode[;session-type | ;SxFy]
    if (handleSession(parser, parser.parseParameters()) && handleAddress(parser[0])) {
      if (getExtEvHandler<CSecsgemHandler>().initActiveConnection(
              mHsmsSettings)) // call handler initActiveConnection for send layer;
        eRetVal = e_InitOk;
    }
    return eRetVal;
  }

  EComResponse CSecsgemComLayer::initActiveListenLayer(char *paLayerParameter) {
    EComResponse eRetVal = e_InitInvalidId;
    util::CParameterParser parser(paLayerParameter, ';', 4); // IP:PORT;DeviceId;Mode[;session-type | ;SxFy]
    if (handleSession(parser, parser.parseParameters()) && handleAddress(parser[0])) {
      if (getExtEvHandler<CSecsgemHandler>().initActiveConnection(
              mHsmsSettings, this, mSessionType, mExpectedStream,
              mExpectedFunction)) // call handler initActiveConnection for listen layer;
        eRetVal = e_InitOk;
    }
    return eRetVal;
  }

  bool CSecsgemComLayer::checkSDsAndRDsType() const {
    for (size_t i = 2; i < mFb->getNumSD(); i++) {
      CIEC_ANY::EDataTypeID typeToCheck = mFb->getDI(static_cast<unsigned int>(i))->getDataTypeID();
      if (CIEC_ANY::e_ANY != typeToCheck && CIEC_ANY::e_STRING != typeToCheck && CIEC_ANY::e_WSTRING != typeToCheck) {
        DEVLOG_ERROR("[SECS/GEM Layer] FB named %s has an invalid SD_%d\n", mFb->getInstanceNameId().data(), i);
        return false;
      }
    }
    for (size_t i = 2; i < mFb->getNumRD(); i++) {
      CIEC_ANY::EDataTypeID typeToCheck = mFb->getDO(static_cast<unsigned int>(i))->getDataTypeID();
      if (CIEC_ANY::e_ANY != typeToCheck && CIEC_ANY::e_STRING != typeToCheck && CIEC_ANY::e_WSTRING != typeToCheck) {
        DEVLOG_ERROR("[SECS/GEM Layer] FB named %s has an invalid RD_%d\n", mFb->getInstanceNameId().data(), i);
        return false;
      }
    }
    return true;
  }

  bool CSecsgemComLayer::handleSession(util::CParameterParser &paParser, size_t paNoOfParameters) {
    bool everythingOK = true;

    if (2 < paNoOfParameters) {
      mDeviceId = static_cast<TForteUInt16>(util::strtoul(paParser[1], nullptr, 10));

      auto mode = std::string(paParser[2]);
      std::transform(mode.begin(), mode.end(), mode.begin(), [](unsigned char c) { return std::tolower(c); });

      if ("passive" == mode) {
        mHsmsSettings.mMode = e_Passive;
      } else if ("active" == mode) {
        mHsmsSettings.mMode = e_Active;
      } else {
        everythingOK = false;
        DEVLOG_ERROR(
            "[SECS/GEM Layer] Wrong parameters. It should be as IP:PORT;DeviceId;Mode[;session-type | ;SxFy]\n");
      }
      mSessionType = e_Data;

      if (3 < paNoOfParameters) {
        std::regex sxfyRegex(R"(^S(\d+)F(\d+)$)");
        std::smatch matches;

        if (!std::regex_match(std::string(paParser[3]), sxfyRegex)) {
          std::string toCheck = std::string(paParser[3]);

          if (toCheck == "select.req") {
            mSessionType = e_SelectReq;
          } else if (toCheck == "select.rsp") {
            mSessionType = e_SelectRsp;
          } else if (toCheck == "deselect.req") {
            mSessionType = e_DeselectReq;
          } else if (toCheck == "deselect.rsp") {
            mSessionType = e_DeselectRsp;
          } else if (toCheck == "linktest.req") {
            mSessionType = e_LinktestReq;
          } else if (toCheck == "linktest.rsp") {
            mSessionType = e_LinktestRsp;
          } else if (toCheck == "separate.req") {
            mSessionType = e_SeparateReq;
          } else if (toCheck == "data") {
            mSessionType = e_Data;
          } else {
            everythingOK = false;
            DEVLOG_ERROR(
                "[SECS/GEM Layer] Wrong session type. It should be select.req|select.rsp|deselect.req|linktest.req|"
                "linktest.rsp|separate.req|data \n");
          }
        } else {
          auto toMatch = std::string(paParser[3]);
          if (std::regex_match(toMatch, matches, sxfyRegex)) {
            mExpectedStream = std::stoi(matches[1].str());
            mExpectedFunction = std::stoi(matches[2].str());
          }
        }
      }
    } else {
      everythingOK = false;
      DEVLOG_ERROR("[SECS/GEM Layer] Wrong parameters. It should be as IP:PORT;DeviceId;Mode[;session-type | ;SxFy]\n");
    }
    return everythingOK;
  }

  bool CSecsgemComLayer::handleAddress(const char *paAddress) {
    bool everythingOK = true;
    // look for parameters
    std::string addressToParse(paAddress);
    util::CParameterParser portParser(addressToParse.c_str(), ':', 2);
    if (2 == portParser.parseParameters()) {
      mHsmsSettings.mHost = std::string(portParser[0]);
      mHsmsSettings.mPort = static_cast<TForteUInt16>(util::strtoul(portParser[1], nullptr, 10));
    } else { // if not defined, use default port.
      mHsmsSettings.mHost = std::string(portParser[0]);
      mHsmsSettings.mPort = 5000;
      DEVLOG_INFO("[SECS/GEM Layer] No port was found on the parameter, using default 5000\n");
    }
    return everythingOK;
  }

  EComResponse CSecsgemComLayer::sendData(void *paData, unsigned int) {
    mInterruptResp = e_Nothing;
    if (mCorrectlyInitialized) {
      switch (mFb->getComServiceType()) {
        // case e_Server: break;
        case e_Client: sendRequest(paData); break;
        default:
          // e_Publisher and e_Subscriber
          break;
      }
    } else {
      DEVLOG_ERROR("[SECS/GEM Layer]The FB is not initialized\n");
    }
    return mInterruptResp;
  }

  void CSecsgemComLayer::sendRequest(void *paData) {
    std::string smlMessage = "";
    if (mSessionType == e_Data) {
      if (CIEC_ANY::e_WSTRING == getSDx(paData, 0).getDataTypeID()) {
        smlMessage = static_cast<const CIEC_WSTRING &>(getSDx(paData, 0)).getValue();
      } else if (CIEC_ANY::e_STRING == getSDx(paData, 0).getDataTypeID()) {
        smlMessage = static_cast<const CIEC_STRING &>(getSDx(paData, 0)).getStorage();
      }
    }
    if (getExtEvHandler<CSecsgemHandler>().sendData(mHsmsSettings, this, smlMessage, mSessionType)) {
      mInterruptResp = e_ProcessDataOk;
    } else {
      mInterruptResp = e_ProcessDataSendFailed;
      DEVLOG_ERROR("[SECS/GEM Layer] Sending message failed.\n");
    }
  }

  EComResponse CSecsgemComLayer::recvData(const void *paData, unsigned int paSize) {
    mInterruptResp = e_Nothing;
    if (mCorrectlyInitialized) {
      auto *data = reinterpret_cast<const std::vector<std::byte> *>(paData);
      switch (mFb->getComServiceType()) {
        case e_Server:
          // To be handled.
          break;
        case e_Client: {
          if (paData == nullptr) { // timeout occured
            mInterruptResp = e_ProcessDataRecvFaild;
          } else {
            if (paSize == 0) {
              mInterruptResp = e_ProcessDataOk;
            }
            mInterruptResp = receiveMessage(data);
          }
          break;
        }
      }
    } else {
      DEVLOG_ERROR("[SECS/GEM Layer] The FB is not initialized\n");
    }
    if (e_ProcessDataOk == mInterruptResp) {
      mFb->interruptCommFB(this);
    }
    return mInterruptResp;
  }

  EComResponse CSecsgemComLayer::receiveMessage(const std::vector<std::byte> *paData) {
    EComResponse eRetval = e_ProcessDataInvalidObject;

    if (paData->size() >= 10) {
      mRecvBuffer.resize(paData->size());
      memcpy(mRecvBuffer.data(), paData->data(), paData->size());
      auto header = std::span(mRecvBuffer).subspan(0, 10);
      auto receivedSessionType = CSecsgemParser::parseSessionType(header);

      CIEC_ANY **apoRDs = mFb->getRDs();

      switch (mSessionType) {
        case e_Data: {
          auto outMessage = CSecsgemParser::decodeMessage(mRecvBuffer);
          if (outMessage != "") {
            apoRDs[0]->setValue(CIEC_STRING(outMessage));
            eRetval = e_ProcessDataOk;
          } else {
            eRetval = e_ProcessDataInvalidObject;
          }         
          break;
        }
        case e_SelectReq: {
          if (receivedSessionType == e_SelectRsp) {
            eRetval = e_ProcessDataOk;
            DEVLOG_INFO("[SECS/GEM Layer] Received Control Message: select.rsp\n");
          } else {
            eRetval = e_ProcessDataInhibited;
          }
          break;
        }
      }
    }
    return eRetval;
  }

  EComResponse CSecsgemComLayer::processInterrupt() {
    mInterruptResp = e_ProcessDataOk;
    return mInterruptResp;
  }

  void CSecsgemComLayer::closeConnection() {
    // To be handled
  }
} // namespace forte::com_infra::secsgem
