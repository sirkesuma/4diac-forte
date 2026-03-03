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
     mMaxAllowed(1024 * 1024), //Maximum allowed message length set as 1MB
     mCorrectlyInitialized(false) {
     mMessage.mDeviceId = 0;
     mMessage.mWBit = false;
     mMessage.mSecsStream = 0;
     mMessage.mSecsFunction = 0;
     mMessage.mPType = 0;
     mMessage.mSType = e_Data;
     mMessage.mSystemBytes = 0;
   }

  CSecsgemComLayer::~CSecsgemComLayer() {
    closeConnection();
  }

  EComResponse CSecsgemComLayer::openConnection(char* paLayerParameter) {
    EComResponse eRetVal = e_InitInvalidId;
    if (checkSDsAndRDsType()) {
      switch (mFb->getComServiceType()) {
        //case e_Server: eRetVal = startServer(paLayerParameter); break;
        case e_Client: eRetVal = openClientConnection(paLayerParameter); break;
        case e_Subscriber: eRetVal = registerClientSubscription(paLayerParameter); break;
        default:
          // e_Publisher and e_Subscriber
          eRetVal = e_ProcessDataInvalidObject;
          break;
      }
    }
    mCorrectlyInitialized = (eRetVal == e_InitOk);
    return eRetVal;
  }

  EComResponse CSecsgemComLayer::openClientConnection(char *paLayerParameter) {
    EComResponse eRetVal = e_InitInvalidId;

    util::CParameterParser parser(paLayerParameter, ';', 4); // IP:PORT;DeviceId[;procedure-type][;SxFy | ;system-bytes]
    handleSession(parser, parser.parseParameters());
    handleAddress(parser[0]);
    
    if (0 == mFb->getNumRD() && 0 == mFb->getNumSD()) { // For Select, Deselect, Linktest request
      switch (mMessage.mSType) {       
        case e_SelectReq: 
        {
          auto &handler = getExtEvHandler<CSecsgemHandler>();
          if (!handler.openClientConnection(mHsmsSettings))
            break;

          auto sb = handler.getSystemBytes(mHsmsSettings);

          if (sb > 0) {
            mMessage.mDeviceId = 0xFFFF;
            mMessage.mSystemBytes = sb;
            CSecsgemParser::serializeMessage(mMessage);
          }
          else {
            break;
          }
          if (!handler.sendClientData(this, mMessage.mPayload, true))
            break;
          DEVLOG_INFO("Sent Control message: select.req.\n");
          if (!isControlResponseReceived())
            break;
          if (mResponse.mSType == e_SelectRsp) {
            eRetVal = e_InitOk;
            handler.setConnectionState(mHsmsSettings, e_Selected);
          }
            
          break;
        }          
        case e_DeselectReq: break;
        case e_LinktestReq: break;
        case e_SeparateReq: break;
      }    
    }

    else if (2 == mFb->getNumRD() && 0 == mFb->getNumSD()) { // For listening to equipment data
      if (getExtEvHandler<CSecsgemHandler>().listenClientData(this)) {
        eRetVal = e_InitOk;
      }
    }

    else if (1 == mFb->getNumRD() && 1 == mFb->getNumSD()) { // For sending data to equipment

      if (e_Selected == getExtEvHandler<CSecsgemHandler>().getConnectionState(mHsmsSettings)) {
        eRetVal = e_InitOk;
      }

    } else {
      DEVLOG_ERROR(
          "[SECS/GEM Layer] A client have invalid number of SD or RD \n");
    }
    return eRetVal;
  }

  EComResponse CSecsgemComLayer::registerClientSubscription(char *paLayerParameter) {
    EComResponse eRetVal = e_InitInvalidId;

    util::CParameterParser parser(paLayerParameter, ';', 4); // IP:PORT;DeviceId[;procedure-type][;SxFy | ;system-bytes]
    handleSession(parser, parser.parseParameters());
    handleAddress(parser[0]);

    if (2 == mFb->getNumRD()) {
      if (getExtEvHandler<CSecsgemHandler>().listenClientData(this)) {
        eRetVal = e_InitOk;
      }    
    } else {
      DEVLOG_ERROR("[SECS/GEM Layer] A subscribe have invalid number of RD \n");    
    }
    return eRetVal;
  }
  
  bool CSecsgemComLayer::isControlResponseReceived() {
    DEVLOG_INFO("[SECS/GEM Layer] Start T6 Timer %ds.\n", mHsmsSettings.mT6);

    if (checkResponseReceived(mHsmsSettings.mT6 * 1000)) {
      DEVLOG_INFO("[SECS/GEM Layer] Stop T6 Timer.\n");
      return true;
    }

    DEVLOG_INFO("[SECS/GEM Layer] T6 Timeout.\n");
    return false;
  }


  bool CSecsgemComLayer::checkResponseReceived(int paTimeoutDuration) {
    CIEC_TIME startTime = func_NOW_MONOTONIC();
    while (true) {
      if (mMessage.mSystemBytes == mResponse.mSystemBytes) {
        return true;
      }

      if (func_NOW_MONOTONIC().getInMilliSeconds() > startTime.getInMilliSeconds() + paTimeoutDuration) {
        
        return false;
      }
      forte::arch::CWin32Thread::sleepThread(100);
    }
  
  }

  bool CSecsgemComLayer::checkSDsAndRDsType() const {
    for (size_t i = 2; i < mFb->getNumSD(); i++) {
      CIEC_ANY::EDataTypeID typeToCheck = mFb->getDI(static_cast<unsigned int>(i))->getDataTypeID();
      if (CIEC_ANY::e_ANY != typeToCheck && CIEC_ANY::e_STRING != typeToCheck && CIEC_ANY::e_WSTRING != typeToCheck) {
        DEVLOG_ERROR("[SECS/GEM Layer] Client called %s has an invalid SD_%d\n", mFb->getInstanceNameId().data(), i);
        return false;
      }
    }
    for (size_t i = 2; i < mFb->getNumRD(); i++) {
      CIEC_ANY::EDataTypeID typeToCheck = mFb->getDO(static_cast<unsigned int>(i))->getDataTypeID();
    }
    return true;
  }

  bool CSecsgemComLayer::handleSession(util::CParameterParser &paParser, size_t paNoOfParameters) {
    bool everythingOK = true;
    if (1 < paNoOfParameters) {
      mMessage.mSType = e_Data;
      if (3 <= paNoOfParameters) {
        std::regex numRegex(R"(^\d+$)");
        std::regex sxfyRegex(R"(^S(\d+)F(\d+)$)"); 
        std::smatch matches;

        if (!(std::regex_match(std::string(paParser[2]), numRegex) ||
              std::regex_match(std::string(paParser[2]), sxfyRegex))) {
          std::string toCheck = std::string(paParser[2]);

          if (toCheck == "select.req") {
            mMessage.mSType = e_SelectReq;
          } else if (toCheck == "select.rsp") {
            mMessage.mSType = e_SelectRsp;
          } else if (toCheck == "deselect.req") {
            mMessage.mSType = e_DeselectReq;
          } else if (toCheck == "deselect.rsp") {
            mMessage.mSType = e_DeselectRsp;
          } else if (toCheck == "linktest.req") {
            mMessage.mSType = e_LinktestReq;
          } else if (toCheck == "linktest.rsp") {
            mMessage.mSType = e_LinktestRsp;
          } else if (toCheck == "separate.req") {
            mMessage.mSType = e_SeparateReq;
          } else if (toCheck == "data") {
            mMessage.mSType = e_Data;
          } else {
            everythingOK = false;
            DEVLOG_ERROR(
                "[SECS/GEM Layer] Wrong procedure type. It should be select.req|select.rsp|deselect.req|linktest.req|"
                "linktest.rsp|separate.req|data \n");
          }        
        } else {

          int i = (3 == paNoOfParameters) ? 2 : 3;

          if (std::regex_match(std::string(paParser[i]), numRegex)) {
            mMessage.mSystemBytes = static_cast<TForteUInt16>(util::strtoul(paParser[i], nullptr, 10));
          }

          auto toMatch = std::string(paParser[i]);

          if (std::regex_match(toMatch, matches, sxfyRegex)) {
            mMessage.mSecsStream = std::stoi(matches[1].str());
            mMessage.mSecsFunction = std::stoi(matches[2].str());
          }
        }
      }
      mMessage.mDeviceId = static_cast<TForteUInt16>(util::strtoul(paParser[1], nullptr, 10));
    } else {
      everythingOK = false;
      DEVLOG_ERROR("[SECS/GEM Layer] Wrong parameters. It should be as IP:PORT;DeviceId;[procedure-type]\n");
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
        case e_Server: break;
        case e_Client: sendDataAsClient(paData); break;
        default:
          // e_Publisher and e_Subscriber
          break;
      } 
    } else {
      DEVLOG_ERROR("[SECS/GEM Layer]The FB is not initialized\n");
    }
    return mInterruptResp;
  }

  void CSecsgemComLayer::sendDataAsClient(void *paData) {
    auto &handler = getExtEvHandler<CSecsgemHandler>();
    auto sb = handler.getSystemBytes(mHsmsSettings);

    if (CIEC_ANY::e_WSTRING == getSDx(paData, 0).getDataTypeID()) {
      mMessage.mSmlMessage = static_cast<const CIEC_WSTRING &>(getSDx(paData, 0)).getValue();
    } else if (CIEC_ANY::e_STRING == getSDx(paData, 0).getDataTypeID()) {
      mMessage.mSmlMessage = static_cast<const CIEC_STRING &>(getSDx(paData, 0)).getStorage();
    }

    if (sb > 0) {
      mMessage.mSystemBytes = sb;
      CSecsgemParser::serializeMessage(mMessage);
    }

    if (handler.sendClientData(this, mMessage.mPayload, mMessage.mWBit)) {
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
          if (paSize == 0) {
            if (!mMessage.mWBit) {
              mInterruptResp = e_ProcessDataOk;
            } else {
              mInterruptResp = e_ProcessDataRecvFaild;
            }            
          } else {
            receiveMessage(data);
            mInterruptResp = e_ProcessDataOk;
          }
          break;
        }
        case e_Subscriber: {
          receiveMessage(data);
          mInterruptResp = e_ProcessDataOk;
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

  void CSecsgemComLayer::receiveMessage(std::vector<std::byte> const *paMessage) {
    mResponse.mPayload.resize(paMessage->size());
    memcpy(mResponse.mPayload.data(), paMessage->data(), paMessage->size());
    CSecsgemParser::parseMessage(mResponse);
    CIEC_ANY **apoRDs = mFb->getRDs();
    std::string sType;
    switch (mResponse.mSType) {
      case e_SelectReq: sType = "Control message: select.req"; break;
      case e_SelectRsp: sType = "Control message: select.rsp"; break;
      case e_DeselectReq: sType = "Control message: deselect.req"; break;
      case e_DeselectRsp: sType = "Control message: deselect.rsp"; break;
      case e_LinktestReq: sType = "Control message: linktest.req"; break;
      case e_LinktestRsp: sType = "Control message: linktest.rsp"; break;
      case e_RejectReq: sType = "Control message: reject.req"; break;
      case e_SeparateReq: sType = "Control message: separate.req"; break;
      case e_Data: {
        //apoRDs[0]->setValue({}); // Need to add the output assignment
        break;
      }
    }

    DEVLOG_INFO("[SECS/GEM Layer] Received %s.\n", sType.c_str());
  }

  EComResponse CSecsgemComLayer::handleHSMSResponse(char *paData) {
    EComResponse eRetVal = e_ProcessDataOk;
    return eRetVal;
  }

  EComResponse CSecsgemComLayer::processInterrupt() {
    mInterruptResp = e_ProcessDataOk;
    return mInterruptResp;
  }

  void CSecsgemComLayer::closeConnection() {

  }

  const std::string &CSecsgemComLayer::getHost() const{
    return mHsmsSettings.mHost;
  }

  TForteUInt16 CSecsgemComLayer::getPort() const {
    return mHsmsSettings.mPort;
  }

  const HsmsSettings& CSecsgemComLayer::getHsmsSettings() const {
    return mHsmsSettings;
  }

  const HsmsMessage& CSecsgemComLayer::getMessage() const {
    return mMessage;
  }

  TForteUInt32 CSecsgemComLayer::getSystemBytes() const {
    return mMessage.mSystemBytes;
  }
  
} // namespace forte::com_infra::secsgem
