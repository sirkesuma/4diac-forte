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

#include "secsgemhandler.h"
#include "forte/devexec.h"
#include "forte/iec61131_functions.h"
#include "forte/cominfra/basecommfb.h"
#include "forte/util/criticalregion.h"
#include "secsgemparser.h"
#include "forte/arch/forte_printer.h"
#include "forte/cominfra/comlayer.h"
#include "forte/util/mainparam_utils.h"
#include "secsgemlayer.h"

#include <string>

using namespace std::string_literals;

namespace forte::com_infra::secsgem {

  std::vector<std::byte> CSecsgemHandler::sRecvBuffer;
  const unsigned int CSecsgemHandler::scmSendTimeout = 20;
  const unsigned int CSecsgemHandler::scmAcceptedTimeout = 5;

  CSecsgemHandler::CSecsgemHandler(CDeviceExecution &paDeviceExecution) : CExternalEventHandler(paDeviceExecution) {
    sRecvBuffer.reserve(65535);
  }

  CSecsgemHandler::~CSecsgemHandler() {
    stopTimeoutThread();
    clearEntities();
  }

  void CSecsgemHandler::enableHandler() {
    startTimeoutThread();
  }

  void CSecsgemHandler::disableHandler() {
    stopTimeoutThread();
  }

  void CSecsgemHandler::clearEntities() {
    for (auto &layer : mEntities) {
      removeAndCloseSocket(layer.mSocket);
    }
    mEntities.clear();
  }

  EComResponse CSecsgemHandler::recvData(const void *paData, unsigned int) {
    arch::CIPComSocketHandler::TSocketDescriptor socket =
        *(static_cast<const arch::CIPComSocketHandler::TSocketDescriptor *>(paData));

    // get message length
    char msgLenChar[4];
    TForteUInt32 net;
    int recvLen = arch::CIPComSocketHandler::receiveDataFromTCP(socket, &msgLenChar[0], sizeof(msgLenChar));
    std::memcpy(&net, msgLenChar, sizeof(msgLenChar));
    TForteUInt32 msgLen = ntohl(net);

    // Handle data payload
    if (recvLen == 4) {
      sRecvBuffer.resize(msgLen);
      recvLen =
          arch::CIPComSocketHandler::receiveDataFromTCP(socket, reinterpret_cast<char *>(sRecvBuffer.data()), msgLen);
      TForteUInt32 sb = CSecsgemParser::parseSystemBytes(sRecvBuffer);
      DEVLOG_INFO("[SECS/GEM Handler] Received %d bytes of message, system bytes: %d\n", recvLen, sb);

      if (0 == recvLen) {
        removeAndCloseSocket(socket);
      } else if (-1 == recvLen) {
        removeAndCloseSocket(socket);
        DEVLOG_ERROR("[SECS/GEM handler] Error receiving packet\n");
      } else {
        if (!recvMessage(socket, recvLen)) {
          DEVLOG_WARNING("[SECS/GEM Handler]: A packet arrived to the wrong place\n");
        }
      }
    }
    return e_Nothing;
  }

  bool CSecsgemHandler::recvMessage(const arch::CIPComSocketHandler::TSocketDescriptor paSocket,
                                    const int paRecvLength) {
    auto entity = getEntity(paSocket);
    if (!entity) {
      return false;
    }
    util::CCriticalRegion criticalRegion(mEntityMutex);

    // Parse header;
    auto header = std::span(sRecvBuffer).subspan(0, 10);
    auto sessionType = CSecsgemParser::parseSessionType(header);
    auto streamNo = CSecsgemParser::parseSecsStream(header);
    auto functionNo = CSecsgemParser::parseSecsFunction(header);
    auto systemBytes = CSecsgemParser::parseSystemBytes(header);

    bool isPrimaryMessage = sessionType % 2 == 1 || (streamNo > 0 && functionNo % 2 == 1);

    if (isPrimaryMessage) { // Receiving primary message from remote entity
      for (auto layer = entity->mListenLayers.begin(); layer != entity->mListenLayers.end(); layer++) {
        if (layer->mSType != sessionType || layer->mSecsStream != streamNo || layer->mSecsFunction != functionNo)
          continue;
        callbackClient(layer->mLayer, paRecvLength);
        layer->mSystemBytes = systemBytes;
        return true;
      }
    } else { // Receiving secondary message from remote entity (a reply to a primary message that was sent earlier)
      for (auto layer = entity->mSendLayers.begin(); layer != entity->mSendLayers.end(); layer++) {
        if (systemBytes != layer->mSystemBytes)
          continue;
        callbackClient(layer->mLayer, paRecvLength);
        entity->mSendLayers.erase(layer);
        return true;
      }
    }
    return false;
  }

  void CSecsgemHandler::callbackClient(CSecsgemComLayer *paLayer, const int paRecvLength) {
    if (e_ProcessDataOk ==
        paLayer->recvData(static_cast<void *>(&sRecvBuffer), static_cast<unsigned int>(paRecvLength))) {
      startNewEventChain(paLayer->getCommFB());
    }
  }

  bool CSecsgemHandler::initActiveConnection(const HsmsSettings &paHsmsSettings,
                                             TForteUInt16 paDeviceId,
                                             CSecsgemComLayer *paLayer,                                             
                                             ESType paSType,
                                             TForteUInt8 paStream,
                                             TForteUInt8 paFunction) {
    HsmsSettings settings = paHsmsSettings;
    auto entity = getEntity(settings);

    ListenLayer newListenLayer;
    if (paSType != e_Data || paStream > 0) {
      newListenLayer.mLayer = paLayer;
      newListenLayer.mSecsStream = paStream;
      newListenLayer.mSecsFunction = paFunction;
      newListenLayer.mSType = paSType;
    }

    if (!entity) {
      auto host = settings.mHost.data();
      auto port = settings.mPort;
      auto newSocket = arch::CIPComSocketHandler::openTCPClientConnection(host, port);

      if (arch::CIPComSocketHandler::scmInvalidSocketDescriptor != newSocket) {
        HsmsEntity newEntity;
        newEntity.mHsmsSettings = settings;
        newEntity.mDeviceId = paDeviceId;
        newEntity.mSocket = newSocket;
        newEntity.mState = e_NotSelected;

        if (paSType != e_Data || paStream > 0)
          newEntity.mListenLayers.emplace_back(newListenLayer);

        mEntities.emplace_back(std::move(newEntity));
        mDeviceExecution.getExtEvHandler<arch::CIPComSocketHandler>().addComCallback(newSocket, this);
        DEVLOG_INFO("[SECS/GEM Handler]: Connected to remote entity %s:%u\n", settings.mHost.c_str(), settings.mPort);
        return true;
      } else {
        DEVLOG_ERROR("[SECS/GEM Handler]: Couldn't connect to remote entity %s:%u\n", settings.mHost.c_str(),
                     settings.mHost);
      }
    } else {
      if (paSType != e_Data || paStream > 0)
        entity->mListenLayers.emplace_back(newListenLayer);
      return true;
    }
    return false;
  }

  CSecsgemHandler::HsmsEntity *CSecsgemHandler::getEntity(const HsmsSettings &paHsmsSettings) {
    HsmsEntity *entity = nullptr;
    for (auto et = mEntities.begin(); et != mEntities.end(); ++et) {
      if (paHsmsSettings.mHost == et->mHsmsSettings.mHost && paHsmsSettings.mPort == et->mHsmsSettings.mPort) {
        entity = &*et;
        break;
      }
    }
    return entity;
  }

  CSecsgemHandler::HsmsEntity *CSecsgemHandler::getEntity(const arch::CIPComSocketHandler::TSocketDescriptor paScoket) {
    HsmsEntity *entity = nullptr;
    for (auto et = mEntities.begin(); et != mEntities.end(); ++et) {
      if (et->mSocket == paScoket) {
        entity = &*et;
        break;
      }
    }
    return entity;
  }

  bool CSecsgemHandler::sendData(const HsmsSettings &paHsmsSettings,
                                 CSecsgemComLayer *paLayer,
                                 const std::string &paToSend,
                                 ESType paSessionType,
                                 bool paIsResponse) {
    // Get HSMS entity
    auto entity = getEntity(paHsmsSettings);
    if (!entity) {
      DEVLOG_ERROR("[SECS/GEM Handler]: Connection is not yet initialized for remote entity %s:%u\n",
                   paHsmsSettings.mHost.c_str(), paHsmsSettings.mPort);
      return false;
    }

    // Encode Message
    TForteUInt16 deviceId = paSessionType == e_Data ? entity->mDeviceId : 0xFFFF;
    ESType sType = paSessionType;
    TForteUInt32 sBytes = paIsResponse ? entity->getListenLayer(paLayer)->mSystemBytes : getNextSystemBytes(*entity);
    auto dataToSend = CSecsgemParser::encodeMessage(sType, sBytes, deviceId, paToSend);
    if (dataToSend.size() == 0) {
      DEVLOG_ERROR("[SECS/GEM Handler]: Failed to encode message for FB %s\n", paLayer->getCommFB()->getInstanceName());
      return false;
    }

    // Send data over network
    auto payload = reinterpret_cast<const char *>(dataToSend.data());
    auto payloadSize = static_cast<int>(dataToSend.size());
    if (payloadSize == arch::CIPComSocketHandler::sendDataOnTCP(entity->mSocket, payload, payloadSize)) {
      if (paIsResponse) {
        return true;
      }

      //Handle data request
      if (sType == e_Data) {
        auto header = std::span(dataToSend).subspan(4, 10);
        bool waitbit = CSecsgemParser::parseWaitBit(header);
        if (!waitbit) {
          callbackClient(paLayer, 0);
          return true;
        }
      }
      util::CCriticalRegion criticalRegion(mEntityMutex);
      SendLayer toAdd;
      toAdd.mLayer = paLayer;
      toAdd.mSystemBytes = sBytes;
      toAdd.mTimeoutMs = (sType == e_Data) ? entity->mHsmsSettings.mT3 * 1000 : entity->mHsmsSettings.mT6 * 1000;
      toAdd.mStartTime = func_NOW_MONOTONIC();
      entity->mSendLayers.emplace_back(std::move(toAdd));
      return true;
    } else {
      DEVLOG_ERROR("[SECS/GEM Handler]: Couldn't send data to remote entity %s:%u\n", paHsmsSettings.mHost.c_str(),
                   paHsmsSettings.mPort);
    }
    return false;
  }

  TForteUInt32 CSecsgemHandler::getNextSystemBytes(HsmsEntity &paHsmsEntity) {
    util::CCriticalRegion criticalRegion(mEntityMutex);
    return ++paHsmsEntity.mLastSystemBytes;
  }

  void CSecsgemHandler::setConnectionState(const HsmsSettings &paSettings, EHsmsState paHsmsState) {
    for (auto entity = mEntities.begin(); entity != mEntities.end(); entity++) {
      if (paSettings.mHost == entity->mHsmsSettings.mHost && paSettings.mPort == entity->mHsmsSettings.mPort) {
        entity->mState = paHsmsState;
      }
    }
  }

  EHsmsState CSecsgemHandler::getConnectionState(const HsmsSettings &paSettings) {
    EHsmsState eRetVal = e_NotConnected;
    for (auto entity = mEntities.begin(); entity != mEntities.end(); entity++) {
      if (paSettings.mHost == entity->mHsmsSettings.mHost && paSettings.mPort == entity->mHsmsSettings.mPort) {
        eRetVal = entity->mState;
      }
    }
    return eRetVal;
  }

  void CSecsgemHandler::run() {
    DEVLOG_INFO("[SECS/GEM Handler]: Starting timeout thread\n");

    mThreadStarted.inc();
    while (isAlive()) {
      if (mEntities.empty()) {
        selfSuspend();
      }
      if (!isAlive()) {
        break;
      }

      checkActiveSendLayers();
      sleepThread(100);
    }
  }

  void CSecsgemHandler::checkActiveSendLayers() {
    // to be handled
  }

  void CSecsgemHandler::startTimeoutThread() {
    if (!isAlive()) {
      start();
      mThreadStarted.waitIndefinitely();
      mThreadStarted.inc();
    }
  }

  void CSecsgemHandler::stopTimeoutThread() {
    setAlive(false);
    resumeSelfsuspend();
    end();
  }

  void CSecsgemHandler::removeAndCloseSocket(const arch::CIPComSocketHandler::TSocketDescriptor paSocket) {
    mDeviceExecution.getExtEvHandler<arch::CIPComSocketHandler>().removeComCallback(paSocket);
    mDeviceExecution.getExtEvHandler<arch::CIPComSocketHandler>().closeSocket(paSocket);
  }

  void CSecsgemHandler::resumeSelfsuspend() {
    mSuspendSemaphore.inc();
  }

  void CSecsgemHandler::selfSuspend() {
    mSuspendSemaphore.waitIndefinitely();
  }

} // namespace forte::com_infra::secsgem
