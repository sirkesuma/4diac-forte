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
    clearClientEntities();
  }

  void CSecsgemHandler::enableHandler() {
    startTimeoutThread();
  }

  void CSecsgemHandler::disableHandler() {
    stopTimeoutThread();
  }

  void CSecsgemHandler::clearClientEntities() {
    util::CCriticalRegion criticalRegion(mClientMutex);
    for (auto &clientLayer : mClientEntities) {
      removeAndCloseSocket(clientLayer.mSocket);
    }
    mClientEntities.clear();
  }

  EComResponse CSecsgemHandler::recvData(const void *paData, unsigned int) {
    arch::CIPComSocketHandler::TSocketDescriptor socket =
        *(static_cast<const arch::CIPComSocketHandler::TSocketDescriptor *>(paData));

    char msgLenChar[4];

    TForteUInt32 net;
    int recvLen = arch::CIPComSocketHandler::receiveDataFromTCP(socket, &msgLenChar[0], sizeof(msgLenChar));
    std::memcpy(&net, msgLenChar, sizeof(msgLenChar));
    TForteUInt32 msgLen = ntohl(net);

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
        if (!recvClients(socket, recvLen)) {
          DEVLOG_WARNING("[SECS/GEM Handler]: A packet arrived to the wrong place\n");
        }
      }
    }
    return e_Nothing;
  }

  bool CSecsgemHandler::recvClients(const arch::CIPComSocketHandler::TSocketDescriptor paSocket,
                                    const int paRecvLength) { // check clients
    util::CCriticalRegion criticalRegion(mClientMutex);
    for (auto entity = mClientEntities.begin(); entity != mClientEntities.end(); entity++) {
      if (entity->mSocket == paSocket) {

        HsmsMessage message;
        message.mPayload = sRecvBuffer;
        CSecsgemParser::parseMessage(message);

        TForteUInt32 sb = CSecsgemParser::parseSystemBytes(sRecvBuffer);
        if (message.mSecsFunction == 0 && message.mSecsFunction % 2 == 0 ||
            (message.mSType > 0 && message.mSType % 2 == 0)) { // Even Function Nr. means received secondary message
          for (auto client = entity->mComLayers.begin(); client != entity->mComLayers.end(); client++) {
            if (message.mSystemBytes == client->mSystemBytes) { // Look for client layer with matching message bytes
              switch (CSecsgemParser::parseSType(sRecvBuffer)) {
                case e_Data: {
                  callbackClient(&*client->mLayer, paRecvLength);
                  break;
                }
                default: {
                  client->mLayer->receiveMessage(&sRecvBuffer);
                  break;
                }
              }
              entity->mComLayers.erase(client);
              return true;
            }
          }
        }

        else { // Handle primary or request message
          for (auto client = entity->mListenerLayers.begin(); client != entity->mListenerLayers.end(); client++) {
            if (message.mSType == client->mSType && message.mSecsStream == client->mSecsStream &&
                message.mSecsFunction == client->mSecsFunction) {
              switch (message.mSType) {
                case e_Data: {
                  callbackClient(&*client->mLayer, paRecvLength);
                  break;
                }
                default: {
                  client->mLayer->receiveMessage(&sRecvBuffer);
                  break;
                }
              }
              return true;
            }
          }
        }
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

  bool CSecsgemHandler::openClientConnection(const HsmsSettings &paHsmsSettings) {
    auto host = paHsmsSettings.mHost;
    arch::CIPComSocketHandler::TSocketDescriptor newSocket =
        arch::CIPComSocketHandler::openTCPClientConnection(host.data(), paHsmsSettings.mPort);

    if (arch::CIPComSocketHandler::scmInvalidSocketDescriptor != newSocket) {
      HsmsClientEntity toAdd;
      toAdd.mHsmsSettings = paHsmsSettings;
      toAdd.mSocket = newSocket;
      toAdd.mState = e_NotSelected;
      toAdd.mLastSystemBytes = 0;
      mClientEntities.emplace_back(std::move(toAdd));
      mDeviceExecution.getExtEvHandler<arch::CIPComSocketHandler>().addComCallback(newSocket, this);
      DEVLOG_INFO("[SECS/GEM Handler]: Open client connection for %s:%u\n", paHsmsSettings.mHost.c_str(),
                  paHsmsSettings.mPort);
      return true;
    } else {
      DEVLOG_ERROR("[SECS/GEM Handler]: Couldn't open client connection for %s:%u\n", paHsmsSettings.mHost.c_str(),
                   paHsmsSettings.mHost);
    }
    return false;
  }

  CSecsgemHandler::HsmsClientEntity *CSecsgemHandler::getClientEntity(const HsmsSettings &paHsmsSettings) {
    HsmsClientEntity *client = nullptr;
    for (auto it = mClientEntities.begin(); it != mClientEntities.end(); ++it) {
      if (paHsmsSettings.mHost == it->mHsmsSettings.mHost && paHsmsSettings.mPort == it->mHsmsSettings.mPort) {
        client = &*it;
        break;
      }
    }
    return client;
  }

  bool CSecsgemHandler::isClientConnected(const HsmsSettings &paHsmsSettings) {
    if (getClientEntity(paHsmsSettings) != nullptr) {
      return true;
    }
    return false;
  }

  bool CSecsgemHandler::listenClientData(CSecsgemComLayer *paLayer) {
    auto &hs = paLayer->getHsmsSettings();
    HsmsClientEntity *client = getClientEntity(hs);

    if (!client) {
      DEVLOG_ERROR("[SECS/GEM Handler]: Connection is not yet initialized for %s:%u\n", paLayer->getHost().c_str(),
                   paLayer->getPort());
      return false;
    }

    util::CCriticalRegion criticalRegion(mClientMutex);
    ListenClientLayer toAdd;
    toAdd.mLayer = paLayer;
    toAdd.mSType = paLayer->getMessage().mSType;
    toAdd.mSecsStream = paLayer->getMessage().mSecsStream;
    toAdd.mSecsFunction = paLayer->getMessage().mSecsFunction;

    client->mListenerLayers.emplace_back(std::move(toAdd));

    return true;
  }

  bool CSecsgemHandler::sendClientData(CSecsgemComLayer *paLayer,
                                       const std::vector<std::byte> &paToSend,
                                       bool paExpectReply) {
    arch::CIPComSocketHandler::TSocketDescriptor socket = arch::CIPComSocketHandler::scmInvalidSocketDescriptor;

    auto &hs = paLayer->getHsmsSettings();
    HsmsClientEntity *client = getClientEntity(hs);

    if (!client) {
      DEVLOG_ERROR("[SECS/GEM Handler]: Connection is not yet initialized for %s:%u\n", paLayer->getHost().c_str(),
                   paLayer->getPort());
      return false;
    }

    socket = client->mSocket;
    if (arch::CIPComSocketHandler::scmInvalidSocketDescriptor == socket) {
      DEVLOG_ERROR("[SECS/GEM Handler]: Couldn't open client connection to %s:%u\n", paLayer->getHost().c_str(),
                   paLayer->getPort());
      return false;
    }

    if (static_cast<int>(paToSend.size()) ==
        arch::CIPComSocketHandler::sendDataOnTCP(socket, reinterpret_cast<const char *>(paToSend.data()),
                                                 static_cast<int>(paToSend.size()))) {
      if (paExpectReply) {
        util::CCriticalRegion criticalRegion(mClientMutex);
        ClientLayer toAdd;
        toAdd.mLayer = paLayer;
        toAdd.mSystemBytes = paLayer->getSystemBytes();
        toAdd.mStartTime = func_NOW_MONOTONIC();
        client->mComLayers.emplace_back(std::move(toAdd));
      } else {
        callbackClient(paLayer, 0);
      }
      return true;

    } else {
      DEVLOG_ERROR("[SECS/GEM Handler]: Couldn't send data to client %s:%u\n", paLayer->getHost().c_str(),
                   paLayer->getPort());
    }
    return false;
  }

  TForteUInt32 CSecsgemHandler::getSystemBytes(const HsmsSettings &paHsmsSettings) {
    auto *client = getClientEntity(paHsmsSettings);
    if (client != nullptr) {
      return getNextSystemBytes(*client);
    }
    return 0;
  }

  TForteUInt32 CSecsgemHandler::getNextSystemBytes(HsmsClientEntity &paHsmsClientEntity) {
    util::CCriticalRegion criticalRegion(mClientMutex);
    auto &x = paHsmsClientEntity.mLastSystemBytes;
    ++x;
    if (x == 0)
      x = 1;
    return x;
  }

  void CSecsgemHandler::setConnectionState(const HsmsSettings &paSettings, EHsmsState paHsmsState) {
    for (auto client = mClientEntities.begin(); client != mClientEntities.end(); ++client) {
      if (paSettings.mHost == client->mHsmsSettings.mHost && paSettings.mPort == client->mHsmsSettings.mPort) {
        client->mState = paHsmsState;
      }
    }
  }

  EHsmsState CSecsgemHandler::getConnectionState(const HsmsSettings &paSettings) {
    EHsmsState eRetVal = e_NotConnected;
    for (auto client = mClientEntities.begin(); client != mClientEntities.end(); ++client) {
      if (paSettings.mHost == client->mHsmsSettings.mHost && paSettings.mPort == client->mHsmsSettings.mPort) {
        eRetVal = client->mState;
      }
    }
    return eRetVal;
  }

  void CSecsgemHandler::run() {
    DEVLOG_INFO("[SECS/GEM Handler]: Starting timeout thread\n");

    mThreadStarted.inc();
    while (isAlive()) {
      if (mClientEntities.empty()) {
        selfSuspend();
      }
      if (!isAlive()) {
        break;
      }

      checkClientLayers();
      sleepThread(100);
    }
  }

  void CSecsgemHandler::checkClientLayers() {
    util::CCriticalRegion criticalRegion(mClientMutex);
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
