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

#include "forte/arch/forte_thread.h"
#include "forte/extevhan.h"
#include "forte/conn.h"
#include <stdio.h>
#include "forte/arch/sockhand.h"
#include "forte/datatypes/forte_string.h"
#include "secsgemlayer.h"
#include "forte/cominfra/comCallback.h"
#include "forte/datatypes/forte_date_and_time.h"

#include <vector>

namespace forte::com_infra::secsgem {
  // cppcheck-suppress noConstructor
  class CSecsgemHandler : public CExternalEventHandler,
                          public RegisterExternalEventHandler<CSecsgemHandler>,
                          public arch::CThread,
                          public CComCallback {
    public:
      explicit CSecsgemHandler(CDeviceExecution &paDeviceExecution);
      ~CSecsgemHandler() override;

      /* functions needed for the external event handler interface */
      void enableHandler() override;

      void disableHandler() override;

      EComResponse recvData(const void *paData, unsigned int paSize) override;

      void setConnectionState(const HsmsSettings &paSettings, EHsmsState paState);
      EHsmsState getConnectionState(const HsmsSettings &paSettings);

      bool initActiveConnection(const HsmsSettings &paHsmsSettings,
                                TForteUInt16 paDeviceId = 0,
                                CSecsgemComLayer *paLayer = nullptr,
                                ESType paSType = e_Data,
                                TForteUInt8 paStream = 0,
                                TForteUInt8 paFunction = 0);

      bool sendData(const HsmsSettings &paHsmsSetting,
                    CSecsgemComLayer *paLayer,
                    const std::string &paToSend = "",
                    ESType paSessionType = e_Data,
                    bool paIsResponse = false);

    private:
      struct SendLayer {
          CSecsgemComLayer *mLayer;
          TForteUInt32 mSystemBytes;
          int mTimeoutMs;
          CIEC_TIME mStartTime;
      };

      struct ListenLayer {
          CSecsgemComLayer *mLayer;
          TForteUInt32 mSystemBytes;
          ESType mSType;
          TForteUInt8 mSecsStream;
          TForteUInt8 mSecsFunction;
      };

      struct HsmsEntity {
          HsmsSettings mHsmsSettings;
          arch::CIPComSocketHandler::TSocketDescriptor mSocket = arch::CIPComSocketHandler::scmInvalidSocketDescriptor;
          TForteUInt16 mDeviceId = 0;
          EHsmsState mState = e_NotConnected;
          TForteUInt32 mLastSystemBytes = 0;

          std::vector<SendLayer> mSendLayers;
          std::vector<ListenLayer> mListenLayers;

          ListenLayer *getListenLayer(CSecsgemComLayer *mLayer) {
            for (auto layer = mListenLayers.begin(); layer != mListenLayers.end(); layer++) {
              if (layer->mLayer = mLayer) {
                return &*layer;
              }
            }
            return nullptr;
          }

          ListenLayer *getListenLayer(ESType paSType, TForteUInt8 paStream, TForteUInt8 paFunction) {
            for (auto layer = mListenLayers.begin(); layer != mListenLayers.end(); layer++) {
              if (layer->mSType == paSType && layer->mSecsStream == paStream && layer->mSecsFunction == paFunction) {
                return &*layer;
              }
            }
            return nullptr;
          }
      };

      arch::CSyncObject mEntityMutex;

      void run() override;

      void checkActiveSendLayers();

      void startTimeoutThread();

      void stopTimeoutThread();

      void removeAndCloseSocket(const arch::CIPComSocketHandler::TSocketDescriptor paSocket);

      void resumeSelfsuspend();

      void selfSuspend();

      bool recvMessage(const arch::CIPComSocketHandler::TSocketDescriptor paSocket, const int paRecvLength);

      bool recvClients(const arch::CIPComSocketHandler::TSocketDescriptor paSocket, const int paRecvLength);

      void callbackClient(CSecsgemComLayer *paLayer, const int paRecvLength);

      void clearEntities();

      std::vector<HsmsEntity> mEntities;

      HsmsEntity *getEntity(const HsmsSettings &paHsmsSettings);
      HsmsEntity *getEntity(const arch::CIPComSocketHandler::TSocketDescriptor paScoket);

      arch::CSemaphore mSuspendSemaphore;

      TForteUInt32 getNextSystemBytes(HsmsEntity &paHsmsEntity);

      static std::vector<std::byte> sRecvBuffer;

      static const unsigned int scmSendTimeout;
      static const unsigned int scmAcceptedTimeout;

      arch::CSemaphore mThreadStarted;
  };
} // namespace forte::com_infra::secsgem
