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
        explicit CSecsgemHandler(CDeviceExecution & paDeviceExecution);
        ~CSecsgemHandler() override;

        /* functions needed for the external event handler interface */
        void enableHandler() override;

        void disableHandler() override;

        EComResponse recvData(const void *paData, unsigned int paSize) override;

   

        bool isClientConnected(const HsmsSettings &paHsmsSettings);

        bool openClientConnection(const HsmsSettings &paHsmsSettings);

        bool listenClientData(CSecsgemComLayer *paLayer);

        bool sendClientData(CSecsgemComLayer *paLayer, const std::vector<std::byte> &paToSend, bool paExpectReply);

        TForteUInt32 getSystemBytes(const HsmsSettings &paHsmsSettings);

        void setConnectionState(const HsmsSettings &paSettings ,EHsmsState paState);
        EHsmsState getConnectionState(const HsmsSettings &paSettings);


      private:
        /**
         * Overridden run() from CThread which loops the UA Server.
         */

        struct ClientLayer {
            CSecsgemComLayer *mLayer;
            TForteUInt32 mSystemBytes;
            CIEC_TIME mStartTime;
        };

        struct ListenClientLayer {
            CSecsgemComLayer *mLayer;
            ESType mSType;
            TForteUInt8 mSecsStream;
            TForteUInt8 mSecsFunction;
        };

        struct HsmsClientEntity {
            HsmsSettings mHsmsSettings;
            arch::CIPComSocketHandler::TSocketDescriptor mSocket;
            TForteUInt16 mDeviceId;
            EHsmsState mState;
            TForteUInt32 mLastSystemBytes;
            std::vector<ClientLayer> mComLayers;
            std::vector<ListenClientLayer> mListenerLayers;
        };


        void run() override;

        void checkClientLayers();

        void checkAcceptedSockets();

        void startTimeoutThread();

        void stopTimeoutThread();

        void removeAndCloseSocket(const arch::CIPComSocketHandler::TSocketDescriptor paSocket);

        void resumeSelfsuspend();

        void selfSuspend();

        bool recvClients(const arch::CIPComSocketHandler::TSocketDescriptor paSocket, const int paRecvLength);

        void callbackClient(CSecsgemComLayer *paLayer, const int paRecvLength);

        void clearClientEntities();

        std::vector<HsmsClientEntity> mClientEntities;
        arch::CSyncObject mClientMutex;

        HsmsClientEntity *getClientEntity(const HsmsSettings &paHsmsSettings);

        arch::CSemaphore mSuspendSemaphore;

        TForteUInt32 getNextSystemBytes(HsmsClientEntity &paHsmsClientEntity);

        static std::vector<std::byte> sRecvBuffer;

        static const unsigned int scmSendTimeout;
        static const unsigned int scmAcceptedTimeout;

        arch::CSemaphore mThreadStarted;

  };
} // namespace forte::com_infra::secsgem