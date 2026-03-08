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

#include "forte/config/forte_config.h"
#include "forte/arch/forte_sem.h"
#include "forte/cominfra/comlayer.h"
#include "forte/datatypes/forte_string.h"
#include "forte/util/parameterParser.h"
#include "secsgemtypes.h"
#include <vector>

namespace forte::com_infra::secsgem {

  class CSecsgemComLayer : public CComLayer {
    public:
      CSecsgemComLayer(CComLayer *paUpperLayer, CBaseCommFB *paComFB);
      ~CSecsgemComLayer() override;

      EComResponse sendData(void *paData, unsigned int paSize) override; // top interface, called from top
      EComResponse recvData(const void *paData, unsigned int paSize) override;

      EComResponse openConnection(char *paLayerParameter) override;
      void closeConnection() override;

      EComResponse processInterrupt() override;

    private:
      EComResponse openClientConnection(char *paLayerParameter);

      EComResponse initActiveSendLayer(char *paLayerParameter);

      EComResponse initActiveListenLayer(char *paLayerParameter);

      void sendRequest(void *paData);
      void sendResponse(void *paData);

      EComResponse receiveMessage(const std::vector<std::byte> *paData);

      bool checkSDsAndRDsType() const;

      EComResponse mInterruptResp;

      bool handleAddress(const char *paAddress);

      bool handleSession(util::CParameterParser &paParser, size_t paNoOfParameters);

      HsmsSettings mHsmsSettings;

      TForteUInt16 mDeviceId;
      ESType mSessionType;
      TForteUInt8 mExpectedStream;
      TForteUInt8 mExpectedFunction;

      std::vector<std::byte> mRecvBuffer;

      bool mCorrectlyInitialized;
  };

} // namespace forte::com_infra::secsgem
