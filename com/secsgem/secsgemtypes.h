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

#include <vector>

namespace forte::com_infra::secsgem {

  enum EHsmsMode { e_Passive, e_Active };

  enum ESType {
    e_SelectReq = 1,
    e_SelectRsp = 2,
    e_DeselectReq = 3,
    e_DeselectRsp = 4,
    e_LinktestReq = 5,
    e_LinktestRsp = 6,
    e_RejectReq = 7,
    e_SeparateReq = 9,
    e_Data = 0
  };

  enum EHsmsState {
      e_NotConnected,
      e_NotSelected,
      e_Selected
  };

  struct HsmsSettings {

    /* SECS/GEM Host */
    std::string mHost;
    /* Port of the host */
    TForteUInt16 mPort;

    EHsmsMode mHsmsMode;

    int mT3 = 45;
    int mT5 = 10;
    int mT6 = 5;
    int mT7 = 10;
    int mT8 = 5;
  };

  struct HsmsMessage {
    /* Device ID*/
    TForteUInt16 mDeviceId = 0;
    bool mWBit = false;
    TForteUInt8 mSecsStream = 0;
    TForteUInt8 mSecsFunction = 0;
    TForteUInt8 mPType = 0;
    ESType mSType = e_Data;
    TForteUInt32 mSystemBytes = 0;


    std::string mSmlMessage;

    /* HSMS message text */
    std::vector<std::byte> mMessageText;
    /* HSMS message */
    std::vector<std::byte> mPayload;
  };

} // namespace forte::com_infra::secsgem
