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

  enum ESType {
    e_SelectReq = 1,
    e_SelectRsp = 2,
    e_DeselectReq = 3,
    e_DeselectRsp = 4,
    e_LinktestReq = 5,
    e_LinktestRsp = 6,
    e_RejectReq = 7,
    e_SeparateReq = 9,
    e_Data = 0,
    e_InvalidSession = 0xFF
  };

  enum EHsmsState { e_NotConnected, e_NotSelected, e_Selected };

  enum EHsmsMode {
    /*The Passive mode is used when the local entity listens for and accepts a connect procedure initiated by the Remote
       Entity.*/
    e_Passive,
    /*The Active mode is used when the connect procedure initiated by the Local Entity.*/
    e_Active
  };

  struct HsmsSettings {
      /* SECS/GEM Host */
      std::string mHost = "172.0.0.1";
      /* Port of the host */
      TForteUInt16 mPort = 5000;

      EHsmsMode mMode = e_Active;

      int mT3 = 45;
      int mT5 = 10;
      int mT6 = 5;
      int mT7 = 10;
      int mT8 = 5;
  };

} // namespace forte::com_infra::secsgem
