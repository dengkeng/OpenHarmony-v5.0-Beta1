/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ETHERNET_DHCP_CALLBACK_H
#define ETHERNET_DHCP_CALLBACK_H

#include "refbase.h"
#include <string>

namespace OHOS {
namespace NetManagerStandard {
class EthernetDhcpCallback : public RefBase {
public:
    struct DhcpResult {
        std::string iface;
        std::string ipAddr;
        std::string gateWay;
        std::string subNet;
        std::string route1;
        std::string route2;
        std::string dns1;
        std::string dns2;
    };

public:
    virtual ~EthernetDhcpCallback() = default;
    virtual int32_t OnDhcpSuccess(EthernetDhcpCallback::DhcpResult &dhcpResult) = 0;
};
} // namespace NetManagerStandard
} // namespace OHOS
#endif // ETHERNET_DHCP_CALLBACK_H