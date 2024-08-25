/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#ifndef WIFI_DIRECT_MANAGER_H
#define WIFI_DIRECT_MANAGER_H

#include "channel/wifi_direct_negotiate_channel.h"
#include "common_list.h"
#include "wifi_direct_defines.h"
#include "wifi_direct_types.h"

#ifdef __cplusplus
extern "C" {
#endif

struct WifiDirectStatusListener {
    void (*onLocalRoleChange)(enum WifiDirectRole myRole);
    void (*onDeviceOnLine)(const char *remoteMac, const char *remoteIp, const char *remoteUuid, bool isSource);
    void (*onDeviceOffLine)(const char *remoteMac, const char *remoteIp, const char *remoteUuid, const char *localIp);
    void (*onConnectedForSink)(const char *remoteMac, const char *remoteIp, const char *remoteUuid,
                               enum WifiDirectLinkType type);
    void (*onDisconnectedForSink)(const char *remoteMac, const char *remoteIp, const char *remoteUuid,
                                  enum WifiDirectLinkType type);
};

enum WifiDirectListenerModule {
    TRANS_LINK_MODULE = 0,
    LNN_LANE_MODULE = 1,
    LEGACY_HML_MODULE = 2,
    MODULE_TYPE_MAX,
};

struct WifiDirectManager {
    /* public interface */
    int32_t (*getRequestId)(void);
    int32_t (*connectDevice)(struct WifiDirectConnectInfo *connectInfo, struct WifiDirectConnectCallback *callback);
    int32_t (*disconnectDevice)(struct WifiDirectConnectInfo *connectInfo, struct WifiDirectConnectCallback *callback);
    void (*registerStatusListener)(enum WifiDirectListenerModule module, struct WifiDirectStatusListener *listener);
    int32_t (*getRemoteUuidByIp)(const char *ipString, char *uuid, int32_t uuidSize);
    bool (*isDeviceOnline)(const char *remoteMac);
    int32_t (*getLocalIpByRemoteIp)(const char *remoteIp, char *localIp, int32_t localIpSize);
    int32_t (*getLocalIpByUuid)(const char *uuid, char *localIp, int32_t localIpSize);
    int32_t (*prejudgeAvailability)(const char *remoteNetworkId, enum WifiDirectLinkType linkType);
    int32_t (*getInterfaceNameByLocalIp)(const char *localIp, char *interfaceName, size_t interfaceNameSize);
    int32_t (*getLocalAndRemoteMacByLocalIp)(const char *localIp,  char *localMac, size_t localMacSize,
                                             char *remoteMac, size_t remoteMacSize);
    bool (*isNegotiateChannelNeeded)(const char *remoteNetworkId, enum WifiDirectLinkType linkType);

    void (*onNegotiateChannelDataReceived)(struct WifiDirectNegotiateChannel *channel, const uint8_t *data, size_t len);
    void (*onNegotiateChannelDisconnected)(struct WifiDirectNegotiateChannel *channel);
    void (*onRemoteP2pDisable)(const char *networkId);

    void (*onConnectedForSink)(const char *remoteMac, const char *remoteIp, const char *remoteUuid,
                               enum WifiDirectLinkType type);
    void (*onDisconnectedForSink)(const char *remoteMac, const char *remoteIp, const char *remoteUuid,
                                  enum WifiDirectLinkType type);

    /* private data member */
    int32_t requestId;
    ListNode callbackList;
    struct WifiDirectStatusListener listeners[MODULE_TYPE_MAX];
    enum WifiDirectRole myRole;
    char localMac[MAC_ADDR_STR_LEN];
    bool feature;
};

/* singleton */
struct WifiDirectManager* GetWifiDirectManager(void);

int32_t WifiDirectManagerInit(void);

#ifdef __cplusplus
}
#endif
#endif