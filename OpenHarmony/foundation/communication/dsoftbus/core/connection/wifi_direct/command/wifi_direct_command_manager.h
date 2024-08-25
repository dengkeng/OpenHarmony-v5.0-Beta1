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
#ifndef WIFI_DIRECT_COMMAND_MANAGER_H
#define WIFI_DIRECT_COMMAND_MANAGER_H

#include "common_list.h"
#include "softbus_adapter_thread.h"
#include "wifi_direct_types.h"
#include "command/wifi_direct_command.h"

#ifdef __cplusplus
extern "C" {
#endif

struct WifiDirectCommandManager {
    uint32_t (*allocateCommandId)(void);
    void (*enqueueCommand)(struct WifiDirectCommand *command);
    void (*enqueueCommandFront)(struct WifiDirectCommand *command);
    struct WifiDirectCommand* (*dequeueCommand)(void);
    void (*removePassiveCommand)(void);
    struct WifiDirectCommand *(*find)(bool(*checker)(struct WifiDirectCommand *));

    uint32_t currentCommandId;
};

struct WifiDirectCommandManager* GetWifiDirectCommandManager(void);

#ifdef __cplusplus
}
#endif
#endif