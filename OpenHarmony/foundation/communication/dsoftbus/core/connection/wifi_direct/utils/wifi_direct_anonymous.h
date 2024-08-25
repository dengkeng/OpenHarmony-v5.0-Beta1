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
#ifndef WIFI_DIRECT_ANONYMOUS_H
#define WIFI_DIRECT_ANONYMOUS_H

#include "wifi_direct_types.h"
#include "common_list.h"

#ifdef __cplusplus
extern "C" {
#endif

const char* WifiDirectAnonymizeMac(const char *mac);
const char* WifiDirectAnonymizeIp(const char *ip);
const char* WifiDirectAnonymizeDeviceId(const char *deviceId);
const char* WifiDirectAnonymizePsk(const char *psk);
const char* WifiDirectAnonymizePtk(const char *ptk);

#ifdef __cplusplus
}
#endif
#endif