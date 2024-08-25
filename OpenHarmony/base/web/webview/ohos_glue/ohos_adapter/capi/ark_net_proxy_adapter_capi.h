/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef ARK_NET_PROXY_ADAPTER_CAPI_H_
#define ARK_NET_PROXY_ADAPTER_CAPI_H_
#pragma once

#include "base/capi/ark_web_base_ref_counted_capi.h"
#include "base/include/ark_web_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _ark_net_proxy_event_callback_adapter_t {
    /**
     * @brief Base structure.
     */
    ark_web_base_ref_counted_t base;

    void(ARK_WEB_CALLBACK* changed)(struct _ark_net_proxy_event_callback_adapter_t* self, const ArkWebString* host,
        const uint16_t* port, const ArkWebString* pacUrl, const ArkWebStringVector* exclusionList);
} ark_net_proxy_event_callback_adapter_t;

typedef struct _ark_net_proxy_adapter_t {
    /**
     * @brief Base structure.
     */
    ark_web_base_ref_counted_t base;

    void(ARK_WEB_CALLBACK* reg_net_proxy_event)(
        struct _ark_net_proxy_adapter_t* self, ark_net_proxy_event_callback_adapter_t* eventCallback);

    bool(ARK_WEB_CALLBACK* start_listen)(struct _ark_net_proxy_adapter_t* self);

    void(ARK_WEB_CALLBACK* stop_listen)(struct _ark_net_proxy_adapter_t* self);

    void(ARK_WEB_CALLBACK* get_property)(struct _ark_net_proxy_adapter_t* self, ArkWebString* host, uint16_t* port,
        ArkWebString* pacUrl, ArkWebString* exclusion);
} ark_net_proxy_adapter_t;

#ifdef __cplusplus
}
#endif

#endif // ARK_NET_PROXY_ADAPTER_CAPI_H_
