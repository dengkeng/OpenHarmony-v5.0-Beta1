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

#ifndef ARK_WEB_QUICK_MENU_PARAMS_CAPI_H_
#define ARK_WEB_QUICK_MENU_PARAMS_CAPI_H_
#pragma once

#include "ohos_nweb/capi/ark_web_touch_handle_state_capi.h"

#include "base/capi/ark_web_base_ref_counted_capi.h"
#include "base/include/ark_web_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _ark_web_quick_menu_params_t {
    /**
     * @brief Base structure.
     */
    ark_web_base_ref_counted_t base;

    int32_t(ARK_WEB_CALLBACK* get_xcoord)(struct _ark_web_quick_menu_params_t* self);

    int32_t(ARK_WEB_CALLBACK* get_ycoord)(struct _ark_web_quick_menu_params_t* self);

    int32_t(ARK_WEB_CALLBACK* get_width)(struct _ark_web_quick_menu_params_t* self);

    int32_t(ARK_WEB_CALLBACK* get_height)(struct _ark_web_quick_menu_params_t* self);

    int32_t(ARK_WEB_CALLBACK* get_edit_state_flags)(struct _ark_web_quick_menu_params_t* self);

    int32_t(ARK_WEB_CALLBACK* get_select_x)(struct _ark_web_quick_menu_params_t* self);

    int32_t(ARK_WEB_CALLBACK* get_select_y)(struct _ark_web_quick_menu_params_t* self);

    int32_t(ARK_WEB_CALLBACK* get_select_width)(struct _ark_web_quick_menu_params_t* self);

    int32_t(ARK_WEB_CALLBACK* get_select_xheight)(struct _ark_web_quick_menu_params_t* self);

    ark_web_touch_handle_state_t*(ARK_WEB_CALLBACK* get_touch_handle_state)(
        struct _ark_web_quick_menu_params_t* self, int type);
} ark_web_quick_menu_params_t;

#ifdef __cplusplus
}
#endif

#endif // ARK_WEB_QUICK_MENU_PARAMS_CAPI_H_
