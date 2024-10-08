/*
 * Copyright (c) 2020 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __ADD_AUTH_INFO_H__
#define __ADD_AUTH_INFO_H__

#include "auth_info.h"

#if !(defined(_CUT_STS_) || defined(_CUT_STS_SERVER_) || defined(_CUT_ADD_) || defined(_CUT_ADD_SERVER_))

struct add_auth_data {
    int32_t user_type;
    struct hc_auth_id auth_id;
    struct ltpk ltpk;
    bool permission;
};


#endif /* _CUT_XXX_ */

struct import_auth_data {
    struct hc_auth_id auth_id;
    struct ltpk ltpk;
    struct hc_auth_id owner_id;
    int32_t user_type;
};

#endif /* __ADD_AUTH_INFO_H__ */
