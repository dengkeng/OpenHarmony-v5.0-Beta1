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

#include "getusergrantedpermissionusedtype_fuzzer.h"

#include <iostream>
#include <thread>
#include <string>
#include <vector>
#undef private
#include "accesstoken_kit.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
bool GetUserGrantedPermissionUsedTypeFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }
    AccessTokenID tokenId = static_cast<AccessTokenID>(size);
    std::string permissionName(reinterpret_cast<const char*>(data), size);

    PermUsedTypeEnum type = AccessTokenKit::GetUserGrantedPermissionUsedType(tokenId, permissionName);

    return type != PermUsedTypeEnum::PERM_USED_TYPE_BUTT;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::GetUserGrantedPermissionUsedTypeFuzzTest(data, size);
    return 0;
}
