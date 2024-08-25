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
#ifndef SECURITY_COMPONENT_MOCK_ACCESS_TOKEN_DEF_H
#define SECURITY_COMPONENT_MOCK_ACCESS_TOKEN_DEF_H

namespace OHOS {
namespace Security {
namespace AccessToken {
typedef unsigned int AccessTokenID;
static const AccessTokenID INVALID_TOKENID = 0;

enum AccessTokenKitRet {
    RET_FAILED = -1,
    RET_SUCCESS = 0,
};

typedef enum TypeATokenTypeEnum {
    TOKEN_INVALID = -1,
    TOKEN_HAP = 0,
    TOKEN_NATIVE,
    TOKEN_SHELL,
    TOKEN_TYPE_BUTT,
} ATokenTypeEnum;

typedef enum TypePermissionFlag {
    PERMISSION_DEFAULT_FLAG = 0,
    PERMISSION_USER_SET = 1 << 0,
    PERMISSION_USER_FIXED = 1 << 1,
    PERMISSION_SYSTEM_FIXED = 1 << 2,
    PERMISSION_GRANTED_BY_POLICY = 1 << 3,
    PERMISSION_COMPONENT_SET = 1 << 4,
    PERMISSION_POLICY_FIXED = 1 << 5,
} PermissionFlag;

typedef struct {
    unsigned int tokenUniqueID : 20;
    unsigned int res : 6;
    unsigned int dlpFlag : 1;
    unsigned int type : 2;
    unsigned int version : 3;
} AccessTokenIDInner;
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // SECURITY_COMPONENT_MOCK_ACCESS_TOKEN_DEF_H
