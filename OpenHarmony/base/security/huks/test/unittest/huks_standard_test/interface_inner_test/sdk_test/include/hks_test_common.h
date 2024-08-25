/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef HKS_TEST_COMMON_H
#define HKS_TEST_COMMON_H

#include "hks_test_common_h.h"
#include "securec.h"

#define GOTO_ERROR_IF_FAIL(ret, err) \
    if ((ret) != 0) { \
        goto (err); \
    }

#define GOTO_ERROR_IF_SUCCESS(ret, err) \
    if ((ret) == 0) { \
        goto (err); \
    }

#define CERT_COUNT 4

#endif