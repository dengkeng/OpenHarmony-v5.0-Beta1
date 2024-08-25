/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef OHOS_DM_DFX_TEST_H
#define OHOS_DM_DFX_TEST_H

#include <map>
#include <string>
#include <gtest/gtest.h>

#include "dm_anonymous.h"
#include "dm_constants.h"
#include "dm_error_message.h"
#include "dm_log.h"
#include "dm_hidumper.h"
#include "dm_hisysevent.h"
#include "dm_hitrace.h"
#include "hitrace_meter.h"

namespace OHOS {
namespace DistributedHardware {
class DmDfxTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};
} // namespace DistributedHardware
} // namespace OHOS
#endif
