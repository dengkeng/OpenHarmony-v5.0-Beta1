/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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


#ifndef RESSCHED_SERVICES_RESSCHEDMGR_TEST_UNITTEST_INCLUDE_RES_SCHED_MGR_TEST_H
#define RESSCHED_SERVICES_RESSCHEDMGR_TEST_UNITTEST_INCLUDE_RES_SCHED_MGR_TEST_H

#include <memory>
#include "gtest/gtest.h"
#include "plugin_mgr.h"
#include "res_type.h"
#include "res_sched_mgr.h"

namespace OHOS {
namespace ResourceSchedule {
class ResSchedMgrTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
protected:
    std::shared_ptr<ResData> ReportData(uint32_t resType);
};
} // namespace ResourceSchedule
} // namespace OHOS

#endif // RESSCHED_SERVICES_RESSCHEDMGR_TEST_UNITTEST_INCLUDE_RES_SCHED_MGR_TEST_H
