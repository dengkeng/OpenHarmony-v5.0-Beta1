/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_IMS_SERIVCE_TEST_H
#define OHOS_IMS_SERIVCE_TEST_H

#include <gtest/gtest.h>
#include <map>

#include "ims_call_interface.h"
#include "ims_core_service_interface.h"
#include "ims_sms_interface.h"
#include "singleton.h"

namespace OHOS {
namespace Telephony {
class ImsServiceTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static int32_t InitConditionCheck();
    static void Init();
    bool HasSimCard(int32_t slotId);

    static sptr<ImsCallInterface> imsCallPtr_;
    static sptr<ImsSmsInterface> imsSmsPtr_;
    static sptr<ImsCoreServiceInterface> imsCoreServicePtr_;

    static ImsCallInfo callInfoForSlot0_;
    static ImsCallInfo callInfoForSlot1_;
    static std::vector<std::string> numberList_;
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_IMS_SERIVCE_TEST_H