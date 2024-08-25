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

#include <cstring>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "nweb_log.h"
#include "system_properties_adapter_impl.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::NWeb {
class SystemPropertiesAdapterTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void SystemPropertiesAdapterTest::SetUpTestCase(void)
{}

void SystemPropertiesAdapterTest::TearDownTestCase(void)
{}

void SystemPropertiesAdapterTest::SetUp(void)
{}

void SystemPropertiesAdapterTest::TearDown(void)
{}

class SystemPropertiesObserverTest : public SystemPropertiesObserver {
 public:
   SystemPropertiesObserverTest() = default;
   ~SystemPropertiesObserverTest() override = default;

    void PropertiesUpdate(const char* value) override
    {
        if (strcmp(value, "true") == 0) {
            update_value_ = true;
        } else if (strcmp(value, "false") == 0) {
            update_value_ = false;
        } else {
            WVLOG_E("SystemPropertiesObserverTest return value is invalid");
        }
    }

   bool UpdateValue()
   {
     return update_value_;
   }
 private:
    bool update_value_ = false;
};

/**
 * @tc.name: SystemPropertiesAdapterTest_GetDeviceInfoBrand_001
 * @tc.desc: GetInstance.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SystemPropertiesAdapterTest, SystemPropertiesAdapterTest_GetDeviceInfoBrand_001, TestSize.Level1)
{
    std::string model = SystemPropertiesAdapterImpl::GetInstance().GetDeviceInfoProductModel();
    EXPECT_NE(model, "");
    std::string deviceInfo = SystemPropertiesAdapterImpl::GetInstance().GetDeviceInfoBrand();
    EXPECT_NE(deviceInfo, "");
    int32_t result = SystemPropertiesAdapterImpl::GetInstance().GetDeviceInfoMajorVersion();
    EXPECT_NE(result, -1);
    SystemPropertiesAdapterImpl::GetInstance().GetResourceUseHapPathEnable();
    SystemPropertiesAdapterImpl::GetInstance().GetProductDeviceType();
    bool value = SystemPropertiesAdapterImpl::GetInstance().GetWebOptimizationValue();
    EXPECT_TRUE(value);
    system("param set web.optimization false");
    value = SystemPropertiesAdapterImpl::GetInstance().GetWebOptimizationValue();
    EXPECT_FALSE(value);
    system("param set web.optimization true");
    bool mode = SystemPropertiesAdapterImpl::GetInstance().IsAdvancedSecurityMode();
    EXPECT_FALSE(mode);
    string logMode = SystemPropertiesAdapterImpl::GetInstance().GetNetlogMode();
    EXPECT_EQ(logMode, "None");
    string siteIsolationMode = SystemPropertiesAdapterImpl::GetInstance().GetSiteIsolationMode();
    EXPECT_EQ(siteIsolationMode, "none");
}

/**
 * @tc.name: SystemPropertiesAdapterTest_OptSystemPropertiesObserver_002
 * @tc.desc: AttachSysPropObserver DetachSysPropObserver unittest.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SystemPropertiesAdapterTest, SystemPropertiesAdapterTest_OptSystemPropertiesObserver_002, TestSize.Level1)
{
    system("param set web.render.dump false");
    auto& system_properties_adapter = SystemPropertiesAdapterImpl::GetInstance();
    system_properties_adapter.AttachSysPropObserver(PropertiesKey::PROP_RENDER_DUMP, nullptr);

    auto observer = std::make_shared<SystemPropertiesObserverTest>();
    system_properties_adapter.AttachSysPropObserver(PropertiesKey::PROP_RENDER_DUMP, observer.get());
    system("param set web.render.dump true");
    bool result_first = observer->UpdateValue();
    EXPECT_TRUE(result_first);
    system("param set web.render.dump false");
    bool result_second = observer->UpdateValue();
    EXPECT_FALSE(result_second);

    system_properties_adapter.DetachSysPropObserver(PropertiesKey::PROP_RENDER_DUMP, nullptr);
    system_properties_adapter.DetachSysPropObserver(PropertiesKey::PROP_RENDER_DUMP, observer.get());
    system("param set web.render.dump true");
    bool result_third = observer->UpdateValue();
    EXPECT_FALSE(result_third);
}
} // namespace OHOS
