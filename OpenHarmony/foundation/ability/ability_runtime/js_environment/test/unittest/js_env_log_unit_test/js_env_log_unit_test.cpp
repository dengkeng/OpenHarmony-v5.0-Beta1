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

#include <gtest/gtest.h>
#include <cstdarg>

#include "js_env_logger.h"
#include "hilog/log.h"
#include <string>

using namespace testing;
using namespace testing::ext;

#ifndef ENV_LOG_DOMAIN
#define ENV_LOG_DOMAIN 0xD001300
#endif

#ifndef ENV_LOG_TAG
#define ENV_LOG_TAG "JsEnv"
#endif

namespace OHOS {
namespace JsEnv {
void Logger(JsEnvLogLevel level, const char* fileName, const char* functionName, int line,
    const char* fmt, ...)
{
    std::string cFormat = "[%{public}s(%{public}s:%{public}d)]";
    cFormat += fmt;
    va_list printArgs;
    va_start(printArgs, fmt);
    switch (level) {
        case JsEnvLogLevel::DEBUG:
            HILOG_IMPL(LOG_CORE, LOG_DEBUG, ENV_LOG_DOMAIN, ENV_LOG_TAG,
                cFormat.c_str(), fileName, functionName, line, printArgs);
            break;
        case JsEnvLogLevel::INFO:
            HILOG_IMPL(LOG_CORE, LOG_INFO, ENV_LOG_DOMAIN, ENV_LOG_TAG,
                cFormat.c_str(), fileName, functionName, line, printArgs);
            break;
        case JsEnvLogLevel::WARN:
            HILOG_IMPL(LOG_CORE, LOG_WARN, ENV_LOG_DOMAIN, ENV_LOG_TAG,
                cFormat.c_str(), fileName, functionName, line, printArgs);
            break;
        case JsEnvLogLevel::ERROR:
            HILOG_IMPL(LOG_CORE, LOG_ERROR, ENV_LOG_DOMAIN, ENV_LOG_TAG,
                cFormat.c_str(), fileName, functionName, line, printArgs);
            break;
        case JsEnvLogLevel::FATAL:
            HILOG_IMPL(LOG_CORE, LOG_FATAL, ENV_LOG_DOMAIN, ENV_LOG_TAG,
                cFormat.c_str(), fileName, functionName, line, printArgs);
            break;
        default:
            break;
    }
    va_end(printArgs);
}

class JsEnvLogTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void JsEnvLogTest::SetUpTestCase()
{
    JsEnvLogger::logger = Logger;
}

void JsEnvLogTest::TearDownTestCase()
{}

void JsEnvLogTest::SetUp()
{}

void JsEnvLogTest::TearDown()
{}

/**
 * @tc.name: Logger_0100
 * @tc.desc: Logger_0100 Test
 * @tc.type: FUNC
 * @tc.require: issueI6I13A
 */
HWTEST_F(JsEnvLogTest, Logger_0100, TestSize.Level0)
{
    JSENV_LOG_D(">>>>>>>>TestDebug<<<<<<<<<<<");
    JSENV_LOG_I(">>>>>>>>TestInfo<<<<<<<<<<<");
    JSENV_LOG_W(">>>>>>>>TestWarning<<<<<<<<<<<");
    JSENV_LOG_E(">>>>>>>>TestError<<<<<<<<<<<");
    JSENV_LOG_F(">>>>>>>>TestFatal<<<<<<<<<<<");
}

/**
 * @tc.name: Logger_0200
 * @tc.desc: Logger_0200 Test
 * @tc.type: FUNC
 * @tc.require: issueI6I13A
 */
HWTEST_F(JsEnvLogTest, Logger_0200, TestSize.Level0)
{
    JSENV_LOG_D(">>>>>>>>TestDebug<<<<<<<<<<< + %s", "with string");
    JSENV_LOG_I(">>>>>>>>TestInfo<<<<<<<<<<< + %s", "with string");
    JSENV_LOG_W(">>>>>>>>TestWarning<<<<<<<<<<< + %s", "with string");
    JSENV_LOG_E(">>>>>>>>TestError<<<<<<<<<<< + %s + %d", "with int", 32);
    JSENV_LOG_F(">>>>>>>>TestFatal<<<<<<<<<<< + %s", "with string");
}
}  // namespace JsEnv
}  // namespace OHOS
