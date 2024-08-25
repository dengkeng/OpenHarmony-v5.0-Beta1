/*
* Copyright (c) 2023 Shenzhen Kaihong Digital Industry Development Co., Ltd.
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
#include "NodeISayHello.h"
#include "../generatorCode/napitest.h"
#include "hilog/log.h"
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, 0XD002E00, "NAPITESTNAPILayer"};
#define NAPITEST_LOGI(fmt, ...) OHOS::HiviewDFX::HiLog::Info(LABEL, \
    	"%{public}s:%{public}d " fmt, __func__, __LINE__, ##__VA_ARGS__)
	
namespace napitest {
  // 1. 打印from, to, enum sayType的值
  // 2. 调用注册的NodeISayHelloListenerSayHelloStart(info: SayInfo)方法
  //    工具提供的业务接口（回调） void NodeISayHello::SayHelloListenerSayHelloStartCallback(SayInfo& info)
  // 3. 调用注册的NodeISayHelloListenerSayHelloEnd(info: SayInfo)方法
  //    工具提供的业务接口（回调） void NodeISayHello::SayHelloListenerSayHelloEndCallback(SayInfo& info)
void NodeISayHello::sayHello(std::string& from, std::string& to, uint32_t& sayType)
{
    // 1.打印
    NAPITEST_LOGI("NAPITEST_LOGI sayHello from = %s\r\n", from.c_str());
    NAPITEST_LOGI("NAPITEST_LOGI sayHello to = %s\r\n", to.c_str());
    NAPITEST_LOGI("NAPITEST_LOGI sayHello sayType = %d\r\n", sayType);
   
    // 2.调用回调
    napitest::napitest_interface::SayInfo info1;
    info1.from = "js1";
    uint32_t a = 992;
    info1.fromId.emplace(a);
    uint32_t b = 1014;
    info1.toId.emplace(b);
    info1.to = "native1";
    info1.content = "hello1";
    info1.saidTime = "123456789";
    info1.isEnd = false;

    napitest::napitest_interface::SayInfo info2;
    info2.from = "native";
    uint32_t c = 101;
    info2.fromId.emplace(c);
    uint32_t d = 99;
    info2.toId.emplace(d);
    info2.to = "js";
    info2.content = "hello";
    info2.saidTime = "987654321";
    info2.isEnd = true;
    // 业务代码调用 onSayHelloStart callback
    NAPITEST_LOGI("NAPITEST_LOGI NodeISayHelloListener_onSayHelloStartCallback begin\r\n");
    napitest::napitest_interface::NodeISayHello::listener_.NodeISayHelloListener_onSayHelloStartCallback(info1);
    NAPITEST_LOGI("NAPITEST_LOGI NodeISayHelloListener_onSayHelloStartCallback end\r\n");
    // 业务代码调用 onSayHelloEnd callback
    NAPITEST_LOGI("NAPITEST_LOGI NodeISayHelloListener_onSayHelloEndCallback begin\r\n");
    napitest::napitest_interface::NodeISayHello::listener_.NodeISayHelloListener_onSayHelloEndCallback(info2);
    NAPITEST_LOGI("NAPITEST_LOGI NodeISayHelloListener_onSayHelloEndCallback end\r\n");
    return;
}

// 调用register注册的回调
void NodeISayHello::sayHi(std::string& from, std::string& to, uint32_t& sayType)
{
    // 1.打印
    NAPITEST_LOGI("NAPITEST_LOGI sayHi from = %s\r\n", from.c_str());
    NAPITEST_LOGI("NAPITEST_LOGI sayHi to = %s\r\n", to.c_str());
    NAPITEST_LOGI("NAPITEST_LOGI sayHi sayType = %d\r\n", sayType);
    // 2.调用回调
    napitest::napitest_interface::NodeISayHello *ptr = new napitest::napitest_interface::NodeISayHello();
    uint32_t callbackNum = 50;
    ptr->CallbackfuncCallback(callbackNum);
    delete ptr;
    return;
}

// 普通函数调用，返回str
std::string funcTest(bool& v)
{
    if (v) {
        return "ret is true";
    } else {
        return "ret is false";
    }
}

// 1.打印值：from, to 以及枚举enum SayType的值
// 2. 将回调值（0， "", "recv hello."）的值传回Js层
void NodeISayHello::sayHelloWithResponse(std::string& from, std::string& to, uint32_t& sayType)
{
    // 1.打印
    NAPITEST_LOGI("NAPITEST_LOGI sayHelloWithResponse from = %s\r\n", from.c_str());
    NAPITEST_LOGI("NAPITEST_LOGI sayHelloWithResponse to = %s\r\n", to.c_str());
    NAPITEST_LOGI("NAPITEST_LOGI sayHelloWithResponse sayType = %d\r\n", sayType);
    // 2.调用promise回调 (0, "", "recv hello.")
    napitest::napitest_interface::NodeISayHello *p = new  napitest::napitest_interface::NodeISayHello();
    // 调用工具接口将回调传回工具
    p->auto_interface_5SetCbValue(0, "", "recv hello.");
    delete p;
    return;
}
}
