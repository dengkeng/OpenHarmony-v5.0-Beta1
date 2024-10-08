/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef UPDATER_UI_CALLBACK_MANAGER_H
#define UPDATER_UI_CALLBACK_MANAGER_H

#include <functional>
#include <unordered_map>
#include <utility>
#include <vector>
#include "event_listener.h"
#include "json_node.h"
#include "updater_ui_traits.h"

namespace Updater {
class CallbackManager {
public:
    static void Init(bool hasFocus);
    static void Register(const CallbackCfg &cbCfg);
    static bool LoadCallbacks(const JsonNode &node);
    static bool RegisterFunc(const std::string &name, Callback cb);
private:
    static std::unordered_map<std::string, Callback> &GetFuncs();
    static std::unordered_map<std::string, EventType> evtTypes_;
    static std::vector<CallbackCfg> callbackCfgs_;
};

#define DEFINE_CALLBACK(name, async)                                   \
    void name(OHOS::UIView &);                                         \
    static void __attribute((constructor)) RegisterCallback##name()    \
    {                                                                  \
        LOG(INFO) << "register callback " << (#name);                  \
        CallbackManager::RegisterFunc(#name, Callback{&name, async});  \
    }                                                                  \
    void name(OHOS::UIView &)

#define DEFINE_ASYN_CALLBACK(name) DEFINE_CALLBACK(name, true)

#define DEFINE_SYNC_CALLBACK(name) DEFINE_CALLBACK(name, false)
}
#endif
