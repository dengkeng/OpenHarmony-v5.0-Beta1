/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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
#include "appfreeze_manager.h"

#include <fcntl.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <fstream>

#include "faultloggerd_client.h"
#include "file_ex.h"
#include "dfx_dump_catcher.h"
#include "directory_ex.h"
#include "hisysevent.h"
#include "hitrace_meter.h"
#include "parameter.h"
#include "singleton.h"

#include "app_mgr_client.h"
#include "hilog_tag_wrapper.h"
#include "hilog_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr char EVENT_UID[] = "UID";
constexpr char EVENT_PID[] = "PID";
constexpr char EVENT_MESSAGE[] = "MSG";
constexpr char EVENT_PACKAGE_NAME[] = "PACKAGE_NAME";
constexpr char EVENT_PROCESS_NAME[] = "PROCESS_NAME";
constexpr char EVENT_STACK[] = "STACK";
constexpr char BINDER_INFO[] = "BINDER_INFO";
constexpr char APP_RUNNING_UNIQUE_ID[] = "APP_RUNNING_UNIQUE_ID";
constexpr int MAX_LAYER = 8;
const std::string LOG_FILE_PATH = "data/log/eventlog";
}
std::shared_ptr<AppfreezeManager> AppfreezeManager::instance_ = nullptr;
ffrt::mutex AppfreezeManager::singletonMutex_;

AppfreezeManager::AppfreezeManager()
{
    name_ = "AppfreezeManager" + std::to_string(GetMilliseconds());
}

AppfreezeManager::~AppfreezeManager()
{
}

std::shared_ptr<AppfreezeManager> AppfreezeManager::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<ffrt::mutex> lock(singletonMutex_);
        if (instance_ == nullptr) {
            instance_ = std::make_shared<AppfreezeManager>();
        }
    }
    return instance_;
}

void AppfreezeManager::DestroyInstance()
{
    std::lock_guard<ffrt::mutex> lock(singletonMutex_);
    if (instance_ != nullptr) {
        instance_.reset();
        instance_ = nullptr;
    }
}

uint64_t AppfreezeManager::GetMilliseconds()
{
    auto now = std::chrono::system_clock::now();
    auto millisecs = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch());
    return millisecs.count();
}

bool AppfreezeManager::IsHandleAppfreeze(const std::string& bundleName)
{
    if (bundleName.empty()) {
        return true;
    }
    return !DelayedSingleton<AppExecFwk::AppMgrClient>::GetInstance()->IsAttachDebug(bundleName);
}

int AppfreezeManager::AppfreezeHandle(const FaultData& faultData, const AppfreezeManager::AppInfo& appInfo)
{
    TAG_LOGD(AAFwkTag::APPDFR, "called %{public}s, bundleName %{public}s, name_ %{public}s",
        faultData.errorObject.name.c_str(), appInfo.bundleName.c_str(), name_.c_str());
    if (!IsHandleAppfreeze(appInfo.bundleName)) {
        return -1;
    }
    HITRACE_METER_FMT(HITRACE_TAG_APP, "AppfreezeHandler:%{public}s bundleName:%{public}s",
        faultData.errorObject.name.c_str(), appInfo.bundleName.c_str());
    if (faultData.errorObject.name == AppFreezeType::APP_INPUT_BLOCK) {
        AcquireStack(faultData, appInfo);
    } else {
        NotifyANR(faultData, appInfo, "");
    }
    return 0;
}

int AppfreezeManager::AppfreezeHandleWithStack(const FaultData& faultData, const AppfreezeManager::AppInfo& appInfo)
{
    TAG_LOGD(AAFwkTag::APPDFR, "called %{public}s, bundleName %{public}s, name_ %{public}s",
        faultData.errorObject.name.c_str(), appInfo.bundleName.c_str(), name_.c_str());
    if (!IsHandleAppfreeze(appInfo.bundleName)) {
        return -1;
    }
    FaultData faultNotifyData;
    faultNotifyData.errorObject.name = faultData.errorObject.name;
    faultNotifyData.errorObject.message = faultData.errorObject.message;
    faultNotifyData.errorObject.stack = faultData.errorObject.stack;
    faultNotifyData.faultType = FaultDataType::APP_FREEZE;

    HITRACE_METER_FMT(HITRACE_TAG_APP, "AppfreezeHandleWithStack pid:%d-name:%s",
        appInfo.pid, faultData.errorObject.name.c_str());

    std::string fileName = faultData.errorObject.name + "_" + std::to_string(appInfo.pid) + "_stack";
    std::string catcherStack = "";
    std::string catchJsonStack = "";
    std::string fullStackPath = "";

    if (faultData.errorObject.name == AppFreezeType::LIFECYCLE_HALF_TIMEOUT
        || faultData.errorObject.name == AppFreezeType::LIFECYCLE_TIMEOUT) {
        catcherStack += CatcherStacktrace(appInfo.pid);
        fullStackPath = WriteToFile(fileName, catcherStack);
        faultNotifyData.errorObject.stack = fullStackPath;
    } else {
        catchJsonStack += CatchJsonStacktrace(appInfo.pid);
        fullStackPath = WriteToFile(fileName, catchJsonStack);
        faultNotifyData.errorObject.stack = fullStackPath;
    }

    if (faultNotifyData.errorObject.name == AppFreezeType::APP_INPUT_BLOCK) {
        AcquireStack(faultNotifyData, appInfo);
    } else {
        NotifyANR(faultNotifyData, appInfo, "");
    }
    return 0;
}

std::string AppfreezeManager::WriteToFile(const std::string& fileName, std::string& content)
{
    std::string dir_path = LOG_FILE_PATH + "/freeze";
    constexpr mode_t defaultLogDirMode = 0770;
    if (!OHOS::FileExists(dir_path)) {
        OHOS::ForceCreateDirectory(dir_path);
        OHOS::ChangeModeDirectory(dir_path, defaultLogDirMode);
    }

    std::string stackPath = dir_path + "/" + fileName;
    constexpr mode_t defaultLogFileMode = 0664;
    auto fd = open(stackPath.c_str(), O_CREAT | O_WRONLY | O_TRUNC, defaultLogFileMode);
    if (fd < 0) {
        TAG_LOGI(AAFwkTag::APPDFR, "Failed to create stackPath");
        return "";
    } else {
        TAG_LOGI(AAFwkTag::APPDFR, "stackPath = %{public}s", stackPath.c_str());
    }
    OHOS::SaveStringToFd(fd, content);
    close(fd);
    return stackPath;
}

int AppfreezeManager::LifecycleTimeoutHandle(const ParamInfo& info, std::unique_ptr<FreezeUtil::LifecycleFlow> flow)
{
    if (info.typeId != AppfreezeManager::TypeAttribute::CRITICAL_TIMEOUT) {
        return -1;
    }
    if (!IsHandleAppfreeze(info.bundleName)) {
        return -1;
    }
    if (info.eventName != AppFreezeType::LIFECYCLE_TIMEOUT &&
        info.eventName != AppFreezeType::LIFECYCLE_HALF_TIMEOUT) {
        return -1;
    }
    TAG_LOGD(AAFwkTag::APPDFR, "LifecycleTimeoutHandle called %{public}s, name_ %{public}s", info.bundleName.c_str(),
        name_.c_str());
    HITRACE_METER_FMT(HITRACE_TAG_APP, "LifecycleTimeoutHandle:%{public}s bundleName:%{public}s",
        info.eventName.c_str(), info.bundleName.c_str());
    AppFaultDataBySA faultDataSA;
    faultDataSA.errorObject.name = info.eventName;
    faultDataSA.errorObject.message = info.msg;
    faultDataSA.faultType = FaultDataType::APP_FREEZE;
    faultDataSA.timeoutMarkers = "notifyFault" +
                                 std::to_string(info.pid) +
                                 "-" + std::to_string(GetMilliseconds());
    faultDataSA.pid = info.pid;
    if (flow != nullptr && flow->state != AbilityRuntime::FreezeUtil::TimeoutState::UNKNOWN) {
        faultDataSA.token = flow->token;
        faultDataSA.state = static_cast<uint32_t>(flow->state);
    }
    DelayedSingleton<AppExecFwk::AppMgrClient>::GetInstance()->NotifyAppFaultBySA(faultDataSA);
    return 0;
}

int AppfreezeManager::AcquireStack(const FaultData& faultData, const AppfreezeManager::AppInfo& appInfo)
{
    int ret = 0;
    int pid = appInfo.pid;
    FaultData faultNotifyData;
    faultNotifyData.errorObject.name = faultData.errorObject.name;
    faultNotifyData.errorObject.message = faultData.errorObject.message;
    faultNotifyData.errorObject.stack = faultData.errorObject.stack;
    faultNotifyData.faultType = FaultDataType::APP_FREEZE;
    std::string binderInfo;
    std::set<int> pids = GetBinderPeerPids(binderInfo, pid);
    if (pids.empty()) {
        binderInfo += "PeerBinder pids is empty\n";
    }
    for (auto& pidTemp : pids) {
        TAG_LOGI(AAFwkTag::APPDFR, "pidTemp pids:%{public}d", pidTemp);
        if (pidTemp != pid) {
            std::string content = "PeerBinder catcher stacktrace for pid : " + std::to_string(pidTemp) + "\n";
            content += CatcherStacktrace(pidTemp);
            binderInfo += content;
        }
    }

    std::string fileName = faultData.errorObject.name + "_" + std::to_string(appInfo.pid) + "_binder";
    std::string fullStackPath = WriteToFile(fileName, binderInfo);
    binderInfo = fullStackPath;

    ret = NotifyANR(faultNotifyData, appInfo, binderInfo);
    return ret;
}

int AppfreezeManager::NotifyANR(const FaultData& faultData, const AppfreezeManager::AppInfo& appInfo,
    const std::string& binderInfo)
{
    std::string appRunningUniqueId = "";
    DelayedSingleton<AppExecFwk::AppMgrClient>::GetInstance()->GetAppRunningUniqueIdByPid(appInfo.pid,
        appRunningUniqueId);

    int ret = HiSysEventWrite(OHOS::HiviewDFX::HiSysEvent::Domain::AAFWK, faultData.errorObject.name,
        OHOS::HiviewDFX::HiSysEvent::EventType::FAULT, EVENT_UID, appInfo.uid, EVENT_PID, appInfo.pid,
        EVENT_PACKAGE_NAME, appInfo.bundleName, EVENT_PROCESS_NAME, appInfo.processName, EVENT_MESSAGE,
        faultData.errorObject.message, EVENT_STACK, faultData.errorObject.stack, BINDER_INFO, binderInfo,
        APP_RUNNING_UNIQUE_ID, appRunningUniqueId);

    TAG_LOGI(AAFwkTag::APPDFR,
        "reportEvent:%{public}s, pid:%{public}d, bundleName:%{public}s, appRunningUniqueId:%{public}s "
        "hisysevent write ret = %{public}d.",
        faultData.errorObject.name.c_str(), appInfo.pid, appInfo.bundleName.c_str(), appRunningUniqueId.c_str(), ret);
    return 0;
}

std::map<int, std::set<int>> AppfreezeManager::BinderParser(std::ifstream& fin, std::string& stack) const
{
    std::map<int, std::set<int>> binderInfo;
    const int decimal = 10;
    std::string line;
    bool isBinderMatchup = false;
    TAG_LOGI(AAFwkTag::APPDFR, "start");
    stack += "BinderCatcher --\n\n";
    while (getline(fin, line)) {
        stack += line + "\n";
        if (isBinderMatchup) {
            continue;
        }

        if (line.find("async") != std::string::npos) {
            continue;
        }

        std::istringstream lineStream(line);
        std::vector<std::string> strList;
        std::string tmpstr;
        while (lineStream >> tmpstr) {
            strList.push_back(tmpstr);
        }

        auto SplitPhase = [](const std::string& str, uint16_t index) -> std::string {
            std::vector<std::string> strings;
            SplitStr(str, ":", strings);
            if (index < strings.size()) {
                return strings[index];
            }
            return "";
        };

        if (strList.size() >= 7) { // 7: valid array size
            // 2: peer id,
            std::string server = SplitPhase(strList[2], 0);
            // 0: local id,
            std::string client = SplitPhase(strList[0], 0);
            // 5: wait time, s
            std::string wait = SplitPhase(strList[5], 1);
            if (server == "" || client == "" || wait == "") {
                continue;
            }
            int serverNum = std::strtol(server.c_str(), nullptr, decimal);
            int clientNum = std::strtol(client.c_str(), nullptr, decimal);
            int waitNum = std::strtol(wait.c_str(), nullptr, decimal);
            TAG_LOGI(AAFwkTag::APPDFR, "server:%{public}d, client:%{public}d, wait:%{public}d", serverNum, clientNum,
                waitNum);
            binderInfo[clientNum].insert(serverNum);
        }
        if (line.find("context") != line.npos) {
            isBinderMatchup = true;
        }
    }
    TAG_LOGI(AAFwkTag::APPDFR, "binderInfo size: %{public}zu", binderInfo.size());
    return binderInfo;
}

std::set<int> AppfreezeManager::GetBinderPeerPids(std::string& stack, int pid) const
{
    std::set<int> pids;
    std::ifstream fin;
    std::string path = LOGGER_DEBUG_PROC_PATH;
    char resolvePath[PATH_MAX] = {0};
    if (realpath(path.c_str(), resolvePath) == nullptr) {
        TAG_LOGE(AAFwkTag::APPDFR, "GetBinderPeerPids realpath error");
        return pids;
    }
    fin.open(resolvePath);
    if (!fin.is_open()) {
        TAG_LOGE(AAFwkTag::APPDFR, "open file failed, %{public}s.", resolvePath);
        stack += "open file failed :" + path + "\r\n";
        return pids;
    }

    stack += "\n\nPeerBinderCatcher -- pid==" + std::to_string(pid) + "\n\n";
    std::map<int, std::set<int>> binderInfo = BinderParser(fin, stack);
    fin.close();

    if (binderInfo.size() == 0 || binderInfo.find(pid) == binderInfo.end()) {
        return pids;
    }

    ParseBinderPids(binderInfo, pids, pid, 0);
    for (auto& each : pids) {
        TAG_LOGD(AAFwkTag::APPDFR, "each pids:%{public}d", each);
    }
    return pids;
}

void AppfreezeManager::ParseBinderPids(const std::map<int, std::set<int>>& binderInfo,
    std::set<int>& pids, int pid, int layer) const
{
    auto it = binderInfo.find(pid);
    layer++;
    if (layer >= MAX_LAYER) {
        return;
    }
    if (it != binderInfo.end()) {
        for (auto& each : it->second) {
            pids.insert(each);
            ParseBinderPids(binderInfo, pids, each, layer);
        }
    }
}

std::string AppfreezeManager::CatchJsonStacktrace(int pid) const
{
    HITRACE_METER_FMT(HITRACE_TAG_APP, "CatchJsonStacktrace pid:%d", pid);
    HiviewDFX::DfxDumpCatcher dumplog;
    std::string ret;
    std::string msg;
    size_t defaultMaxFaultNum = 256;
    if (!dumplog.DumpCatch(pid, 0, msg, defaultMaxFaultNum, true)) {
        ret = "Failed to dump stacktrace for " + std::to_string(pid) + "\n" + msg;
    } else {
        ret = msg;
    }
    return ret;
}

std::string AppfreezeManager::CatcherStacktrace(int pid) const
{
    HITRACE_METER_FMT(HITRACE_TAG_APP, "CatcherStacktrace pid:%d", pid);
    HiviewDFX::DfxDumpCatcher dumplog;
    std::string ret;
    std::string msg;
    if (!dumplog.DumpCatch(pid, 0, msg)) {
        ret = "Failed to dump stacktrace for " + std::to_string(pid) + "\n" + msg;
    } else {
        ret = msg;
    }
    return ret;
}

bool AppfreezeManager::IsProcessDebug(int32_t pid, std::string processName)
{
    const int buffSize = 128;
    char param[buffSize] = {0};
    std::string filter = "hiviewdfx.freeze.filter." + processName;
    GetParameter(filter.c_str(), "", param, buffSize - 1);
    int32_t debugPid = atoi(param);
    if (debugPid == pid) {
        TAG_LOGI(AAFwkTag::APPDFR, "appfreeze filtration %{public}s_%{public}d don't exit.",
            processName.c_str(), debugPid);
        return true;
    }

    char paramBundle[buffSize] = {0};
    GetParameter("hiviewdfx.appfreeze.filter_bundle_name", "", paramBundle, buffSize - 1);
    std::string debugBundle(paramBundle);

    if (processName.compare(debugBundle) == 0) {
        TAG_LOGI(AAFwkTag::APPDFR, "appfreeze filtration %{public}s_%{public}s don't exit.",
            debugBundle.c_str(), processName.c_str());
        return true;
    }
    return false;
}
}  // namespace AAFwk
}  // namespace OHOS