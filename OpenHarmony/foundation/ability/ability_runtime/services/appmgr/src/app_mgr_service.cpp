/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "app_mgr_service.h"

#include <chrono>
#include <nlohmann/json.hpp>
#include <sys/types.h>
#include <thread>

#include "app_death_recipient.h"
#include "app_mgr_constants.h"
#include "datetime_ex.h"
#include "global_constant.h"
#include "hilog_tag_wrapper.h"
#include "hitrace_meter.h"
#include "in_process_call_wrapper.h"
#include "ipc_skeleton.h"
#include "perf_profile.h"
#include "permission_constants.h"
#include "permission_verification.h"
#include "system_ability_definition.h"
#include "base/security/access_token/interfaces/innerkits/accesstoken/include/accesstoken_kit.h"
#include "app_mgr_service_const.h"
#include "app_mgr_service_dump_error_code.h"

namespace OHOS {
namespace AppExecFwk {
const std::string OPTION_KEY_HELP = "-h";
const std::string OPTION_KEY_DUMP_IPC = "--ipc";
const int32_t HIDUMPER_SERVICE_UID = 1212;
constexpr const int INDEX_PID = 1;
constexpr const int INDEX_CMD = 2;
constexpr const size_t VALID_DUMP_IPC_ARG_SIZE = 3;
namespace {
using namespace std::chrono_literals;
#ifdef ABILITY_COMMAND_FOR_TEST
static const int APP_MS_BLOCK = 65;
#endif
const std::string TASK_INIT_APPMGRSERVICEINNER = "InitAppMgrServiceInnerTask";
const std::string TASK_ATTACH_APPLICATION = "AttachApplicationTask";
const std::string TASK_APPLICATION_FOREGROUNDED = "ApplicationForegroundedTask";
const std::string TASK_APPLICATION_BACKGROUNDED = "ApplicationBackgroundedTask";
const std::string TASK_APPLICATION_TERMINATED = "ApplicationTerminatedTask";
const std::string TASK_ABILITY_CLEANED = "AbilityCleanedTask";
const std::string TASK_ADD_APP_DEATH_RECIPIENT = "AddAppRecipientTask";
const std::string TASK_CLEAR_UP_APPLICATION_DATA = "ClearUpApplicationDataTask";
const std::string TASK_STARTUP_RESIDENT_PROCESS = "StartupResidentProcess";
const std::string TASK_ADD_ABILITY_STAGE_DONE = "AddAbilityStageDone";
const std::string TASK_START_USER_TEST_PROCESS = "StartUserTestProcess";
const std::string TASK_FINISH_USER_TEST = "FinishUserTest";
const std::string TASK_ATTACH_RENDER_PROCESS = "AttachRenderTask";
const std::string TASK_ATTACH_CHILD_PROCESS = "AttachChildProcessTask";
const std::string TASK_EXIT_CHILD_PROCESS_SAFELY = "ExitChildProcessSafelyTask";
const std::string FOUNDATION_PROCESS = "foundation";
constexpr int32_t USER_UID = 2000;
}  // namespace

REGISTER_SYSTEM_ABILITY_BY_ID(AppMgrService, APP_MGR_SERVICE_ID, true);

const std::map<std::string, AppMgrService::DumpIpcKey> AppMgrService::dumpIpcMap = {
    std::map<std::string, AppMgrService::DumpIpcKey>::value_type("--start-stat", KEY_DUMP_IPC_START),
    std::map<std::string, AppMgrService::DumpIpcKey>::value_type("--stop-stat", KEY_DUMP_IPC_STOP),
    std::map<std::string, AppMgrService::DumpIpcKey>::value_type("--stat", KEY_DUMP_IPC_STAT),
};

void AppMgrService::DumpIpcAllFuncInit()
{
    dumpIpcAllFuncMap_[KEY_DUMP_IPC_START] = &AppMgrService::DumpIpcAllStart;
    dumpIpcAllFuncMap_[KEY_DUMP_IPC_STOP] = &AppMgrService::DumpIpcAllStop;
    dumpIpcAllFuncMap_[KEY_DUMP_IPC_STAT] = &AppMgrService::DumpIpcAllStat;
}

void AppMgrService::DumpIpcFuncInit()
{
    dumpIpcFuncMap_[KEY_DUMP_IPC_START] = &AppMgrService::DumpIpcStart;
    dumpIpcFuncMap_[KEY_DUMP_IPC_STOP] = &AppMgrService::DumpIpcStop;
    dumpIpcFuncMap_[KEY_DUMP_IPC_STAT] = &AppMgrService::DumpIpcStat;
}

AppMgrService::AppMgrService()
{
    appMgrServiceInner_ = std::make_shared<AppMgrServiceInner>();
    TAG_LOGI(AAFwkTag::APPMGR, "instance created with no para");
    PerfProfile::GetInstance().SetAmsLoadStartTime(GetTickCount());
    DumpIpcAllFuncInit();
    DumpIpcFuncInit();
}

AppMgrService::AppMgrService(const int32_t serviceId, bool runOnCreate) : SystemAbility(serviceId, runOnCreate)
{
    appMgrServiceInner_ = std::make_shared<AppMgrServiceInner>();
    TAG_LOGI(AAFwkTag::APPMGR, "instance created");
    PerfProfile::GetInstance().SetAmsLoadStartTime(GetTickCount());
    DumpIpcAllFuncInit();
    DumpIpcFuncInit();
}

AppMgrService::~AppMgrService()
{
    TAG_LOGI(AAFwkTag::APPMGR, "instance destroyed");
}

void AppMgrService::OnStart()
{
    TAG_LOGI(AAFwkTag::APPMGR, "ready to start service");
    if (appMgrServiceState_.serviceRunningState == ServiceRunningState::STATE_RUNNING) {
        TAG_LOGW(AAFwkTag::APPMGR, "failed to start service since it's already running");
        return;
    }

    ErrCode errCode = Init();
    if (FAILED(errCode)) {
        TAG_LOGE(AAFwkTag::APPMGR, "init failed, errCode: %{public}08x", errCode);
        return;
    }
    appMgrServiceState_.serviceRunningState = ServiceRunningState::STATE_RUNNING;
    AddSystemAbilityListener(WINDOW_MANAGER_SERVICE_ID);
    TAG_LOGI(AAFwkTag::APPMGR, "start service success");
    PerfProfile::GetInstance().SetAmsLoadEndTime(GetTickCount());
    PerfProfile::GetInstance().Dump();
}

void AppMgrService::OnStop()
{
    TAG_LOGI(AAFwkTag::APPMGR, "ready to stop service");
    appMgrServiceState_.serviceRunningState = ServiceRunningState::STATE_NOT_START;
    eventHandler_.reset();
    taskHandler_.reset();
    if (appMgrServiceInner_) {
        appMgrServiceInner_->OnStop();
    }
    TAG_LOGI(AAFwkTag::APPMGR, "stop service success");
}

void AppMgrService::SetInnerService(const std::shared_ptr<AppMgrServiceInner> &innerService)
{
    appMgrServiceInner_ = innerService;
}

AppMgrServiceState AppMgrService::QueryServiceState()
{
    if (appMgrServiceInner_) {
        appMgrServiceState_.connectionState = appMgrServiceInner_->QueryAppSpawnConnectionState();
    }
    return appMgrServiceState_;
}

ErrCode AppMgrService::Init()
{
    TAG_LOGI(AAFwkTag::APPMGR, "ready to init");
    if (!appMgrServiceInner_) {
        TAG_LOGE(AAFwkTag::APPMGR, "init failed without inner service");
        return ERR_INVALID_OPERATION;
    }

    taskHandler_ = AAFwk::TaskHandlerWrap::CreateQueueHandler("app_mgr_task_queue");
    eventHandler_ = std::make_shared<AMSEventHandler>(taskHandler_, appMgrServiceInner_);
    appMgrServiceInner_->SetTaskHandler(taskHandler_);
    appMgrServiceInner_->SetEventHandler(eventHandler_);
    std::function<void()> initAppMgrServiceInnerTask =
        std::bind(&AppMgrServiceInner::Init, appMgrServiceInner_);
    taskHandler_->SubmitTask(initAppMgrServiceInnerTask, TASK_INIT_APPMGRSERVICEINNER);

    ErrCode openErr = appMgrServiceInner_->OpenAppSpawnConnection();
    if (FAILED(openErr)) {
        TAG_LOGW(AAFwkTag::APPMGR, "failed to connect to AppSpawnDaemon! errCode: %{public}08x", openErr);
    }
    if (!Publish(this)) {
        TAG_LOGE(AAFwkTag::APPMGR, "failed to publish app mgr service to systemAbilityMgr");
        return ERR_APPEXECFWK_SERVICE_NOT_CONNECTED;
    }
    amsMgrScheduler_ = new (std::nothrow) AmsMgrScheduler(appMgrServiceInner_, taskHandler_);
    if (!amsMgrScheduler_) {
        TAG_LOGE(AAFwkTag::APPMGR, "init failed without ability manager service scheduler");
        return ERR_INVALID_OPERATION;
    }
    TAG_LOGI(AAFwkTag::APPMGR, "init success");
    return ERR_OK;
}

void AppMgrService::AttachApplication(const sptr<IRemoteObject> &app)
{
    TAG_LOGD(AAFwkTag::APPMGR, "called");
    if (!IsReady()) {
        TAG_LOGE(AAFwkTag::APPMGR, "AttachApplication failed, not ready.");
        return;
    }

    pid_t pid = IPCSkeleton::GetCallingRealPid();
    std::function<void()> attachApplicationFunc =
        std::bind(&AppMgrServiceInner::AttachApplication, appMgrServiceInner_, pid, iface_cast<IAppScheduler>(app));
    taskHandler_->SubmitTask(attachApplicationFunc, AAFwk::TaskAttribute{
        .taskName_ = TASK_ATTACH_APPLICATION,
        .taskQos_ = AAFwk::TaskQoS::USER_INTERACTIVE
    });
}

int32_t AppMgrService::PreloadApplication(const std::string &bundleName, int32_t userId,
    AppExecFwk::PreloadMode preloadMode, int32_t appIndex)
{
    TAG_LOGD(AAFwkTag::APPMGR, "PreloadApplication called");
    if (!IsReady()) {
        TAG_LOGE(AAFwkTag::APPMGR, "PreloadApplication failed, appMgr not ready.");
        return ERR_INVALID_OPERATION;
    }
    return appMgrServiceInner_->PreloadApplication(bundleName, userId, preloadMode, appIndex);
}

void AppMgrService::ApplicationForegrounded(const int32_t recordId)
{
    if (!IsReady()) {
        return;
    }
    if (!JudgeAppSelfCalled(recordId)) {
        return;
    }
    std::function<void()> applicationForegroundedFunc =
        std::bind(&AppMgrServiceInner::ApplicationForegrounded, appMgrServiceInner_, recordId);
    taskHandler_->SubmitTask(applicationForegroundedFunc, AAFwk::TaskAttribute{
        .taskName_ = TASK_APPLICATION_FOREGROUNDED,
        .taskQos_ = AAFwk::TaskQoS::USER_INTERACTIVE
    });
}

void AppMgrService::ApplicationBackgrounded(const int32_t recordId)
{
    if (!IsReady()) {
        return;
    }
    if (!JudgeAppSelfCalled(recordId)) {
        return;
    }
    std::function<void()> applicationBackgroundedFunc =
        std::bind(&AppMgrServiceInner::ApplicationBackgrounded, appMgrServiceInner_, recordId);
    taskHandler_->SubmitTask(applicationBackgroundedFunc, AAFwk::TaskAttribute{
        .taskName_ = TASK_APPLICATION_BACKGROUNDED,
        .taskQos_ = AAFwk::TaskQoS::USER_INTERACTIVE
    });
}

void AppMgrService::ApplicationTerminated(const int32_t recordId)
{
    if (!IsReady()) {
        return;
    }
    if (!JudgeAppSelfCalled(recordId)) {
        return;
    }
    std::function<void()> applicationTerminatedFunc =
        std::bind(&AppMgrServiceInner::ApplicationTerminated, appMgrServiceInner_, recordId);
    taskHandler_->SubmitTask(applicationTerminatedFunc, AAFwk::TaskAttribute{
        .taskName_ = TASK_APPLICATION_TERMINATED,
        .taskQos_ = AAFwk::TaskQoS::USER_INTERACTIVE
    });
}

void AppMgrService::AbilityCleaned(const sptr<IRemoteObject> &token)
{
    if (!IsReady()) {
        return;
    }

    auto callerUid = IPCSkeleton::GetCallingUid();
    auto appRecord = appMgrServiceInner_->GetTerminatingAppRunningRecord(token);
    if (!appRecord || appRecord->GetUid() != callerUid) {
        TAG_LOGE(AAFwkTag::APPMGR, "Permission verification failed.");
        return;
    }

    std::function<void()> abilityCleanedFunc =
        std::bind(&AppMgrServiceInner::AbilityTerminated, appMgrServiceInner_, token);
    taskHandler_->SubmitTask(abilityCleanedFunc, AAFwk::TaskAttribute{
        .taskName_ = TASK_ABILITY_CLEANED,
        .taskQos_ = AAFwk::TaskQoS::USER_INTERACTIVE
    });
}

bool AppMgrService::IsReady() const
{
    if (appMgrServiceInner_ && taskHandler_ && eventHandler_) {
        return true;
    }

    TAG_LOGW(AAFwkTag::APPMGR, "Not ready");
    return false;
}

void AppMgrService::StartupResidentProcess(const std::vector<AppExecFwk::BundleInfo> &bundleInfos)
{
    if (!IsReady()) {
        return;
    }
    pid_t callingPid = IPCSkeleton::GetCallingRealPid();
    pid_t pid = getprocpid();
    if (callingPid != pid) {
        TAG_LOGE(AAFwkTag::APPMGR, "Not this process call.");
        return;
    }
    TAG_LOGI(AAFwkTag::APPMGR, "Notify start resident process");
    std::function <void()> startupResidentProcess =
        std::bind(&AppMgrServiceInner::LoadResidentProcess, appMgrServiceInner_, bundleInfos);
    taskHandler_->SubmitTask(startupResidentProcess, AAFwk::TaskAttribute{
        .taskName_ = TASK_STARTUP_RESIDENT_PROCESS,
        .taskQos_ = AAFwk::TaskQoS::USER_INTERACTIVE
    });
}

sptr<IAmsMgr> AppMgrService::GetAmsMgr()
{
    return amsMgrScheduler_;
}

int32_t AppMgrService::ClearUpApplicationData(const std::string &bundleName, const int32_t userId)
{
    if (!IsReady()) {
        return ERR_INVALID_OPERATION;
    }
    std::shared_ptr<RemoteClientManager> remoteClientManager = std::make_shared<RemoteClientManager>();
    if (remoteClientManager == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "The remoteClientManager is nullptr.");
        return ERR_INVALID_OPERATION;
    }
    auto bundleMgrHelper = remoteClientManager->GetBundleManagerHelper();
    if (bundleMgrHelper == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "The bundleMgrHelper is nullptr.");
        return ERR_INVALID_OPERATION;
    }
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    if ((callingUid != 0 && callingUid != USER_UID) || userId < 0) {
        std::string callerBundleName;
        auto result = IN_PROCESS_CALL(bundleMgrHelper->GetNameForUid(callingUid, callerBundleName));
        if (result != ERR_OK) {
            TAG_LOGE(AAFwkTag::APPMGR, "GetBundleName failed: %{public}d.", result);
            return ERR_INVALID_OPERATION;
        }
        auto isCallingPerm = AAFwk::PermissionVerification::GetInstance()->VerifyCallingPermission(
            AAFwk::PermissionConstants::PERMISSION_CLEAN_APPLICATION_DATA);
        if (!isCallingPerm) {
            TAG_LOGE(AAFwkTag::APPMGR, "Permission verification failed");
            return ERR_PERMISSION_DENIED;
        }
    }
    int32_t uid = IPCSkeleton::GetCallingUid();
    pid_t pid = IPCSkeleton::GetCallingRealPid();
    appMgrServiceInner_->ClearUpApplicationData(bundleName, uid, pid, userId);
    return ERR_OK;
}

int32_t AppMgrService::ClearUpApplicationDataBySelf(int32_t userId)
{
    if (!IsReady()) {
        return ERR_INVALID_OPERATION;
    }
    int32_t uid = IPCSkeleton::GetCallingUid();
    pid_t pid = IPCSkeleton::GetCallingRealPid();
    return appMgrServiceInner_->ClearUpApplicationDataBySelf(uid, pid, userId);
}

int32_t AppMgrService::GetAllRunningProcesses(std::vector<RunningProcessInfo> &info)
{
    if (!IsReady()) {
        return ERR_INVALID_OPERATION;
    }
    return appMgrServiceInner_->GetAllRunningProcesses(info);
}

int32_t AppMgrService::GetRunningProcessesByBundleType(BundleType bundleType,
    std::vector<RunningProcessInfo> &info)
{
    if (!IsReady()) {
        return ERR_INVALID_OPERATION;
    }
    return appMgrServiceInner_->GetRunningProcessesByBundleType(bundleType, info);
}

int32_t AppMgrService::GetAllRenderProcesses(std::vector<RenderProcessInfo> &info)
{
    if (!IsReady()) {
        return ERR_INVALID_OPERATION;
    }
    return appMgrServiceInner_->GetAllRenderProcesses(info);
}

int32_t AppMgrService::JudgeSandboxByPid(pid_t pid, bool &isSandbox)
{
    if (!IsReady()) {
        TAG_LOGE(AAFwkTag::APPMGR, "AppMgrService is not ready.");
        return ERR_INVALID_OPERATION;
    }
    auto appRunningRecord = appMgrServiceInner_->GetAppRunningRecordByPid(pid);
    if (appRunningRecord && appRunningRecord->GetAppIndex() > AbilityRuntime::GlobalConstant::MAX_APP_TWIN_INDEX) {
        isSandbox = true;
        TAG_LOGD(AAFwkTag::APPMGR, "current app is a sandbox.");
        return ERR_OK;
    }
    TAG_LOGD(AAFwkTag::APPMGR, "current app is not a sandbox.");
    return ERR_OK;
}

int32_t AppMgrService::GetProcessRunningInfosByUserId(std::vector<RunningProcessInfo> &info, int32_t userId)
{
    if (!IsReady()) {
        return ERR_INVALID_OPERATION;
    }
    return appMgrServiceInner_->GetProcessRunningInfosByUserId(info, userId);
}

int32_t AppMgrService::GetProcessRunningInformation(RunningProcessInfo &info)
{
    if (!IsReady()) {
        return ERR_INVALID_OPERATION;
    }
    return appMgrServiceInner_->GetProcessRunningInformation(info);
}

int32_t AppMgrService::NotifyMemoryLevel(int32_t level)
{
    if (!IsReady()) {
        return ERR_INVALID_OPERATION;
    }
    return appMgrServiceInner_->NotifyMemoryLevel(level);
}

int32_t AppMgrService::NotifyProcMemoryLevel(const std::map<pid_t, MemoryLevel> &procLevelMap)
{
    if (!IsReady()) {
        return ERR_INVALID_OPERATION;
    }
    return appMgrServiceInner_->NotifyProcMemoryLevel(procLevelMap);
}

int32_t AppMgrService::DumpHeapMemory(const int32_t pid, OHOS::AppExecFwk::MallocInfo &mallocInfo)
{
    if (!IsReady()) {
        return ERR_INVALID_OPERATION;
    }
    return appMgrServiceInner_->DumpHeapMemory(pid, mallocInfo);
}

// Authenticate dump permissions
bool AppMgrService::HasDumpPermission() const
{
    uint32_t callingTokenID = IPCSkeleton::GetCallingTokenID();
    int res = Security::AccessToken::AccessTokenKit::VerifyAccessToken(callingTokenID, "ohos.permission.DUMP");
    if (res != Security::AccessToken::PermissionState::PERMISSION_GRANTED) {
        TAG_LOGE(AAFwkTag::APPMGR, "No dump permission, please check!");
        return false;
    }
    return true;
}

int32_t AppMgrService::DumpJsHeapMemory(OHOS::AppExecFwk::JsHeapDumpInfo &info)
{
    if (!IsReady() || !HasDumpPermission()) {
        return ERR_INVALID_OPERATION;
    }
    return appMgrServiceInner_->DumpJsHeapMemory(info);
}

void AppMgrService::AddAbilityStageDone(const int32_t recordId)
{
    if (!IsReady()) {
        return;
    }
    if (!JudgeAppSelfCalled(recordId)) {
        return;
    }
    std::function <void()> addAbilityStageDone =
        std::bind(&AppMgrServiceInner::AddAbilityStageDone, appMgrServiceInner_, recordId);
    taskHandler_->SubmitTask(addAbilityStageDone, AAFwk::TaskAttribute{
        .taskName_ = TASK_ADD_ABILITY_STAGE_DONE,
        .taskQos_ = AAFwk::TaskQoS::USER_INTERACTIVE
    });
}

int32_t AppMgrService::RegisterApplicationStateObserver(const sptr<IApplicationStateObserver> &observer,
    const std::vector<std::string> &bundleNameList)
{
    TAG_LOGD(AAFwkTag::APPMGR, "begin");
    if (!IsReady()) {
        TAG_LOGE(AAFwkTag::APPMGR, "not ready");
        return ERR_INVALID_OPERATION;
    }
    return appMgrServiceInner_->RegisterApplicationStateObserver(observer, bundleNameList);
}

int32_t AppMgrService::UnregisterApplicationStateObserver(const sptr<IApplicationStateObserver> &observer)
{
    TAG_LOGD(AAFwkTag::APPMGR, "begin");
    if (!IsReady()) {
        TAG_LOGE(AAFwkTag::APPMGR, "not ready");
        return ERR_INVALID_OPERATION;
    }
    return appMgrServiceInner_->UnregisterApplicationStateObserver(observer);
}

int32_t AppMgrService::RegisterAbilityForegroundStateObserver(const sptr<IAbilityForegroundStateObserver> &observer)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::APPMGR, "Called.");
    if (!IsReady()) {
        TAG_LOGE(AAFwkTag::APPMGR, "Not ready.");
        return ERR_INVALID_OPERATION;
    }
    return appMgrServiceInner_->RegisterAbilityForegroundStateObserver(observer);
}

int32_t AppMgrService::UnregisterAbilityForegroundStateObserver(const sptr<IAbilityForegroundStateObserver> &observer)
{
    TAG_LOGD(AAFwkTag::APPMGR, "Called.");
    if (!IsReady()) {
        TAG_LOGE(AAFwkTag::APPMGR, "Not ready.");
        return ERR_INVALID_OPERATION;
    }
    return appMgrServiceInner_->UnregisterAbilityForegroundStateObserver(observer);
}

int32_t AppMgrService::GetForegroundApplications(std::vector<AppStateData> &list)
{
    TAG_LOGD(AAFwkTag::APPMGR, "begin");
    if (!IsReady()) {
        TAG_LOGE(AAFwkTag::APPMGR, "not ready");
        return ERR_INVALID_OPERATION;
    }
    return appMgrServiceInner_->GetForegroundApplications(list);
}

int AppMgrService::StartUserTestProcess(const AAFwk::Want &want, const sptr<IRemoteObject> &observer,
    const AppExecFwk::BundleInfo &bundleInfo, int32_t userId)
{
    if (!IsReady()) {
        TAG_LOGE(AAFwkTag::APPMGR, "not ready");
        return ERR_INVALID_OPERATION;
    }
    if (!AAFwk::PermissionVerification::GetInstance()->IsShellCall()) {
        TAG_LOGE(AAFwkTag::APPMGR, "StartUserTestProcess is not shell call.");
        return ERR_INVALID_OPERATION;
    }
    std::function<void()> startUserTestProcessFunc =
        std::bind(&AppMgrServiceInner::StartUserTestProcess, appMgrServiceInner_, want, observer, bundleInfo, userId);
    taskHandler_->SubmitTask(startUserTestProcessFunc, TASK_START_USER_TEST_PROCESS);
    return ERR_OK;
}

int AppMgrService::FinishUserTest(const std::string &msg, const int64_t &resultCode, const std::string &bundleName)
{
    if (!IsReady()) {
        TAG_LOGE(AAFwkTag::APPMGR, "Not ready");
        return ERR_INVALID_OPERATION;
    }
    std::shared_ptr<RemoteClientManager> remoteClientManager = std::make_shared<RemoteClientManager>();
    if (remoteClientManager == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "The remoteClientManager is nullptr.");
        return ERR_INVALID_OPERATION;
    }
    auto bundleMgrHelper = remoteClientManager->GetBundleManagerHelper();
    if (bundleMgrHelper == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "The bundleMgrHelper is nullptr.");
        return ERR_INVALID_OPERATION;
    }
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    std::string callerBundleName;
    auto result = IN_PROCESS_CALL(bundleMgrHelper->GetNameForUid(callingUid, callerBundleName));
    if (result == ERR_OK) {
        TAG_LOGI(AAFwkTag::APPMGR, "The callingPid_ is %{public}s.", callerBundleName.c_str());
        if (bundleName != callerBundleName) {
            TAG_LOGE(AAFwkTag::APPMGR, "Not this process call.");
            return ERR_INVALID_OPERATION;
        }
    } else {
        TAG_LOGE(AAFwkTag::APPMGR, "GetBundleName failed: %{public}d.", result);
        return ERR_INVALID_OPERATION;
    }
    pid_t callingPid = IPCSkeleton::GetCallingRealPid();
    std::function<void()> finishUserTestProcessFunc =
        std::bind(&AppMgrServiceInner::FinishUserTest, appMgrServiceInner_, msg, resultCode, bundleName, callingPid);
    taskHandler_->SubmitTask(finishUserTestProcessFunc, TASK_FINISH_USER_TEST);
    return ERR_OK;
}

int AppMgrService::Dump(int fd, const std::vector<std::u16string>& args)
{
    TAG_LOGD(AAFwkTag::APPMGR, "Called.");
    if (!IsReady()) {
        TAG_LOGE(AAFwkTag::APPMGR, "not ready.");
        return ERR_APPEXECFWK_HIDUMP_ERROR;
    }

    std::string result;
    auto errCode = Dump(args, result);
    int ret = dprintf(fd, "%s\n", result.c_str());
    if (ret < 0) {
        TAG_LOGE(AAFwkTag::APPMGR, "dprintf error.");
        return ERR_APPEXECFWK_HIDUMP_ERROR;
    }
    return errCode;
}

int AppMgrService::Dump(const std::vector<std::u16string>& args, std::string& result)
{
    TAG_LOGD(AAFwkTag::APPMGR, "Called.");
    auto size = args.size();
    if (size == 0) {
        ShowHelp(result);
        return DumpErrorCode::ERR_OK;
    }

    std::string optionKey = Str16ToStr8(args[0]);
    if (optionKey == OPTION_KEY_HELP) {
        ShowHelp(result);
        return DumpErrorCode::ERR_OK;
    }
    if (optionKey == OPTION_KEY_DUMP_IPC) {
        return DumpIpc(args, result);
    }

    result.append("error: unkown option.\n");
    return DumpErrorCode::ERR_UNKNOWN_OPTION_ERROR;
}

void AppMgrService::ShowHelp(std::string& result) const
{
    result.append("Usage:\n")
        .append("-h                          ")
        .append("help text for the tool\n");
}

int AppMgrService::DumpIpcAllInner(const AppMgrService::DumpIpcKey key, std::string& result)
{
    TAG_LOGD(AAFwkTag::APPMGR, "Called.");
    auto itFunc = dumpIpcAllFuncMap_.find(key);
    if (itFunc == dumpIpcAllFuncMap_.end()) {
        result.append(MSG_DUMP_IPC_FAIL).append(MSG_DUMP_IPC_FAIL_REASON_INTERNAL);
        TAG_LOGE(AAFwkTag::APPMGR, "option key %{public}d does not exist", key);
        return DumpErrorCode::ERR_INTERNAL_ERROR;
    }
    auto dumpFunc = itFunc->second;
    if (dumpFunc == nullptr) {
        result.append(MSG_DUMP_IPC_FAIL).append(MSG_DUMP_IPC_FAIL_REASON_INTERNAL);
        TAG_LOGE(AAFwkTag::APPMGR, "dump ipc all function does not exist");
        return DumpErrorCode::ERR_INTERNAL_ERROR;
    }
    return (this->*dumpFunc)(result);
}

int AppMgrService::DumpIpcWithPidInner(const AppMgrService::DumpIpcKey key,
    const std::string& optionPid, std::string& result)
{
    TAG_LOGD(AAFwkTag::APPMGR, "Called.");
    int32_t pid = -1;
    try {
        pid = static_cast<int32_t>(std::stoi(optionPid));
    } catch (...) {
        result.append(MSG_DUMP_IPC_FAIL).append(MSG_DUMP_IPC_FAIL_REASON_INVALILD_PID);
        TAG_LOGE(AAFwkTag::APPMGR, "stoi(%{public}s) failed", optionPid.c_str());
        return DumpErrorCode::ERR_INVALID_PID_ERROR;
    }
    if (pid < 0) {
        result.append(MSG_DUMP_IPC_FAIL).append(MSG_DUMP_IPC_FAIL_REASON_INVALILD_PID);
        TAG_LOGE(AAFwkTag::APPMGR, "invalid pid: %{public}s", optionPid.c_str());
        return DumpErrorCode::ERR_INVALID_PID_ERROR;
    }
    auto itFunc = dumpIpcFuncMap_.find(key);
    if (itFunc == dumpIpcFuncMap_.end()) {
        result.append(MSG_DUMP_IPC_FAIL).append(MSG_DUMP_IPC_FAIL_REASON_INTERNAL);
        TAG_LOGE(AAFwkTag::APPMGR, "option key %{public}d does not exist", key);
        return DumpErrorCode::ERR_INTERNAL_ERROR;
    }
    auto dumpFunc = itFunc->second;
    if (dumpFunc == nullptr) {
        result.append(MSG_DUMP_IPC_FAIL).append(MSG_DUMP_IPC_FAIL_REASON_INTERNAL);
        TAG_LOGE(AAFwkTag::APPMGR, "dump ipc function does not exist");
        return DumpErrorCode::ERR_INTERNAL_ERROR;
    }
    return (this->*dumpFunc)(pid, result);
}

int AppMgrService::DumpIpc(const std::vector<std::u16string>& args, std::string& result)
{
    TAG_LOGD(AAFwkTag::APPMGR, "Called. AppMgrService::DumpIpc start");
    if (args.size() != VALID_DUMP_IPC_ARG_SIZE) {
        result.append(MSG_DUMP_IPC_FAIL).append(MSG_DUMP_IPC_FAIL_REASON_INVALILD_NUM_ARGS);
        TAG_LOGE(AAFwkTag::APPMGR, "invalid number of arguments");
        return DumpErrorCode::ERR_INVALID_NUM_ARGS_ERROR;
    }
    auto isShellCall = AAFwk::PermissionVerification::GetInstance()->IsShellCall();
    auto isHidumperServiceCall = (IPCSkeleton::GetCallingUid() == HIDUMPER_SERVICE_UID);
    if (!isShellCall && !isHidumperServiceCall) {
        result.append(MSG_DUMP_IPC_FAIL).append(MSG_DUMP_IPC_FAIL_REASON_PERMISSION_DENY);
        TAG_LOGE(AAFwkTag::APPMGR, "Permission deny.");
        return DumpErrorCode::ERR_PERMISSION_DENY_ERROR;
    }

    std::string optionCmd = Str16ToStr8(args[INDEX_CMD]);
    std::string optionPid = Str16ToStr8(args[INDEX_PID]);
    TAG_LOGD(AAFwkTag::APPMGR, "option pid:%{public}s, option cmd:%{public}s",
        optionPid.c_str(), optionCmd.c_str());

    auto itDumpKey = dumpIpcMap.find(optionCmd);
    if (itDumpKey == dumpIpcMap.end()) {
        result.append(MSG_DUMP_IPC_FAIL).append(MSG_DUMP_IPC_FAIL_REASON_INVALILD_CMD);
        TAG_LOGE(AAFwkTag::APPMGR, "option command %{public}s does not exist", optionCmd.c_str());
        return DumpErrorCode::ERR_INVALID_CMD_ERROR;
    }
    DumpIpcKey key = itDumpKey->second;

    if (optionPid == "-a" || optionPid == "all" || optionPid == "--all") {
        return DumpIpcAllInner(key, result);
    }
    return DumpIpcWithPidInner(key, optionPid, result);
}

int AppMgrService::DumpIpcAllStart(std::string& result)
{
    TAG_LOGD(AAFwkTag::APPMGR, "Called.");
    return appMgrServiceInner_->DumpIpcAllStart(result);
}

int AppMgrService::DumpIpcAllStop(std::string& result)
{
    TAG_LOGD(AAFwkTag::APPMGR, "Called.");
    return appMgrServiceInner_->DumpIpcAllStop(result);
}

int AppMgrService::DumpIpcAllStat(std::string& result)
{
    TAG_LOGD(AAFwkTag::APPMGR, "Called.");
    return appMgrServiceInner_->DumpIpcAllStat(result);
}

int AppMgrService::DumpIpcStart(const int32_t pid, std::string& result)
{
    TAG_LOGD(AAFwkTag::APPMGR, "Called.");
    return appMgrServiceInner_->DumpIpcStart(pid, result);
}

int AppMgrService::DumpIpcStop(const int32_t pid, std::string& result)
{
    TAG_LOGD(AAFwkTag::APPMGR, "Called.");
    return appMgrServiceInner_->DumpIpcStop(pid, result);
}

int AppMgrService::DumpIpcStat(const int32_t pid, std::string& result)
{
    TAG_LOGD(AAFwkTag::APPMGR, "Called.");
    return appMgrServiceInner_->DumpIpcStat(pid, result);
}

void AppMgrService::ScheduleAcceptWantDone(const int32_t recordId, const AAFwk::Want &want, const std::string &flag)
{
    if (!IsReady()) {
        TAG_LOGE(AAFwkTag::APPMGR, "not ready");
        return;
    }
    if (!JudgeAppSelfCalled(recordId)) {
        return;
    }
    auto task = [=]() { appMgrServiceInner_->ScheduleAcceptWantDone(recordId, want, flag); };
    taskHandler_->SubmitTask(task);
}

void AppMgrService::ScheduleNewProcessRequestDone(const int32_t recordId, const AAFwk::Want &want,
    const std::string &flag)
{
    if (!IsReady()) {
        TAG_LOGE(AAFwkTag::APPMGR, "not ready");
        return;
    }
    if (!JudgeAppSelfCalled(recordId)) {
        return;
    }
    auto task = [=]() { appMgrServiceInner_->ScheduleNewProcessRequestDone(recordId, want, flag); };
    taskHandler_->SubmitTask(task, AAFwk::TaskQoS::USER_INTERACTIVE);
}

int AppMgrService::GetAbilityRecordsByProcessID(const int pid, std::vector<sptr<IRemoteObject>> &tokens)
{
    if (!IsReady()) {
        TAG_LOGE(AAFwkTag::APPMGR, "not ready");
        return ERR_INVALID_OPERATION;
    }
    auto isSaCall = AAFwk::PermissionVerification::GetInstance()->IsSACall();
    if (!isSaCall) {
        TAG_LOGE(AAFwkTag::APPMGR, "Not SA call.");
        return ERR_INVALID_OPERATION;
    }
    return appMgrServiceInner_->GetAbilityRecordsByProcessID(pid, tokens);
}

int32_t AppMgrService::PreStartNWebSpawnProcess()
{
    TAG_LOGI(AAFwkTag::APPMGR, "PreStartNWebSpawnProcess");
    if (!IsReady()) {
        TAG_LOGE(AAFwkTag::APPMGR, "PreStartNWebSpawnProcess failed, AppMgrService not ready.");
        return ERR_INVALID_OPERATION;
    }

    return appMgrServiceInner_->PreStartNWebSpawnProcess(IPCSkeleton::GetCallingRealPid());
}

int32_t AppMgrService::StartRenderProcess(const std::string &renderParam, int32_t ipcFd,
    int32_t sharedFd, int32_t crashFd, pid_t &renderPid)
{
    if (!IsReady()) {
        TAG_LOGE(AAFwkTag::APPMGR, "StartRenderProcess failed, AppMgrService not ready.");
        return ERR_INVALID_OPERATION;
    }

    return appMgrServiceInner_->StartRenderProcess(IPCSkeleton::GetCallingRealPid(),
        renderParam, ipcFd, sharedFd, crashFd, renderPid);
}

void AppMgrService::AttachRenderProcess(const sptr<IRemoteObject> &scheduler)
{
    TAG_LOGI(AAFwkTag::APPMGR, "AttachRenderProcess called.");
    if (!IsReady()) {
        TAG_LOGE(AAFwkTag::APPMGR, "AttachRenderProcess failed, not ready.");
        return;
    }

    auto pid = IPCSkeleton::GetCallingRealPid();
    auto fun = std::bind(&AppMgrServiceInner::AttachRenderProcess,
        appMgrServiceInner_, pid, iface_cast<IRenderScheduler>(scheduler));
    taskHandler_->SubmitTask(fun, AAFwk::TaskAttribute{
        .taskName_ = TASK_ATTACH_RENDER_PROCESS,
        .taskQos_ = AAFwk::TaskQoS::USER_INTERACTIVE
    });
}

int32_t AppMgrService::GetRenderProcessTerminationStatus(pid_t renderPid, int &status)
{
    if (!IsReady()) {
        TAG_LOGE(AAFwkTag::APPMGR, "GetRenderProcessTerminationStatus failed, AppMgrService not ready.");
        return ERR_INVALID_OPERATION;
    }

    return appMgrServiceInner_->GetRenderProcessTerminationStatus(renderPid, status);
}

int32_t AppMgrService::GetConfiguration(Configuration& config)
{
    if (!IsReady()) {
        TAG_LOGE(AAFwkTag::APPMGR, "GetConfiguration failed, AppMgrService not ready.");
        return ERR_INVALID_OPERATION;
    }
    config = *(appMgrServiceInner_->GetConfiguration());
    return ERR_OK;
}

int32_t AppMgrService::UpdateConfiguration(const Configuration& config)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    if (!IsReady()) {
        TAG_LOGE(AAFwkTag::APPMGR, "UpdateConfiguration failed, AppMgrService not ready.");
        return ERR_INVALID_OPERATION;
    }
    return appMgrServiceInner_->UpdateConfiguration(config);
}

int32_t AppMgrService::UpdateConfigurationByBundleName(const Configuration& config, const std::string &name)
{
    if (!IsReady()) {
        TAG_LOGE(AAFwkTag::APPMGR, "UpdateConfigurationByBundleName failed, AppMgrService not ready.");
        return ERR_INVALID_OPERATION;
    }
    return appMgrServiceInner_->UpdateConfigurationByBundleName(config, name);
}

int32_t AppMgrService::RegisterConfigurationObserver(const sptr<IConfigurationObserver> &observer)
{
    if (!IsReady()) {
        TAG_LOGE(AAFwkTag::APPMGR, "RegisterConfigurationObserver failed, AppMgrService not ready.");
        return ERR_INVALID_OPERATION;
    }
    return appMgrServiceInner_->RegisterConfigurationObserver(observer);
}

int32_t AppMgrService::UnregisterConfigurationObserver(const sptr<IConfigurationObserver> &observer)
{
    if (!IsReady()) {
        TAG_LOGE(AAFwkTag::APPMGR, "UnregisterConfigurationObserver failed, AppMgrService not ready.");
        return ERR_INVALID_OPERATION;
    }
    return appMgrServiceInner_->UnregisterConfigurationObserver(observer);
}

#ifdef ABILITY_COMMAND_FOR_TEST
int AppMgrService::BlockAppService()
{
    TAG_LOGD(AAFwkTag::APPMGR, "begin");
    if (!IsReady()) {
        return ERR_INVALID_OPERATION;
    }
    auto task = [=]() {
        while (1) {
            TAG_LOGD(AAFwkTag::APPMGR, "begin block app service");
            std::this_thread::sleep_for(APP_MS_BLOCK*1s);
        }
    };
    taskHandler_->SubmitTask(task);
    return ERR_OK;
}
#endif

bool AppMgrService::GetAppRunningStateByBundleName(const std::string &bundleName)
{
    if (!IsReady()) {
        TAG_LOGE(AAFwkTag::APPMGR, "AppMgrService is not ready.");
        return false;
    }

    return appMgrServiceInner_->GetAppRunningStateByBundleName(bundleName);
}

int32_t AppMgrService::NotifyLoadRepairPatch(const std::string &bundleName, const sptr<IQuickFixCallback> &callback)
{
    if (!IsReady()) {
        TAG_LOGE(AAFwkTag::APPMGR, "AppMgrService is not ready.");
        return ERR_INVALID_OPERATION;
    }
    return appMgrServiceInner_->NotifyLoadRepairPatch(bundleName, callback);
}

int32_t AppMgrService::NotifyHotReloadPage(const std::string &bundleName, const sptr<IQuickFixCallback> &callback)
{
    if (!IsReady()) {
        TAG_LOGE(AAFwkTag::APPMGR, "AppMgrService is not ready.");
        return ERR_INVALID_OPERATION;
    }
    return appMgrServiceInner_->NotifyHotReloadPage(bundleName, callback);
}

#ifdef BGTASKMGR_CONTINUOUS_TASK_ENABLE
int32_t AppMgrService::SetContinuousTaskProcess(int32_t pid, bool isContinuousTask)
{
    if (!IsReady()) {
        TAG_LOGE(AAFwkTag::APPMGR, "AppMgrService is not ready.");
        return ERR_INVALID_OPERATION;
    }

    return appMgrServiceInner_->SetContinuousTaskProcess(pid, isContinuousTask);
}
#endif

int32_t AppMgrService::NotifyUnLoadRepairPatch(const std::string &bundleName, const sptr<IQuickFixCallback> &callback)
{
    if (!IsReady()) {
        TAG_LOGE(AAFwkTag::APPMGR, "AppMgrService is not ready.");
        return ERR_INVALID_OPERATION;
    }
    return appMgrServiceInner_->NotifyUnLoadRepairPatch(bundleName, callback);
}

bool AppMgrService::JudgeAppSelfCalled(int32_t recordId)
{
    if (appMgrServiceInner_ == nullptr) {
        return false;
    }

    auto callingTokenId = IPCSkeleton::GetCallingTokenID();
    std::shared_ptr<AppRunningRecord> appRecord = appMgrServiceInner_->GetAppRunningRecordByAppRecordId(recordId);
    if (appRecord == nullptr || ((appRecord->GetApplicationInfo())->accessTokenId) != callingTokenId) {
        TAG_LOGE(AAFwkTag::APPMGR, "Is not self, not enabled");
        return false;
    }

    return true;
}

bool AppMgrService::IsSharedBundleRunning(const std::string &bundleName, uint32_t versionCode)
{
    if (!IsReady()) {
        return ERR_INVALID_OPERATION;
    }
    return appMgrServiceInner_->IsSharedBundleRunning(bundleName, versionCode);
}

int32_t AppMgrService::StartNativeProcessForDebugger(const AAFwk::Want &want)
{
    if (!IsReady()) {
        TAG_LOGE(AAFwkTag::APPMGR, "AppMgrService is not ready.");
        return ERR_INVALID_OPERATION;
    }
    auto isShellCall = AAFwk::PermissionVerification::GetInstance()->IsShellCall();
    if (!isShellCall) {
        TAG_LOGE(AAFwkTag::APPMGR, "permission denied, only called by shell.");
        return ERR_INVALID_OPERATION;
    }
    auto ret = appMgrServiceInner_->StartNativeProcessForDebugger(want);
    if (ret != ERR_OK) {
        TAG_LOGE(AAFwkTag::APPMGR, "debuggablePipe fail to start native process.");
    }
    return ret;
}

int32_t AppMgrService::GetBundleNameByPid(const int32_t pid, std::string &bundleName, int32_t &uid)
{
    if (!IsReady()) {
        TAG_LOGE(AAFwkTag::APPMGR, "AppMgrService is not ready.");
        return ERR_INVALID_OPERATION;
    }
    return appMgrServiceInner_->GetBundleNameByPid(pid, bundleName, uid);
}

int32_t AppMgrService::NotifyAppFault(const FaultData &faultData)
{
    if (!IsReady()) {
        TAG_LOGE(AAFwkTag::APPMGR, "AppMgrService is not ready.");
        return ERR_INVALID_OPERATION;
    }

    auto ret = appMgrServiceInner_->NotifyAppFault(faultData);
    if (ret != ERR_OK) {
        TAG_LOGE(AAFwkTag::APPMGR, "Notify fault data fail.");
    }
    return ret;
}

int32_t AppMgrService::NotifyAppFaultBySA(const AppFaultDataBySA &faultData)
{
    if (!IsReady()) {
        TAG_LOGE(AAFwkTag::APPMGR, "AppMgrService is not ready.");
        return ERR_INVALID_OPERATION;
    }

    auto ret = appMgrServiceInner_->NotifyAppFaultBySA(faultData);
    if (ret != ERR_OK) {
        TAG_LOGE(AAFwkTag::APPMGR, "Notify fault data fail.");
    }
    return ret;
}

int32_t AppMgrService::GetProcessMemoryByPid(const int32_t pid, int32_t &memorySize)
{
    if (!IsReady()) {
        TAG_LOGE(AAFwkTag::APPMGR, "AppMgrService is not ready.");
        return ERR_INVALID_OPERATION;
    }

    return appMgrServiceInner_->GetProcessMemoryByPid(pid, memorySize);
}

int32_t AppMgrService::GetRunningProcessInformation(const std::string &bundleName, int32_t userId,
    std::vector<RunningProcessInfo> &info)
{
    if (!IsReady()) {
        TAG_LOGE(AAFwkTag::APPMGR, "AppMgrService is not ready.");
        return ERR_INVALID_OPERATION;
    }

    return appMgrServiceInner_->GetRunningProcessInformation(bundleName, userId, info);
}

void AppMgrService::OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    TAG_LOGI(AAFwkTag::APPMGR, "systemAbilityId: %{public}d add", systemAbilityId);
    if (!IsReady()) {
        TAG_LOGE(AAFwkTag::APPMGR, "AppMgrService is not ready.");
        return;
    }

    if (systemAbilityId != WINDOW_MANAGER_SERVICE_ID) {
        return;
    }

    appMgrServiceInner_->InitFocusListener();
    appMgrServiceInner_->InitWindowVisibilityChangedListener();
}

void AppMgrService::OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    TAG_LOGI(AAFwkTag::APPMGR, "systemAbilityId: %{public}d remove", systemAbilityId);
    if (!IsReady()) {
        TAG_LOGE(AAFwkTag::APPMGR, "AppMgrService is not ready.");
        return;
    }

    if (systemAbilityId != WINDOW_MANAGER_SERVICE_ID) {
        return;
    }

    appMgrServiceInner_->FreeFocusListener();
    appMgrServiceInner_->FreeWindowVisibilityChangedListener();
}

int32_t AppMgrService::ChangeAppGcState(pid_t pid, int32_t state)
{
    TAG_LOGD(AAFwkTag::APPMGR, "called.");
    if (!appMgrServiceInner_) {
        return ERR_INVALID_VALUE;
    }
    return appMgrServiceInner_->ChangeAppGcState(pid, state);
}

int32_t AppMgrService::NotifyPageShow(const sptr<IRemoteObject> &token, const PageStateData &pageStateData)
{
    TAG_LOGD(AAFwkTag::APPMGR,
        "bundleName: %{public}s, moduelName: %{public}s, abilityName: %{public}s, pageName: %{public}s",
        pageStateData.bundleName.c_str(), pageStateData.moduleName.c_str(), pageStateData.abilityName.c_str(),
        pageStateData.pageName.c_str());
    if (!IsReady()) {
        TAG_LOGE(AAFwkTag::APPMGR, "AppMgrService is not ready.");
        return ERR_INVALID_OPERATION;
    }
    return appMgrServiceInner_->NotifyPageShow(token, pageStateData);
}

int32_t AppMgrService::NotifyPageHide(const sptr<IRemoteObject> &token, const PageStateData &pageStateData)
{
    TAG_LOGD(AAFwkTag::APPMGR,
        "bundleName: %{public}s, moduelName: %{public}s, abilityName: %{public}s, pageName: %{public}s",
        pageStateData.bundleName.c_str(), pageStateData.moduleName.c_str(), pageStateData.abilityName.c_str(),
        pageStateData.pageName.c_str());
    if (!IsReady()) {
        TAG_LOGE(AAFwkTag::APPMGR, "AppMgrService is not ready.");
        return ERR_INVALID_OPERATION;
    }
    return appMgrServiceInner_->NotifyPageHide(token, pageStateData);
}

int32_t AppMgrService::RegisterAppRunningStatusListener(const sptr<IRemoteObject> &listener)
{
    TAG_LOGD(AAFwkTag::APPMGR, "Called.");
    if (!IsReady()) {
        TAG_LOGE(AAFwkTag::APPMGR, "Not ready");
        return ERR_INVALID_OPERATION;
    }
    return appMgrServiceInner_->RegisterAppRunningStatusListener(listener);
}

int32_t AppMgrService::UnregisterAppRunningStatusListener(const sptr<IRemoteObject> &listener)
{
    TAG_LOGD(AAFwkTag::APPMGR, "Called.");
    if (!IsReady()) {
        TAG_LOGE(AAFwkTag::APPMGR, "Not ready.");
        return ERR_INVALID_OPERATION;
    }
    return appMgrServiceInner_->UnregisterAppRunningStatusListener(listener);
}

int32_t AppMgrService::RegisterAppForegroundStateObserver(const sptr<IAppForegroundStateObserver> &observer)
{
    TAG_LOGD(AAFwkTag::APPMGR, "Called.");
    if (!IsReady()) {
        TAG_LOGE(AAFwkTag::APPMGR, "Not ready.");
        return ERR_INVALID_OPERATION;
    }
    return appMgrServiceInner_->RegisterAppForegroundStateObserver(observer);
}

int32_t AppMgrService::UnregisterAppForegroundStateObserver(const sptr<IAppForegroundStateObserver> &observer)
{
    TAG_LOGD(AAFwkTag::APPMGR, "Called.");
    if (!IsReady()) {
        TAG_LOGE(AAFwkTag::APPMGR, "Not ready.");
        return ERR_INVALID_OPERATION;
    }
    return appMgrServiceInner_->UnregisterAppForegroundStateObserver(observer);
}

int32_t AppMgrService::IsApplicationRunning(const std::string &bundleName, bool &isRunning)
{
    if (!IsReady()) {
        return ERR_INVALID_OPERATION;
    }
    return appMgrServiceInner_->IsApplicationRunning(bundleName, isRunning);
}

int32_t AppMgrService::StartChildProcess(const std::string &srcEntry, pid_t &childPid, int32_t childProcessCount,
    bool isStartWithDebug)
{
    TAG_LOGD(AAFwkTag::APPMGR, "Called.");
    if (!IsReady()) {
        TAG_LOGE(AAFwkTag::APPMGR, "StartChildProcess failed, AppMgrService not ready.");
        return ERR_INVALID_OPERATION;
    }
    return appMgrServiceInner_->StartChildProcess(IPCSkeleton::GetCallingRealPid(), srcEntry, childPid,
        childProcessCount, isStartWithDebug);
}

int32_t AppMgrService::GetChildProcessInfoForSelf(ChildProcessInfo &info)
{
    if (!IsReady()) {
        TAG_LOGE(AAFwkTag::APPMGR, "StartChildProcess failed, AppMgrService not ready.");
        return ERR_INVALID_OPERATION;
    }
    return appMgrServiceInner_->GetChildProcessInfoForSelf(info);
}

void AppMgrService::AttachChildProcess(const sptr<IRemoteObject> &childScheduler)
{
    TAG_LOGD(AAFwkTag::APPMGR, "AttachChildProcess.");
    if (!IsReady()) {
        TAG_LOGE(AAFwkTag::APPMGR, "AttachChildProcess failed, not ready.");
        return;
    }
    if (!taskHandler_) {
        TAG_LOGE(AAFwkTag::APPMGR, "taskHandler_ is null.");
        return;
    }
    pid_t pid = IPCSkeleton::GetCallingRealPid();
    std::function<void()> task = std::bind(&AppMgrServiceInner::AttachChildProcess,
        appMgrServiceInner_, pid, iface_cast<IChildScheduler>(childScheduler));
    taskHandler_->SubmitTask(task, AAFwk::TaskAttribute{
        .taskName_ = TASK_ATTACH_CHILD_PROCESS,
        .taskQos_ = AAFwk::TaskQoS::USER_INTERACTIVE
    });
}

void AppMgrService::ExitChildProcessSafely()
{
    if (!IsReady()) {
        TAG_LOGE(AAFwkTag::APPMGR, "ExitChildProcessSafely failed, AppMgrService not ready.");
        return;
    }
    if (!taskHandler_) {
        TAG_LOGE(AAFwkTag::APPMGR, "taskHandler_ is null.");
        return;
    }
    pid_t pid = IPCSkeleton::GetCallingRealPid();
    std::function<void()> task = std::bind(&AppMgrServiceInner::ExitChildProcessSafelyByChildPid,
        appMgrServiceInner_, pid);
    taskHandler_->SubmitTask(task, AAFwk::TaskAttribute{
        .taskName_ = TASK_EXIT_CHILD_PROCESS_SAFELY,
        .taskQos_ = AAFwk::TaskQoS::USER_INTERACTIVE
    });
}

bool AppMgrService::IsFinalAppProcess()
{
    if (!IsReady()) {
        TAG_LOGE(AAFwkTag::APPMGR, "Not ready.");
        return false;
    }
    return appMgrServiceInner_->IsFinalAppProcessByBundleName("");
}

int32_t AppMgrService::RegisterRenderStateObserver(const sptr<IRenderStateObserver> &observer)
{
    if (!IsReady()) {
        TAG_LOGE(AAFwkTag::APPMGR, "AppMgrService not ready.");
        return ERR_INVALID_OPERATION;
    }

    if (AAFwk::PermissionVerification::GetInstance()->VerifyAppStateObserverPermission() == ERR_PERMISSION_DENIED) {
        TAG_LOGE(AAFwkTag::APPMGR, "Permission verification failed");
        return ERR_PERMISSION_DENIED;
    }
    return appMgrServiceInner_->RegisterRenderStateObserver(observer);
}

int32_t AppMgrService::UnregisterRenderStateObserver(const sptr<IRenderStateObserver> &observer)
{
    if (!IsReady()) {
        TAG_LOGE(AAFwkTag::APPMGR, "AppMgrService not ready.");
        return ERR_INVALID_OPERATION;
    }

    if (AAFwk::PermissionVerification::GetInstance()->VerifyAppStateObserverPermission() == ERR_PERMISSION_DENIED) {
        TAG_LOGE(AAFwkTag::APPMGR, "Permission verification failed");
        return ERR_PERMISSION_DENIED;
    }
    return appMgrServiceInner_->UnregisterRenderStateObserver(observer);
}

int32_t AppMgrService::UpdateRenderState(pid_t renderPid, int32_t state)
{
    if (!IsReady()) {
        TAG_LOGE(AAFwkTag::APPMGR, "AppMgrService not ready.");
        return ERR_INVALID_OPERATION;
    }
    return appMgrServiceInner_->UpdateRenderState(renderPid, state);
}

int32_t AppMgrService::SignRestartAppFlag(const std::string &bundleName)
{
    if (!IsReady()) {
        TAG_LOGE(AAFwkTag::APPMGR, "Not ready.");
        return ERR_INVALID_OPERATION;
    }
    bool isCallingPermission =
        AAFwk::PermissionVerification::GetInstance()->CheckSpecificSystemAbilityAccessPermission(FOUNDATION_PROCESS);
    if (!isCallingPermission) {
        TAG_LOGE(AAFwkTag::APPMGR, "VerificationAllToken failed.");
        return ERR_PERMISSION_DENIED;
    }
    return appMgrServiceInner_->SignRestartAppFlag(bundleName);
}

int32_t AppMgrService::GetAppRunningUniqueIdByPid(pid_t pid, std::string &appRunningUniqueId)
{
    if (!IsReady()) {
        TAG_LOGE(AAFwkTag::APPMGR, "GetAppRunningUniqueIdByPid, Not ready.");
        return ERR_INVALID_OPERATION;
    }
    bool isCallingPermission = AAFwk::PermissionVerification::GetInstance()->IsSACall() &&
        AAFwk::PermissionVerification::GetInstance()->VerifyRunningInfoPerm();
    if (!isCallingPermission) {
        TAG_LOGE(AAFwkTag::APPMGR, "GetAppRunningUniqueIdByPid, Not SA call or Permission verification failed.");
        return ERR_PERMISSION_DENIED;
    }
    return appMgrServiceInner_->GetAppRunningUniqueIdByPid(pid, appRunningUniqueId);
}

int32_t AppMgrService::GetAllUIExtensionRootHostPid(pid_t pid, std::vector<pid_t> &hostPids)
{
    if (!IsReady()) {
        TAG_LOGE(AAFwkTag::APPMGR, "Not ready.");
        return ERR_INVALID_OPERATION;
    }

    return appMgrServiceInner_->GetAllUIExtensionRootHostPid(pid, hostPids);
}

int32_t AppMgrService::GetAllUIExtensionProviderPid(pid_t hostPid, std::vector<pid_t> &providerPids)
{
    if (!IsReady()) {
        TAG_LOGE(AAFwkTag::APPMGR, "Not ready.");
        return ERR_INVALID_OPERATION;
    }

    return appMgrServiceInner_->GetAllUIExtensionProviderPid(hostPid, providerPids);
}

int32_t AppMgrService::NotifyMemorySizeStateChanged(bool isMemorySizeSufficent)
{
    if (!IsReady()) {
        TAG_LOGE(AAFwkTag::APPMGR, "AppMgrService is not ready.");
        return ERR_INVALID_OPERATION;
    }

    return appMgrServiceInner_->NotifyMemorySizeStateChanged(isMemorySizeSufficent);
}
}  // namespace AppExecFwk
}  // namespace OHOS
