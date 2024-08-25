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

#include "ams_mgr_stub.h"

#include "ability_info.h"
#include "app_debug_listener_interface.h"
#include "app_mgr_proxy.h"
#include "app_scheduler_interface.h"
#include "appexecfwk_errors.h"
#include "hilog_tag_wrapper.h"
#include "hilog_wrapper.h"
#include "hitrace_meter.h"
#include "iapp_state_callback.h"
#include "ipc_skeleton.h"
#include "ipc_types.h"
#include "iremote_object.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int32_t MAX_APP_DEBUG_COUNT = 100;
constexpr int32_t MAX_KILL_PROCESS_PID_COUNT = 100;
}
AmsMgrStub::AmsMgrStub()
{
    memberFuncMap_[static_cast<uint32_t>(IAmsMgr::Message::LOAD_ABILITY)] = &AmsMgrStub::HandleLoadAbility;
    memberFuncMap_[static_cast<uint32_t>(IAmsMgr::Message::TERMINATE_ABILITY)] =
        &AmsMgrStub::HandleTerminateAbility;
    memberFuncMap_[static_cast<uint32_t>(IAmsMgr::Message::UPDATE_ABILITY_STATE)] =
        &AmsMgrStub::HandleUpdateAbilityState;
    memberFuncMap_[static_cast<uint32_t>(IAmsMgr::Message::UPDATE_EXTENSION_STATE)] =
        &AmsMgrStub::HandleUpdateExtensionState;
    memberFuncMap_[static_cast<uint32_t>(IAmsMgr::Message::REGISTER_APP_STATE_CALLBACK)] =
        &AmsMgrStub::HandleRegisterAppStateCallback;
    memberFuncMap_[static_cast<uint32_t>(IAmsMgr::Message::ABILITY_BEHAVIOR_ANALYSIS)] =
        &AmsMgrStub::HandleAbilityBehaviorAnalysis;
    memberFuncMap_[static_cast<uint32_t>(IAmsMgr::Message::KILL_PEOCESS_BY_ABILITY_TOKEN)] =
        &AmsMgrStub::HandleKillProcessByAbilityToken;
    memberFuncMap_[static_cast<uint32_t>(IAmsMgr::Message::KILL_PROCESSES_BY_USERID)] =
        &AmsMgrStub::HandleKillProcessesByUserId;
    memberFuncMap_[static_cast<uint32_t>(IAmsMgr::Message::KILL_PROCESS_WITH_ACCOUNT)] =
        &AmsMgrStub::HandleKillProcessWithAccount;
    memberFuncMap_[static_cast<uint32_t>(IAmsMgr::Message::KILL_APPLICATION)] = &AmsMgrStub::HandleKillApplication;
    memberFuncMap_[static_cast<uint32_t>(IAmsMgr::Message::ABILITY_ATTACH_TIMEOUT)] =
        &AmsMgrStub::HandleAbilityAttachTimeOut;
    memberFuncMap_[static_cast<uint32_t>(IAmsMgr::Message::PREPARE_TERMINATE_ABILITY)] =
        &AmsMgrStub::HandlePrepareTerminate;
    memberFuncMap_[static_cast<uint32_t>(IAmsMgr::Message::KILL_APPLICATION_BYUID)] =
        &AmsMgrStub::HandleKillApplicationByUid;
    memberFuncMap_[static_cast<uint32_t>(IAmsMgr::Message::KILL_APPLICATION_SELF)] =
        &AmsMgrStub::HandleKillApplicationSelf;
    memberFuncMap_[static_cast<uint32_t>(IAmsMgr::Message::GET_RUNNING_PROCESS_INFO_BY_TOKEN)] =
        &AmsMgrStub::HandleGetRunningProcessInfoByToken;
    memberFuncMap_[static_cast<uint32_t>(IAmsMgr::Message::GET_RUNNING_PROCESS_INFO_BY_PID)] =
        &AmsMgrStub::HandleGetRunningProcessInfoByPid;
    memberFuncMap_[static_cast<uint32_t>(IAmsMgr::Message::SET_ABILITY_FOREGROUNDING_FLAG)] =
        &AmsMgrStub::HandleSetAbilityForegroundingFlagToAppRecord;
    memberFuncMap_[static_cast<uint32_t>(IAmsMgr::Message::START_SPECIFIED_ABILITY)] =
        &AmsMgrStub::HandleStartSpecifiedAbility;
    memberFuncMap_[static_cast<uint32_t>(IAmsMgr::Message::REGISTER_START_SPECIFIED_ABILITY_RESPONSE)] =
        &AmsMgrStub::HandleRegisterStartSpecifiedAbilityResponse;
    memberFuncMap_[static_cast<uint32_t>(IAmsMgr::Message::GET_APPLICATION_INFO_BY_PROCESS_ID)] =
        &AmsMgrStub::HandleGetApplicationInfoByProcessID;
    memberFuncMap_[static_cast<uint32_t>(IAmsMgr::Message::NOTIFY_APP_MGR_RECORD_EXIT_REASON)] =
        &AmsMgrStub::HandleNotifyAppMgrRecordExitReason;
    memberFuncMap_[static_cast<uint32_t>(IAmsMgr::Message::UPDATE_APPLICATION_INFO_INSTALLED)] =
        &AmsMgrStub::HandleUpdateApplicationInfoInstalled;
    memberFuncMap_[static_cast<uint32_t>(IAmsMgr::Message::SET_CURRENT_USER_ID)] =
        &AmsMgrStub::HandleSetCurrentUserId;
    memberFuncMap_[static_cast<uint32_t>(IAmsMgr::Message::Get_BUNDLE_NAME_BY_PID)] =
        &AmsMgrStub::HandleGetBundleNameByPid;
    CreateMemberFuncMap();
}

AmsMgrStub::~AmsMgrStub()
{
    memberFuncMap_.clear();
}

void AmsMgrStub::CreateMemberFuncMap()
{
    memberFuncMap_[static_cast<uint32_t>(IAmsMgr::Message::REGISTER_APP_DEBUG_LISTENER)] =
        &AmsMgrStub::HandleRegisterAppDebugListener;
    memberFuncMap_[static_cast<uint32_t>(IAmsMgr::Message::UNREGISTER_APP_DEBUG_LISTENER)] =
        &AmsMgrStub::HandleUnregisterAppDebugListener;
    memberFuncMap_[static_cast<uint32_t>(IAmsMgr::Message::ATTACH_APP_DEBUG)] =
        &AmsMgrStub::HandleAttachAppDebug;
    memberFuncMap_[static_cast<uint32_t>(IAmsMgr::Message::DETACH_APP_DEBUG)] =
        &AmsMgrStub::HandleDetachAppDebug;
    memberFuncMap_[static_cast<uint32_t>(IAmsMgr::Message::SET_APP_WAITING_DEBUG)] =
        &AmsMgrStub::HandleSetAppWaitingDebug;
    memberFuncMap_[static_cast<uint32_t>(IAmsMgr::Message::CANCEL_APP_WAITING_DEBUG)] =
        &AmsMgrStub::HandleCancelAppWaitingDebug;
    memberFuncMap_[static_cast<uint32_t>(IAmsMgr::Message::GET_WAITING_DEBUG_APP)] =
        &AmsMgrStub::HandleGetWaitingDebugApp;
    memberFuncMap_[static_cast<uint32_t>(IAmsMgr::Message::IS_WAITING_DEBUG_APP)] =
        &AmsMgrStub::HandleIsWaitingDebugApp;
    memberFuncMap_[static_cast<uint32_t>(IAmsMgr::Message::CLEAR_NON_PERSIST_WAITING_DEBUG_FLAG)] =
        &AmsMgrStub::HandleClearNonPersistWaitingDebugFlag;
    memberFuncMap_[static_cast<uint32_t>(IAmsMgr::Message::REGISTER_ABILITY_DEBUG_RESPONSE)] =
        &AmsMgrStub::HandleRegisterAbilityDebugResponse;
    memberFuncMap_[static_cast<uint32_t>(IAmsMgr::Message::IS_ATTACH_DEBUG)] =
        &AmsMgrStub::HandleIsAttachDebug;
    memberFuncMap_[static_cast<uint32_t>(IAmsMgr::Message::SET_APP_ASSERT_PAUSE_STATE)] =
        &AmsMgrStub::HandleSetAppAssertionPauseState;
    memberFuncMap_[static_cast<uint32_t>(IAmsMgr::Message::CLEAR_PROCESS_BY_TOKEN)] =
        &AmsMgrStub::HandleClearProcessByToken;
    memberFuncMap_[static_cast<uint32_t>(IAmsMgr::Message::KILL_PROCESSES_BY_PIDS)] =
        &AmsMgrStub::HandleKillProcessesByPids;
    memberFuncMap_[static_cast<uint32_t>(IAmsMgr::Message::ATTACH_PID_TO_PARENT)] =
        &AmsMgrStub::HandleAttachPidToParent;
    memberFuncMap_[static_cast<uint32_t>(IAmsMgr::Message::IS_MEMORY_SIZE_SUFFICIENT)] =
        &AmsMgrStub::HandleIsMemorySizeSufficent;
    memberFuncMap_[static_cast<uint32_t>(IAmsMgr::Message::SET_KEEP_ALIVE_ENABLE_STATE)] =
        &AmsMgrStub::HandleSetKeepAliveEnableState;
}

int AmsMgrStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    if (code != static_cast<uint32_t>(IAmsMgr::Message::Get_BUNDLE_NAME_BY_PID)) {
        TAG_LOGI(AAFwkTag::APPMGR, "AmsMgrStub::OnReceived, code = %{public}u, flags= %{public}d.", code,
            option.GetFlags());
    }
    std::u16string descriptor = AmsMgrStub::GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (descriptor != remoteDescriptor) {
        TAG_LOGE(AAFwkTag::APPMGR, "local descriptor is unequal to remote");
        return ERR_INVALID_STATE;
    }

    auto itFunc = memberFuncMap_.find(code);
    if (itFunc != memberFuncMap_.end()) {
        auto memberFunc = itFunc->second;
        if (memberFunc != nullptr) {
            return (this->*memberFunc)(data, reply);
        }
    }
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

ErrCode AmsMgrStub::HandleLoadAbility(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER(HITRACE_TAG_APP);
    sptr<IRemoteObject> token = nullptr;
    sptr<IRemoteObject> preToke = nullptr;
    if (data.ReadBool()) {
        token = data.ReadRemoteObject();
    }
    if (data.ReadBool()) {
        preToke = data.ReadRemoteObject();
    }
    std::shared_ptr<AbilityInfo> abilityInfo(data.ReadParcelable<AbilityInfo>());
    if (!abilityInfo) {
        TAG_LOGE(AAFwkTag::APPMGR, "ReadParcelable<AbilityInfo> failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    std::shared_ptr<ApplicationInfo> appInfo(data.ReadParcelable<ApplicationInfo>());
    if (!appInfo) {
        TAG_LOGE(AAFwkTag::APPMGR, "ReadParcelable<ApplicationInfo> failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    std::shared_ptr<AAFwk::Want> want(data.ReadParcelable<AAFwk::Want>());
    if (!want) {
        TAG_LOGE(AAFwkTag::APPMGR, "ReadParcelable want failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t abilityRecordId = data.ReadInt32();

    LoadAbility(token, preToke, abilityInfo, appInfo, want, abilityRecordId);
    return NO_ERROR;
}

ErrCode AmsMgrStub::HandleTerminateAbility(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER(HITRACE_TAG_APP);
    sptr<IRemoteObject> token = data.ReadRemoteObject();
    bool clearMissionFlag = data.ReadBool();
    TerminateAbility(token, clearMissionFlag);
    return NO_ERROR;
}

ErrCode AmsMgrStub::HandleUpdateAbilityState(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER(HITRACE_TAG_APP);
    sptr<IRemoteObject> token = data.ReadRemoteObject();
    int32_t state = data.ReadInt32();
    UpdateAbilityState(token, static_cast<AbilityState>(state));
    return NO_ERROR;
}

ErrCode AmsMgrStub::HandleUpdateExtensionState(MessageParcel &data, MessageParcel &reply)
{
    sptr<IRemoteObject> token = data.ReadRemoteObject();
    int32_t state = data.ReadInt32();
    UpdateExtensionState(token, static_cast<ExtensionState>(state));
    return NO_ERROR;
}

ErrCode AmsMgrStub::HandleRegisterAppStateCallback(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER(HITRACE_TAG_APP);
    sptr<IAppStateCallback> callback = nullptr;
    if (data.ReadBool()) {
        sptr<IRemoteObject> obj = data.ReadRemoteObject();
        callback = iface_cast<IAppStateCallback>(obj);
    }
    RegisterAppStateCallback(callback);
    return NO_ERROR;
}

ErrCode AmsMgrStub::HandleAbilityBehaviorAnalysis(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER(HITRACE_TAG_APP);
    sptr<IRemoteObject> token = data.ReadRemoteObject();
    sptr<IRemoteObject> preToke = nullptr;
    if (data.ReadBool()) {
        preToke = data.ReadRemoteObject();
    }
    int32_t visibility = data.ReadInt32();
    int32_t perceptibility = data.ReadInt32();
    int32_t connectionState = data.ReadInt32();

    AbilityBehaviorAnalysis(token, preToke, visibility, perceptibility, connectionState);
    return NO_ERROR;
}

ErrCode AmsMgrStub::HandleKillProcessByAbilityToken(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER(HITRACE_TAG_APP);
    sptr<IRemoteObject> token = data.ReadRemoteObject();

    KillProcessByAbilityToken(token);
    return NO_ERROR;
}

ErrCode AmsMgrStub::HandleKillProcessesByUserId(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER(HITRACE_TAG_APP);
    int32_t userId = data.ReadInt32();

    KillProcessesByUserId(userId);
    return NO_ERROR;
}

ErrCode AmsMgrStub::HandleKillProcessesByPids(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER(HITRACE_TAG_APP);
    auto size = data.ReadUint32();
    if (size == 0 || size > MAX_KILL_PROCESS_PID_COUNT) {
        TAG_LOGE(AAFwkTag::APPMGR, "Invalid size.");
        return ERR_INVALID_VALUE;
    }
    std::vector<int32_t> pids;
    for (uint32_t i = 0; i < size; i++) {
        pids.emplace_back(data.ReadInt32());
    }

    KillProcessesByPids(pids);
    return NO_ERROR;
}

ErrCode AmsMgrStub::HandleAttachPidToParent(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER(HITRACE_TAG_APP);
    sptr<IRemoteObject> token = data.ReadRemoteObject();
    sptr<IRemoteObject> callerToken = data.ReadRemoteObject();
    AttachPidToParent(token, callerToken);
    return NO_ERROR;
}

ErrCode AmsMgrStub::HandleKillProcessWithAccount(MessageParcel &data, MessageParcel &reply)
{
    TAG_LOGI(AAFwkTag::APPMGR, "enter");

    HITRACE_METER(HITRACE_TAG_APP);

    std::string bundleName = data.ReadString();
    int accountId = data.ReadInt32();

    TAG_LOGI(AAFwkTag::APPMGR, "bundleName = %{public}s, accountId = %{public}d", bundleName.c_str(), accountId);

    int32_t result = KillProcessWithAccount(bundleName, accountId);
    reply.WriteInt32(result);

    TAG_LOGI(AAFwkTag::APPMGR, "end");

    return NO_ERROR;
}

ErrCode AmsMgrStub::HandleKillApplication(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER(HITRACE_TAG_APP);
    std::string bundleName = data.ReadString();
    int32_t result = KillApplication(bundleName);
    reply.WriteInt32(result);
    return NO_ERROR;
}

ErrCode AmsMgrStub::HandleKillApplicationByUid(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER(HITRACE_TAG_APP);
    std::string bundleName = data.ReadString();
    int uid = data.ReadInt32();
    int32_t result = KillApplicationByUid(bundleName, uid);
    reply.WriteInt32(result);
    return NO_ERROR;
}

ErrCode AmsMgrStub::HandleKillApplicationSelf(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER(HITRACE_TAG_APP);
    int32_t result = KillApplicationSelf();
    if (!reply.WriteInt32(result)) {
        TAG_LOGE(AAFwkTag::APPMGR, "result write failed.");
        return ERR_INVALID_VALUE;
    }
    return NO_ERROR;
}

int32_t AmsMgrStub::HandleAbilityAttachTimeOut(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER(HITRACE_TAG_APP);
    sptr<IRemoteObject> token = data.ReadRemoteObject();
    AbilityAttachTimeOut(token);
    return NO_ERROR;
}

int32_t AmsMgrStub::HandlePrepareTerminate(MessageParcel &data, MessageParcel &reply)
{
    sptr<IRemoteObject> token = data.ReadRemoteObject();
    PrepareTerminate(token);
    return NO_ERROR;
}

void AmsMgrStub::UpdateExtensionState(const sptr<IRemoteObject> &token, const ExtensionState state)
{}

int32_t AmsMgrStub::HandleGetRunningProcessInfoByToken(MessageParcel &data, MessageParcel &reply)
{
    RunningProcessInfo processInfo;
    auto token = data.ReadRemoteObject();
    GetRunningProcessInfoByToken(token, processInfo);
    if (reply.WriteParcelable(&processInfo)) {
        TAG_LOGE(AAFwkTag::APPMGR, "process info write failed.");
        return ERR_INVALID_VALUE;
    }
    return NO_ERROR;
}

int32_t AmsMgrStub::HandleGetRunningProcessInfoByPid(MessageParcel &data, MessageParcel &reply)
{
    RunningProcessInfo processInfo;
    auto pid = static_cast<pid_t>(data.ReadInt32());
    GetRunningProcessInfoByPid(pid, processInfo);
    if (reply.WriteParcelable(&processInfo)) {
        TAG_LOGE(AAFwkTag::APPMGR, "process info write failed.");
        return ERR_INVALID_VALUE;
    }
    return NO_ERROR;
}

int32_t AmsMgrStub::HandleSetAbilityForegroundingFlagToAppRecord(MessageParcel &data, MessageParcel &reply)
{
    RunningProcessInfo processInfo;
    auto pid = static_cast<pid_t>(data.ReadInt32());
    SetAbilityForegroundingFlagToAppRecord(pid);
    return NO_ERROR;
}

int32_t AmsMgrStub::HandleStartSpecifiedAbility(MessageParcel &data, MessageParcel &reply)
{
    AAFwk::Want *want = data.ReadParcelable<AAFwk::Want>();
    if (want == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "want is nullptr");
        return ERR_INVALID_VALUE;
    }

    AbilityInfo *abilityInfo = data.ReadParcelable<AbilityInfo>();
    if (abilityInfo == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "abilityInfo is nullptr.");
        delete want;
        return ERR_INVALID_VALUE;
    }
    StartSpecifiedAbility(*want, *abilityInfo, data.ReadInt32());
    delete want;
    delete abilityInfo;
    return NO_ERROR;
}

int32_t AmsMgrStub::HandleRegisterStartSpecifiedAbilityResponse(MessageParcel &data, MessageParcel &reply)
{
    sptr<IRemoteObject> obj = data.ReadRemoteObject();
    sptr<IStartSpecifiedAbilityResponse> response = iface_cast<IStartSpecifiedAbilityResponse>(obj);
    RegisterStartSpecifiedAbilityResponse(response);
    return NO_ERROR;
}

int32_t AmsMgrStub::HandleGetApplicationInfoByProcessID(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER(HITRACE_TAG_APP);
    int32_t pid = data.ReadInt32();
    AppExecFwk::ApplicationInfo application;
    bool debug;
    int32_t result = GetApplicationInfoByProcessID(pid, application, debug);
    if (!reply.WriteInt32(result)) {
        TAG_LOGE(AAFwkTag::APPMGR, "write result error.");
        return ERR_INVALID_VALUE;
    }
    if (!reply.WriteParcelable(&application)) {
        TAG_LOGE(AAFwkTag::APPMGR, "write application info failed");
        return ERR_INVALID_VALUE;
    }
    if (!reply.WriteBool(debug)) {
        TAG_LOGE(AAFwkTag::APPMGR, "write debug info failed");
        return ERR_INVALID_VALUE;
    }
    return NO_ERROR;
}

int32_t AmsMgrStub::HandleNotifyAppMgrRecordExitReason(MessageParcel &data, MessageParcel &reply)
{
    TAG_LOGD(AAFwkTag::APPMGR, "HandleNotifyAppMgrRecordExitReason called.");
    int32_t pid = data.ReadInt32();
    int32_t reason = data.ReadInt32();
    std::string exitMsg = Str16ToStr8(data.ReadString16());
    int32_t result = NotifyAppMgrRecordExitReason(pid, reason, exitMsg);
    if (!reply.WriteInt32(result)) {
        TAG_LOGE(AAFwkTag::APPMGR, "Write result failed.");
        return IPC_PROXY_ERR;
    }
    return NO_ERROR;
}

int32_t AmsMgrStub::HandleUpdateApplicationInfoInstalled(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER(HITRACE_TAG_APP);
    std::string bundleName = data.ReadString();
    int uid = data.ReadInt32();
    int32_t result = UpdateApplicationInfoInstalled(bundleName, uid);
    reply.WriteInt32(result);
    return NO_ERROR;
}

int32_t AmsMgrStub::HandleSetCurrentUserId(MessageParcel &data, MessageParcel &reply)
{
    int32_t userId = data.ReadInt32();
    SetCurrentUserId(userId);
    return NO_ERROR;
}

int32_t AmsMgrStub::HandleGetBundleNameByPid(MessageParcel &data, MessageParcel &reply)
{
    int32_t pid = data.ReadInt32();
    std::string bundleName;
    int32_t uid;
    GetBundleNameByPid(pid, bundleName, uid);

    reply.WriteString(bundleName);
    reply.WriteInt32(uid);
    return NO_ERROR;
}

int32_t AmsMgrStub::HandleRegisterAppDebugListener(MessageParcel &data, MessageParcel &reply)
{
    TAG_LOGD(AAFwkTag::APPMGR, "Called.");
    auto appDebugLister = iface_cast<IAppDebugListener>(data.ReadRemoteObject());
    if (appDebugLister == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "App debug lister is null.");
        return ERR_INVALID_VALUE;
    }

    auto result = RegisterAppDebugListener(appDebugLister);
    if (!reply.WriteInt32(result)) {
        TAG_LOGE(AAFwkTag::APPMGR, "Fail to write result.");
        return ERR_INVALID_VALUE;
    }
    return NO_ERROR;
}

int32_t AmsMgrStub::HandleUnregisterAppDebugListener(MessageParcel &data, MessageParcel &reply)
{
    TAG_LOGD(AAFwkTag::APPMGR, "Called.");
    auto appDebugLister = iface_cast<IAppDebugListener>(data.ReadRemoteObject());
    if (appDebugLister == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "App debug lister is nullptr.");
        return ERR_INVALID_VALUE;
    }

    auto result = UnregisterAppDebugListener(appDebugLister);
    if (!reply.WriteInt32(result)) {
        TAG_LOGE(AAFwkTag::APPMGR, "Fail to write result.");
        return ERR_INVALID_VALUE;
    }
    return NO_ERROR;
}

int32_t AmsMgrStub::HandleAttachAppDebug(MessageParcel &data, MessageParcel &reply)
{
    TAG_LOGD(AAFwkTag::APPMGR, "Called.");
    auto bundleName = data.ReadString();
    if (bundleName.empty()) {
        TAG_LOGE(AAFwkTag::APPMGR, "Bundle name is empty.");
        return ERR_INVALID_VALUE;
    }

    auto result = AttachAppDebug(bundleName);
    if (!reply.WriteInt32(result)) {
        TAG_LOGE(AAFwkTag::APPMGR, "Fail to write result.");
        return ERR_INVALID_VALUE;
    }
    return NO_ERROR;
}

int32_t AmsMgrStub::HandleDetachAppDebug(MessageParcel &data, MessageParcel &reply)
{
    TAG_LOGD(AAFwkTag::APPMGR, "Called.");
    auto bundleName = data.ReadString();
    if (bundleName.empty()) {
        TAG_LOGE(AAFwkTag::APPMGR, "Bundle name is empty.");
        return ERR_INVALID_VALUE;
    }

    auto result = DetachAppDebug(bundleName);
    if (!reply.WriteInt32(result)) {
        TAG_LOGE(AAFwkTag::APPMGR, "Fail to write result.");
        return ERR_INVALID_VALUE;
    }
    return NO_ERROR;
}

int32_t AmsMgrStub::HandleSetAppWaitingDebug(MessageParcel &data, MessageParcel &reply)
{
    TAG_LOGD(AAFwkTag::APPMGR, "Called.");
    auto bundleName = data.ReadString();
    if (bundleName.empty()) {
        TAG_LOGE(AAFwkTag::APPMGR, "Bundle name is empty.");
        return ERR_INVALID_VALUE;
    }
    auto isPersist = data.ReadBool();
    auto result = SetAppWaitingDebug(bundleName, isPersist);
    if (!reply.WriteInt32(result)) {
        TAG_LOGE(AAFwkTag::APPMGR, "Fail to write result.");
        return ERR_INVALID_VALUE;
    }
    return NO_ERROR;
}

int32_t AmsMgrStub::HandleCancelAppWaitingDebug(MessageParcel &data, MessageParcel &reply)
{
    TAG_LOGD(AAFwkTag::APPMGR, "Called.");
    auto result = CancelAppWaitingDebug();
    if (!reply.WriteInt32(result)) {
        TAG_LOGE(AAFwkTag::APPMGR, "Fail to write result.");
        return ERR_INVALID_VALUE;
    }
    return NO_ERROR;
}

int32_t AmsMgrStub::HandleGetWaitingDebugApp(MessageParcel &data, MessageParcel &reply)
{
    TAG_LOGD(AAFwkTag::APPMGR, "Called.");
    std::vector<std::string> debugInfoList;
    auto result = GetWaitingDebugApp(debugInfoList);
    if (!reply.WriteInt32(result)) {
        TAG_LOGE(AAFwkTag::APPMGR, "Fail to write result.");
        return ERR_INVALID_VALUE;
    }

    int32_t listSize = static_cast<int32_t>(debugInfoList.size());
    if (listSize > MAX_APP_DEBUG_COUNT) {
        TAG_LOGE(AAFwkTag::APPMGR, "Max app debug count is %{public}d.", listSize);
        return ERR_INVALID_VALUE;
    }

    if (!reply.WriteInt32(listSize)) {
        TAG_LOGE(AAFwkTag::APPMGR, "Fail to write list size.");
        return ERR_INVALID_VALUE;
    }

    if (!reply.WriteStringVector(debugInfoList)) {
        TAG_LOGE(AAFwkTag::APPMGR, "Fail to write string vector debug info list.");
        return ERR_INVALID_VALUE;
    }
    return NO_ERROR;
}

int32_t AmsMgrStub::HandleIsWaitingDebugApp(MessageParcel &data, MessageParcel &reply)
{
    TAG_LOGD(AAFwkTag::APPMGR, "Called.");
    auto bundleName = data.ReadString();
    if (bundleName.empty()) {
        TAG_LOGE(AAFwkTag::APPMGR, "Bundle name is empty.");
        return ERR_INVALID_VALUE;
    }

    auto result = IsWaitingDebugApp(bundleName);
    if (!reply.WriteBool(result)) {
        TAG_LOGE(AAFwkTag::APPMGR, "Fail to write result.");
        return ERR_INVALID_VALUE;
    }
    return NO_ERROR;
}

int32_t AmsMgrStub::HandleSetKeepAliveEnableState(MessageParcel &data, MessageParcel &reply)
{
    TAG_LOGD(AAFwkTag::APPMGR, "Called.");
    auto bundleName = data.ReadString();
    auto enable = data.ReadBool();
    SetKeepAliveEnableState(bundleName, enable);
    return NO_ERROR;
}

int32_t AmsMgrStub::HandleClearNonPersistWaitingDebugFlag(MessageParcel &data, MessageParcel &reply)
{
    TAG_LOGD(AAFwkTag::APPMGR, "Called.");
    ClearNonPersistWaitingDebugFlag();
    return NO_ERROR;
}

int32_t AmsMgrStub::HandleRegisterAbilityDebugResponse(MessageParcel &data, MessageParcel &reply)
{
    TAG_LOGD(AAFwkTag::APPMGR, "Called.");
    auto response = iface_cast<IAbilityDebugResponse>(data.ReadRemoteObject());
    if (response == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "Response is nullptr.");
        return ERR_INVALID_VALUE;
    }

    auto result = RegisterAbilityDebugResponse(response);
    if (!reply.WriteInt32(result)) {
        TAG_LOGE(AAFwkTag::APPMGR, "Fail to write result.");
        return ERR_INVALID_VALUE;
    }
    return NO_ERROR;
}

int32_t AmsMgrStub::HandleIsAttachDebug(MessageParcel &data, MessageParcel &reply)
{
    TAG_LOGD(AAFwkTag::APPMGR, "Called.");
    auto bundleName = data.ReadString();
    if (bundleName.empty()) {
        TAG_LOGE(AAFwkTag::APPMGR, "Bundle name is empty.");
        return ERR_INVALID_VALUE;
    }

    auto result = IsAttachDebug(bundleName);
    if (!reply.WriteBool(result)) {
        TAG_LOGE(AAFwkTag::APPMGR, "Fail to write result.");
        return ERR_INVALID_VALUE;
    }
    return NO_ERROR;
}

int32_t AmsMgrStub::HandleSetAppAssertionPauseState(MessageParcel &data, MessageParcel &reply)
{
    TAG_LOGD(AAFwkTag::APPMGR, "Called.");
    auto pid = data.ReadInt32();
    auto flag = data.ReadBool();
    SetAppAssertionPauseState(pid, flag);
    return NO_ERROR;
}

int32_t AmsMgrStub::HandleClearProcessByToken(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER(HITRACE_TAG_APP);
    sptr<IRemoteObject> token = data.ReadRemoteObject();
    ClearProcessByToken(token);
    return NO_ERROR;
}

int32_t AmsMgrStub::HandleIsMemorySizeSufficent(MessageParcel &data, MessageParcel &reply)
{
    auto result = IsMemorySizeSufficent();
    if (!reply.WriteBool(result)) {
        HILOG_ERROR("Fail to write result.");
        return ERR_INVALID_VALUE;
    }
    return NO_ERROR;
}
}  // namespace AppExecFwk
}  // namespace OHOS
