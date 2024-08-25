/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "free_install_manager.h"

#include <chrono>

#include "ability_info.h"
#include "ability_manager_errors.h"
#include "ability_manager_service.h"
#include "ability_util.h"
#include "atomic_service_status_callback.h"
#include "distributed_client.h"
#include "free_install_observer_manager.h"
#include "hilog_tag_wrapper.h"
#include "hilog_wrapper.h"
#include "hitrace_meter.h"
#include "in_process_call_wrapper.h"
#include "uri_utils.h"

namespace OHOS {
namespace AAFwk {
const std::u16string DMS_FREE_INSTALL_CALLBACK_TOKEN = u"ohos.DistributedSchedule.IDmsFreeInstallCallback";
const std::string DMS_MISSION_ID = "dmsMissionId";
const std::string PARAM_FREEINSTALL_APPID = "ohos.freeinstall.params.callingAppId";
const std::string PARAM_FREEINSTALL_BUNDLENAMES = "ohos.freeinstall.params.callingBundleNames";
const std::string PARAM_FREEINSTALL_UID = "ohos.freeinstall.params.callingUid";
constexpr uint32_t IDMS_CALLBACK_ON_FREE_INSTALL_DONE = 0;
constexpr uint32_t UPDATE_ATOMOIC_SERVICE_TASK_TIMER = 24 * 60 * 60 * 1000; /* 24h */

FreeInstallManager::FreeInstallManager(const std::weak_ptr<AbilityManagerService> &server)
    : server_(server)
{
}

bool FreeInstallManager::IsTopAbility(const sptr<IRemoteObject> &callerToken)
{
    TAG_LOGI(AAFwkTag::FREE_INSTALL, "%{public}s", __func__);
    auto server = server_.lock();
    CHECK_POINTER_AND_RETURN_LOG(server, false, "Get server failed!");
    AppExecFwk::ElementName elementName = IN_PROCESS_CALL(server->GetTopAbility());
    if (elementName.GetBundleName().empty() || elementName.GetAbilityName().empty()) {
        TAG_LOGE(AAFwkTag::FREE_INSTALL, "GetBundleName or GetAbilityName empty!");
        return false;
    }

    auto caller = Token::GetAbilityRecordByToken(callerToken);
    if (caller == nullptr) {
        TAG_LOGE(AAFwkTag::FREE_INSTALL, "Caller is null!");
        return false;
    }

    auto type = caller->GetAbilityInfo().type;
    if (type == AppExecFwk::AbilityType::SERVICE || type == AppExecFwk::AbilityType::EXTENSION) {
        TAG_LOGI(AAFwkTag::FREE_INSTALL, "The ability is service or extension ability.");
        return true;
    }

    AppExecFwk::ElementName callerElementName = caller->GetElementName();
    std::string callerBundleName = callerElementName.GetBundleName();
    std::string callerAbilityName = callerElementName.GetAbilityName();
    std::string callerModuleName = callerElementName.GetModuleName();
    if (elementName.GetBundleName().compare(callerBundleName) == 0 &&
        elementName.GetAbilityName().compare(callerAbilityName) == 0 &&
        elementName.GetModuleName().compare(callerModuleName) == 0) {
        TAG_LOGI(AAFwkTag::FREE_INSTALL, "The ability is top ability.");
        return true;
    }

    return false;
}

int FreeInstallManager::StartFreeInstall(const Want &want, int32_t userId, int requestCode,
    const sptr<IRemoteObject> &callerToken, bool isAsync)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGI(AAFwkTag::FREE_INSTALL, "StartFreeInstall called");
    auto isSaCall = AAFwk::PermissionVerification::GetInstance()->IsSACall();
    if (!isSaCall && !IsTopAbility(callerToken)) {
        return NOT_TOP_ABILITY;
    }
    FreeInstallInfo info = BuildFreeInstallInfo(want, userId, requestCode, callerToken, isAsync);
    {
        std::lock_guard<ffrt::mutex> lock(freeInstallListLock_);
        freeInstallList_.push_back(info);
    }
    sptr<AtomicServiceStatusCallback> callback = new AtomicServiceStatusCallback(weak_from_this(), isAsync);
    auto bundleMgrHelper = AbilityUtil::GetBundleManagerHelper();
    CHECK_POINTER_AND_RETURN(bundleMgrHelper, GET_ABILITY_SERVICE_FAILED);
    AppExecFwk::AbilityInfo abilityInfo = {};
    constexpr auto flag = AppExecFwk::AbilityInfoFlag::GET_ABILITY_INFO_WITH_APPLICATION;
    info.want.SetParam(PARAM_FREEINSTALL_UID, IPCSkeleton::GetCallingUid());

    if (IN_PROCESS_CALL(bundleMgrHelper->QueryAbilityInfo(info.want, flag, info.userId, abilityInfo, callback))) {
        TAG_LOGI(AAFwkTag::FREE_INSTALL, "The app has installed.");
    }
    std::string callingAppId = info.want.GetStringParam(PARAM_FREEINSTALL_APPID);
    std::vector<std::string> callingBundleNames = info.want.GetStringArrayParam(PARAM_FREEINSTALL_BUNDLENAMES);
    if (callingAppId.empty() && callingBundleNames.empty()) {
        TAG_LOGI(AAFwkTag::FREE_INSTALL, "callingAppId and callingBundleNames are empty");
    }
    info.want.RemoveParam(PARAM_FREEINSTALL_APPID);
    info.want.RemoveParam(PARAM_FREEINSTALL_BUNDLENAMES);

    if (isAsync) {
        return ERR_OK;
    } else {
        auto future = info.promise->get_future();
        std::future_status status = future.wait_for(std::chrono::milliseconds(DELAY_LOCAL_FREE_INSTALL_TIMEOUT));
        if (status == std::future_status::timeout) {
            RemoveFreeInstallInfo(info.want.GetElement().GetBundleName(), info.want.GetElement().GetAbilityName(),
                info.want.GetStringParam(Want::PARAM_RESV_START_TIME));
            return FREE_INSTALL_TIMEOUT;
        }
        return future.get();
    }
}

int FreeInstallManager::RemoteFreeInstall(const Want &want, int32_t userId, int requestCode,
    const sptr<IRemoteObject> &callerToken)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGI(AAFwkTag::FREE_INSTALL, "RemoteFreeInstall called");
    bool isFromRemote = want.GetBoolParam(FROM_REMOTE_KEY, false);
    auto isSaCall = AAFwk::PermissionVerification::GetInstance()->IsSACall();
    if (!isSaCall && !isFromRemote && !IsTopAbility(callerToken)) {
        return NOT_TOP_ABILITY;
    }
    FreeInstallInfo info = BuildFreeInstallInfo(want, userId, requestCode, callerToken, false);
    {
        std::lock_guard<ffrt::mutex> lock(freeInstallListLock_);
        freeInstallList_.push_back(info);
    }
    sptr<AtomicServiceStatusCallback> callback = new AtomicServiceStatusCallback(weak_from_this(), false);
    int32_t callerUid = IPCSkeleton::GetCallingUid();
    uint32_t accessToken = IPCSkeleton::GetCallingTokenID();
    UriUtils::GetInstance().FilterUriWithPermissionDms(info.want, accessToken);
    DistributedClient dmsClient;
    auto result = dmsClient.StartRemoteFreeInstall(info.want, callerUid, info.requestCode, accessToken, callback);
    if (result != ERR_NONE) {
        return result;
    }
    auto remoteFuture = info.promise->get_future();
    std::future_status remoteStatus = remoteFuture.wait_for(std::chrono::milliseconds(
        DELAY_REMOTE_FREE_INSTALL_TIMEOUT));
    if (remoteStatus == std::future_status::timeout) {
        return FREE_INSTALL_TIMEOUT;
    }
    return remoteFuture.get();
}

FreeInstallInfo FreeInstallManager::BuildFreeInstallInfo(const Want &want, int32_t userId, int requestCode,
    const sptr<IRemoteObject> &callerToken, bool isAsync)
{
    FreeInstallInfo info = {
        .want = want,
        .userId = userId,
        .requestCode = requestCode,
        .callerToken = callerToken
    };
    if (!isAsync) {
        auto promise = std::make_shared<std::promise<int32_t>>();
        info.promise = promise;
    }
    auto identity = IPCSkeleton::ResetCallingIdentity();
    info.identity = identity;
    IPCSkeleton::SetCallingIdentity(identity);
    return info;
}

int FreeInstallManager::StartRemoteFreeInstall(const Want &want, int requestCode, int32_t validUserId,
    const sptr<IRemoteObject> &callerToken)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGI(AAFwkTag::FREE_INSTALL, "%{public}s", __func__);
    if (!want.GetBoolParam(Want::PARAM_RESV_FOR_RESULT, false)) {
        TAG_LOGI(AAFwkTag::FREE_INSTALL, "%{public}s: StartAbility freeInstall", __func__);
        return RemoteFreeInstall(want, validUserId, requestCode, callerToken);
    }
    int32_t missionId = DelayedSingleton<AbilityManagerService>::GetInstance()->
        GetMissionIdByAbilityToken(callerToken);
    if (missionId < 0) {
        return ERR_INVALID_VALUE;
    }
    Want* newWant = const_cast<Want*>(&want);
    newWant->SetParam(DMS_MISSION_ID, missionId);
    TAG_LOGI(AAFwkTag::FREE_INSTALL, "%{public}s: StartAbilityForResult freeInstall", __func__);
    return RemoteFreeInstall(*newWant, validUserId, requestCode, callerToken);
}

int FreeInstallManager::NotifyDmsCallback(const Want &want, int resultCode)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    std::lock_guard<ffrt::mutex> autoLock(distributedFreeInstallLock_);
    if (dmsFreeInstallCbs_.empty()) {
        TAG_LOGE(AAFwkTag::FREE_INSTALL, "Has no dms callback.");
        return ERR_INVALID_VALUE;
    }

    MessageParcel reply;
    MessageOption option;

    for (auto it = dmsFreeInstallCbs_.begin(); it != dmsFreeInstallCbs_.end();) {
        std::string abilityName = (*it).want.GetElement().GetAbilityName();
        if (want.GetElement().GetAbilityName().compare(abilityName) == 0) {
            TAG_LOGI(AAFwkTag::FREE_INSTALL, "Handle DMS.");
            MessageParcel data;
            if (!data.WriteInterfaceToken(DMS_FREE_INSTALL_CALLBACK_TOKEN)) {
                TAG_LOGE(AAFwkTag::FREE_INSTALL, "Write interface token failed.");
                return ERR_INVALID_VALUE;
            }

            if (!data.WriteInt32(resultCode)) {
                TAG_LOGE(AAFwkTag::FREE_INSTALL, "Write resultCode error.");
                return ERR_INVALID_VALUE;
            }

            if (!data.WriteParcelable(&((*it).want))) {
                TAG_LOGE(AAFwkTag::FREE_INSTALL, "want write failed.");
                return INNER_ERR;
            }

            if (!data.WriteInt32((*it).requestCode)) {
                TAG_LOGE(AAFwkTag::FREE_INSTALL, "Write resultCode error.");
                return ERR_INVALID_VALUE;
            }

            (*it).dmsCallback->SendRequest(IDMS_CALLBACK_ON_FREE_INSTALL_DONE, data, reply, option);
            it = dmsFreeInstallCbs_.erase(it);
        } else {
            it++;
        }
    }

    return reply.ReadInt32();
}

void FreeInstallManager::NotifyFreeInstallResult(const Want &want, int resultCode, bool isAsync)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    std::lock_guard<ffrt::mutex> lock(freeInstallListLock_);
    if (freeInstallList_.empty()) {
        TAG_LOGI(AAFwkTag::FREE_INSTALL, "Has no app callback.");
        return;
    }

    bool isFromRemote = want.GetBoolParam(FROM_REMOTE_KEY, false);
    TAG_LOGI(AAFwkTag::FREE_INSTALL, "isFromRemote = %{public}d", isFromRemote);
    for (auto it = freeInstallList_.begin(); it != freeInstallList_.end();) {
        std::string bundleName = (*it).want.GetElement().GetBundleName();
        std::string abilityName = (*it).want.GetElement().GetAbilityName();
        std::string startTime = (*it).want.GetStringParam(Want::PARAM_RESV_START_TIME);
        if (want.GetElement().GetBundleName().compare(bundleName) != 0 ||
            want.GetElement().GetAbilityName().compare(abilityName) != 0 ||
            want.GetStringParam(Want::PARAM_RESV_START_TIME).compare(startTime) != 0) {
            it++;
            continue;
        }

        if (!isAsync && (*it).promise == nullptr) {
            it++;
            continue;
        }

        if (resultCode == ERR_OK) {
            TAG_LOGI(AAFwkTag::FREE_INSTALL, "FreeInstall success.");
            if (isAsync) {
                StartAbilityByFreeInstall(*it, bundleName, abilityName, startTime);
            } else {
                (*it).promise->set_value(resultCode);
            }
        } else {
            TAG_LOGI(AAFwkTag::FREE_INSTALL, "FreeInstall failed.");
            if (isAsync) {
                DelayedSingleton<FreeInstallObserverManager>::GetInstance()->OnInstallFinished(
                    bundleName, abilityName, startTime, resultCode);
            } else {
                (*it).promise->set_value(resultCode);
            }
        }

        it = freeInstallList_.erase(it);
    }
}

void FreeInstallManager::StartAbilityByFreeInstall(FreeInstallInfo &info, std::string &bundleName,
    std::string &abilityName, std::string &startTime)
{
    info.want.SetFlags(info.want.GetFlags() ^ Want::FLAG_INSTALL_ON_DEMAND);
    auto identity = IPCSkeleton::ResetCallingIdentity();
    IPCSkeleton::SetCallingIdentity(info.identity);
    int32_t result = ERR_OK;
    if (info.want.GetElement().GetAbilityName().empty()) {
        result = UpdateElementName(info.want, info.userId);
    }
    if (result == ERR_OK) {
        result = DelayedSingleton<AbilityManagerService>::GetInstance()->StartAbilityByFreeInstall(info.want,
            info.callerToken, info.userId, info.requestCode);
    }
    IPCSkeleton::SetCallingIdentity(identity);
    TAG_LOGI(AAFwkTag::FREE_INSTALL, "The result of StartAbility is %{public}d.", result);
    DelayedSingleton<FreeInstallObserverManager>::GetInstance()->OnInstallFinished(
        bundleName, abilityName, startTime, result);
}

int32_t FreeInstallManager::UpdateElementName(Want &want, int32_t userId) const
{
    auto bundleMgrHelper = AbilityUtil::GetBundleManagerHelper();
    CHECK_POINTER_AND_RETURN(bundleMgrHelper, ERR_INVALID_VALUE);
    Want launchWant;
    auto errCode = IN_PROCESS_CALL(bundleMgrHelper->GetLaunchWantForBundle(want.GetBundle(), launchWant, userId));
    if (errCode != ERR_OK) {
        TAG_LOGE(AAFwkTag::FREE_INSTALL, "GetLaunchWantForBundle returns %{public}d.", errCode);
        return errCode;
    }
    want.SetElement(launchWant.GetElement());
    return ERR_OK;
}

int FreeInstallManager::FreeInstallAbilityFromRemote(const Want &want, const sptr<IRemoteObject> &callback,
    int32_t userId, int requestCode)
{
    TAG_LOGI(AAFwkTag::FREE_INSTALL, "%{public}s", __func__);
    if (callback == nullptr) {
        TAG_LOGE(AAFwkTag::FREE_INSTALL, "FreeInstallAbilityFromRemote callback is nullptr.");
        return ERR_INVALID_VALUE;
    }

    FreeInstallInfo info = {
        .want = want,
        .userId = userId,
        .requestCode = requestCode,
        .dmsCallback = callback
    };

    {
        std::lock_guard<ffrt::mutex> autoLock(distributedFreeInstallLock_);
        dmsFreeInstallCbs_.push_back(info);
    }

    auto result = StartFreeInstall(info.want, info.userId, info.requestCode, nullptr);
    if (result != ERR_OK) {
        TAG_LOGE(AAFwkTag::FREE_INSTALL, "StartFreeInstall failed, errCode: %{public}d", result);
        NotifyDmsCallback(info.want, result);
    }
    return result;
}

int FreeInstallManager::ConnectFreeInstall(const Want &want, int32_t userId,
    const sptr<IRemoteObject> &callerToken, const std::string& localDeviceId)
{
    auto bundleMgrHelper = AbilityUtil::GetBundleManagerHelper();
    CHECK_POINTER_AND_RETURN(bundleMgrHelper, GET_ABILITY_SERVICE_FAILED);
    std::string wantDeviceId = want.GetElement().GetDeviceID();
    if (!(localDeviceId == wantDeviceId || wantDeviceId.empty())) {
        TAG_LOGE(AAFwkTag::FREE_INSTALL, "Failed to get device id.");
        return INVALID_PARAMETERS_ERR;
    }

    auto isSaCall = AAFwk::PermissionVerification::GetInstance()->IsSACall();
    if (!isSaCall) {
        std::string wantAbilityName = want.GetElement().GetAbilityName();
        std::string wantBundleName = want.GetElement().GetBundleName();
        if (wantBundleName.empty() || wantAbilityName.empty()) {
            TAG_LOGE(AAFwkTag::FREE_INSTALL, "The wantBundleName or wantAbilityName is empty.");
            return INVALID_PARAMETERS_ERR;
        }
        int callerUid = IPCSkeleton::GetCallingUid();
        std::string localBundleName;
        auto res = IN_PROCESS_CALL(bundleMgrHelper->GetNameForUid(callerUid, localBundleName));
        if (res != ERR_OK || localBundleName != wantBundleName) {
            TAG_LOGE(AAFwkTag::FREE_INSTALL, "The wantBundleName is not local BundleName.");
            return INVALID_PARAMETERS_ERR;
        }
    }

    AppExecFwk::AbilityInfo abilityInfo;
    std::vector<AppExecFwk::ExtensionAbilityInfo> extensionInfos;
    if (!IN_PROCESS_CALL(bundleMgrHelper->QueryAbilityInfo(
        want, AppExecFwk::AbilityInfoFlag::GET_ABILITY_INFO_WITH_APPLICATION, userId, abilityInfo)) &&
        !IN_PROCESS_CALL(bundleMgrHelper->QueryExtensionAbilityInfos(
            want, AppExecFwk::AbilityInfoFlag::GET_ABILITY_INFO_WITH_APPLICATION, userId, extensionInfos))) {
        TAG_LOGI(AAFwkTag::FREE_INSTALL, "AbilityManagerService::ConnectFreeInstall. try to StartFreeInstall");
        int result = StartFreeInstall(want, userId, DEFAULT_INVAL_VALUE, callerToken);
        if (result) {
            TAG_LOGE(AAFwkTag::FREE_INSTALL, "AbilityManagerService::ConnectFreeInstall. StartFreeInstall error");
            return result;
        }
        TAG_LOGI(AAFwkTag::FREE_INSTALL, "AbilityManagerService::ConnectFreeInstall. StartFreeInstall success");
    }
    return ERR_OK;
}

std::time_t FreeInstallManager::GetTimeStamp()
{
    std::chrono::time_point<std::chrono::system_clock, std::chrono::milliseconds> tp =
        std::chrono::time_point_cast<std::chrono::milliseconds>(std::chrono::system_clock::now());
    std::time_t timestamp = tp.time_since_epoch().count();
    return timestamp;
}

void FreeInstallManager::OnInstallFinished(int resultCode, const Want &want, int32_t userId, bool isAsync)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGI(AAFwkTag::FREE_INSTALL, "%{public}s resultCode = %{public}d", __func__, resultCode);

    NotifyDmsCallback(want, resultCode);
    NotifyFreeInstallResult(want, resultCode, isAsync);

    PostUpgradeAtomicServiceTask(resultCode, want, userId);
}

void FreeInstallManager::PostUpgradeAtomicServiceTask(int resultCode, const Want &want, int32_t userId)
{
    TAG_LOGI(AAFwkTag::FREE_INSTALL, "PostUpgradeAtomicServiceTask begin.");
    std::weak_ptr<FreeInstallManager> thisWptr(shared_from_this());
    if (resultCode == ERR_OK) {
        auto updateAtmoicServiceTask = [want, userId, thisWptr, &timeStampMap = timeStampMap_]() {
            auto sptr = thisWptr.lock();
            TAG_LOGD(AAFwkTag::FREE_INSTALL,
                "bundleName: %{public}s, moduleName: %{public}s", want.GetElement().GetBundleName().c_str(),
                want.GetElement().GetModuleName().c_str());
            std::string nameKey = want.GetElement().GetBundleName() + want.GetElement().GetModuleName();
            if (timeStampMap.find(nameKey) == timeStampMap.end() ||
                sptr->GetTimeStamp() - timeStampMap[nameKey] > UPDATE_ATOMOIC_SERVICE_TASK_TIMER) {
                auto bundleMgrHelper = AbilityUtil::GetBundleManagerHelper();
                CHECK_POINTER(bundleMgrHelper);
                bundleMgrHelper->UpgradeAtomicService(want, userId);
                timeStampMap.emplace(nameKey, sptr->GetTimeStamp());
            }
        };

        auto handler = DelayedSingleton<AbilityManagerService>::GetInstance()->GetTaskHandler();
        CHECK_POINTER_LOG(handler, "Fail to get Ability task handler.");
        handler->SubmitTask(updateAtmoicServiceTask, "UpdateAtmoicServiceTask");
    }
}

void FreeInstallManager::OnRemoteInstallFinished(int resultCode, const Want &want, int32_t userId)
{
    TAG_LOGI(AAFwkTag::FREE_INSTALL, "%{public}s resultCode = %{public}d", __func__, resultCode);
    NotifyFreeInstallResult(want, resultCode);
}

int FreeInstallManager::AddFreeInstallObserver(const sptr<AbilityRuntime::IFreeInstallObserver> &observer)
{
    TAG_LOGI(AAFwkTag::FREE_INSTALL, "Add FreeInstallObserver");
    return DelayedSingleton<FreeInstallObserverManager>::GetInstance()->AddObserver(observer);
}

void FreeInstallManager::PostTimeoutTask(const Want &want)
{
    TAG_LOGI(AAFwkTag::FREE_INSTALL, "PostTimeoutTask begin.");
    std::string bundleName = want.GetElement().GetBundleName();
    std::string abilityName = want.GetElement().GetAbilityName();
    std::string startTime = want.GetStringParam(Want::PARAM_RESV_START_TIME);
    auto task = [weak = weak_from_this(), bundleName, abilityName, startTime]() {
        auto self = weak.lock();
        if (!self) {
            TAG_LOGE(AAFwkTag::FREE_INSTALL, "this is nullptr");
            return;
        }
        DelayedSingleton<FreeInstallObserverManager>::GetInstance()->OnInstallFinished(bundleName, abilityName,
            startTime, FREE_INSTALL_TIMEOUT);
        self->RemoveFreeInstallInfo(bundleName, abilityName, startTime);
    };
    std::string taskName = std::string("FreeInstallTimeout_") + bundleName + std::string("_") +
        abilityName + std::string("_") + startTime;
    auto handler = DelayedSingleton<AbilityManagerService>::GetInstance()->GetTaskHandler();
    CHECK_POINTER_LOG(handler, "Fail to get AbilityTaskHandler.");
    handler->SubmitTask(task, taskName, DELAY_LOCAL_FREE_INSTALL_TIMEOUT);
}

void FreeInstallManager::RemoveTimeoutTask(const std::string &bundleName, const std::string &abilityName,
    const std::string &startTime)
{
    // remove timeout task
    std::string taskName = std::string("FreeInstallTimeout_") + bundleName + std::string("_") +
        abilityName + std::string("_") + startTime;
    TAG_LOGI(AAFwkTag::FREE_INSTALL, "RemoveTimeoutTask task name:%{public}s", taskName.c_str());
    auto handler = DelayedSingleton<AbilityManagerService>::GetInstance()->GetTaskHandler();
    CHECK_POINTER_LOG(handler, "Fail to get AbilityTaskHandler.");
    handler->CancelTask(taskName);
}

void FreeInstallManager::OnRemoveTimeoutTask(const Want &want)
{
    // only SA can call this interface
    TAG_LOGI(AAFwkTag::FREE_INSTALL, "OnRemoveTimeoutTask begin.");
    auto isSaCall = AAFwk::PermissionVerification::GetInstance()->IsSACall();
    if (!isSaCall) {
        TAG_LOGE(AAFwkTag::FREE_INSTALL, "Permission verification failed.");
        return;
    }
    std::string bundleName = want.GetElement().GetBundleName();
    std::string abilityName = want.GetElement().GetAbilityName();
    std::string startTime = want.GetStringParam(Want::PARAM_RESV_START_TIME);
    if (bundleName.empty() || abilityName.empty()) {
        TAG_LOGE(AAFwkTag::FREE_INSTALL, "wantBundleName or wantAbilityName is empty");
        return;
    }
    RemoveTimeoutTask(bundleName, abilityName, startTime);
}

void FreeInstallManager::RemoveFreeInstallInfo(const std::string &bundleName, const std::string &abilityName,
    const std::string &startTime)
{
    std::lock_guard<ffrt::mutex> lock(freeInstallListLock_);
    for (auto it = freeInstallList_.begin(); it != freeInstallList_.end();) {
        if ((*it).want.GetElement().GetBundleName() == bundleName &&
            (*it).want.GetElement().GetAbilityName() == abilityName &&
            (*it).want.GetStringParam(Want::PARAM_RESV_START_TIME) == startTime) {
            it = freeInstallList_.erase(it);
        } else {
            it++;
        }
    }
}
}  // namespace AAFwk
}  // namespace OHOS
