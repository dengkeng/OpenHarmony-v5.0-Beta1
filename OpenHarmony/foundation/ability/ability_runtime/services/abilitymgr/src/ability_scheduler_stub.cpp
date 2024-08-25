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

#include "ability_scheduler_stub.h"

#include "abs_shared_result_set.h"
#include "data_ability_observer_interface.h"
#include "data_ability_operation.h"
#include "data_ability_predicates.h"
#include "data_ability_result.h"
#include "hilog_tag_wrapper.h"
#include "hilog_wrapper.h"
#include "ipc_types.h"
#include "ishared_result_set.h"
#include "pac_map.h"
#include "session_info.h"
#include "values_bucket.h"
#include "want.h"

namespace OHOS {
namespace AAFwk {
constexpr int CYCLE_LIMIT = 2000;
AbilitySchedulerStub::AbilitySchedulerStub()
{
    requestFuncMap_[SCHEDULE_ABILITY_TRANSACTION] = &AbilitySchedulerStub::AbilityTransactionInner;
    requestFuncMap_[SEND_RESULT] = &AbilitySchedulerStub::SendResultInner;
    requestFuncMap_[SCHEDULE_ABILITY_CONNECT] = &AbilitySchedulerStub::ConnectAbilityInner;
    requestFuncMap_[SCHEDULE_ABILITY_DISCONNECT] = &AbilitySchedulerStub::DisconnectAbilityInner;
    requestFuncMap_[SCHEDULE_ABILITY_COMMAND] = &AbilitySchedulerStub::CommandAbilityInner;
    requestFuncMap_[SCHEDULE_ABILITY_PREPARE_TERMINATE] = &AbilitySchedulerStub::PrepareTerminateAbilityInner;
    requestFuncMap_[SCHEDULE_ABILITY_COMMAND_WINDOW] = &AbilitySchedulerStub::CommandAbilityWindowInner;
    requestFuncMap_[SCHEDULE_SAVE_ABILITY_STATE] = &AbilitySchedulerStub::SaveAbilityStateInner;
    requestFuncMap_[SCHEDULE_RESTORE_ABILITY_STATE] = &AbilitySchedulerStub::RestoreAbilityStateInner;
    requestFuncMap_[SCHEDULE_GETFILETYPES] = &AbilitySchedulerStub::GetFileTypesInner;
    requestFuncMap_[SCHEDULE_OPENFILE] = &AbilitySchedulerStub::OpenFileInner;
    requestFuncMap_[SCHEDULE_OPENRAWFILE] = &AbilitySchedulerStub::OpenRawFileInner;
    requestFuncMap_[SCHEDULE_INSERT] = &AbilitySchedulerStub::InsertInner;
    requestFuncMap_[SCHEDULE_UPDATE] = &AbilitySchedulerStub::UpdatetInner;
    requestFuncMap_[SCHEDULE_DELETE] = &AbilitySchedulerStub::DeleteInner;
    requestFuncMap_[SCHEDULE_QUERY] = &AbilitySchedulerStub::QueryInner;
    requestFuncMap_[SCHEDULE_CALL] = &AbilitySchedulerStub::CallInner;
    requestFuncMap_[SCHEDULE_GETTYPE] = &AbilitySchedulerStub::GetTypeInner;
    requestFuncMap_[SCHEDULE_RELOAD] = &AbilitySchedulerStub::ReloadInner;
    requestFuncMap_[SCHEDULE_BATCHINSERT] = &AbilitySchedulerStub::BatchInsertInner;
    requestFuncMap_[SCHEDULE_REGISTEROBSERVER] = &AbilitySchedulerStub::RegisterObserverInner;
    requestFuncMap_[SCHEDULE_UNREGISTEROBSERVER] = &AbilitySchedulerStub::UnregisterObserverInner;
    requestFuncMap_[SCHEDULE_NOTIFYCHANGE] = &AbilitySchedulerStub::NotifyChangeInner;
    requestFuncMap_[SCHEDULE_NORMALIZEURI] = &AbilitySchedulerStub::NormalizeUriInner;
    requestFuncMap_[SCHEDULE_DENORMALIZEURI] = &AbilitySchedulerStub::DenormalizeUriInner;
    requestFuncMap_[SCHEDULE_EXECUTEBATCH] = &AbilitySchedulerStub::ExecuteBatchInner;
    requestFuncMap_[NOTIFY_CONTINUATION_RESULT] = &AbilitySchedulerStub::NotifyContinuationResultInner;
    requestFuncMap_[REQUEST_CALL_REMOTE] = &AbilitySchedulerStub::CallRequestInner;
    requestFuncMap_[CONTINUE_ABILITY] = &AbilitySchedulerStub::ContinueAbilityInner;
    requestFuncMap_[DUMP_ABILITY_RUNNER_INNER] = &AbilitySchedulerStub::DumpAbilityInfoInner;
    requestFuncMap_[SCHEDULE_SHARE_DATA] = &AbilitySchedulerStub::ShareDataInner;
    requestFuncMap_[SCHEDULE_ONEXECUTE_INTENT] = &AbilitySchedulerStub::OnExecuteIntentInner;
    requestFuncMap_[CREATE_MODAL_UI_EXTENSION] = &AbilitySchedulerStub::CreateModalUIExtensionInner;
    requestFuncMap_[UPDATE_SESSION_TOKEN] = &AbilitySchedulerStub::UpdateSessionTokenInner;
    
#ifdef ABILITY_COMMAND_FOR_TEST
    requestFuncMap_[BLOCK_ABILITY_INNER] = &AbilitySchedulerStub::BlockAbilityInner;
#endif
}

AbilitySchedulerStub::~AbilitySchedulerStub()
{
    requestFuncMap_.clear();
}

int AbilitySchedulerStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    std::u16string descriptor = AbilitySchedulerStub::GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (descriptor != remoteDescriptor) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "local descriptor is not equal to remote");
        return ERR_INVALID_STATE;
    }

    auto itFunc = requestFuncMap_.find(code);
    if (itFunc != requestFuncMap_.end()) {
        auto requestFunc = itFunc->second;
        if (requestFunc != nullptr) {
            return (this->*requestFunc)(data, reply);
        }
    }
    TAG_LOGW(AAFwkTag::ABILITYMGR, "AbilitySchedulerStub::OnRemoteRequest, default case, need check.");
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

int AbilitySchedulerStub::AbilityTransactionInner(MessageParcel &data, MessageParcel &reply)
{
    std::shared_ptr<Want> want(data.ReadParcelable<Want>());
    if (want == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "AbilitySchedulerStub want is nullptr");
        return ERR_INVALID_VALUE;
    }
    std::unique_ptr<LifeCycleStateInfo> stateInfo(data.ReadParcelable<LifeCycleStateInfo>());
    if (!stateInfo) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "ReadParcelable<LifeCycleStateInfo> failed");
        return ERR_INVALID_VALUE;
    }
    sptr<SessionInfo> sessionInfo = nullptr;
    if (data.ReadBool()) {
        sessionInfo = data.ReadParcelable<SessionInfo>();
    }
    ScheduleAbilityTransaction(*want, *stateInfo, sessionInfo);
    return NO_ERROR;
}

int AbilitySchedulerStub::ShareDataInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t requestCode = data.ReadInt32();
    TAG_LOGI(AAFwkTag::ABILITYMGR, "requestCode:%{public}d.", requestCode);
    ScheduleShareData(requestCode);
    return NO_ERROR;
}

int AbilitySchedulerStub::SendResultInner(MessageParcel &data, MessageParcel &reply)
{
    int requestCode = data.ReadInt32();
    int resultCode = data.ReadInt32();
    std::shared_ptr<Want> want(data.ReadParcelable<Want>());
    if (want == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "AbilitySchedulerStub want is nullptr");
        return ERR_INVALID_VALUE;
    }
    SendResult(requestCode, resultCode, *want);
    return NO_ERROR;
}

int AbilitySchedulerStub::ConnectAbilityInner(MessageParcel &data, MessageParcel &reply)
{
    std::shared_ptr<Want> want(data.ReadParcelable<Want>());
    if (want == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "AbilitySchedulerStub want is nullptr");
        return ERR_INVALID_VALUE;
    }
    ScheduleConnectAbility(*want);
    return NO_ERROR;
}

int AbilitySchedulerStub::DisconnectAbilityInner(MessageParcel &data, MessageParcel &reply)
{
    std::shared_ptr<Want> want(data.ReadParcelable<Want>());
    if (want == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "AbilitySchedulerStub want is nullptr");
        return ERR_INVALID_VALUE;
    }
    ScheduleDisconnectAbility(*want);
    return NO_ERROR;
}

int AbilitySchedulerStub::CommandAbilityInner(MessageParcel &data, MessageParcel &reply)
{
    std::shared_ptr<Want> want(data.ReadParcelable<Want>());
    if (want == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "AbilitySchedulerStub want is nullptr");
        return ERR_INVALID_VALUE;
    }
    bool reStart = data.ReadBool();
    int startId = data.ReadInt32();
    TAG_LOGD(AAFwkTag::ABILITYMGR, "ReadInt32, startId:%{public}d", startId);
    ScheduleCommandAbility(*want, reStart, startId);
    return NO_ERROR;
}

int AbilitySchedulerStub::PrepareTerminateAbilityInner(MessageParcel &data, MessageParcel &reply)
{
    bool ret = SchedulePrepareTerminateAbility();
    if (!reply.WriteInt32(ret)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "fail to write ret");
        return ERR_INVALID_VALUE;
    }
    return NO_ERROR;
}

int AbilitySchedulerStub::CommandAbilityWindowInner(MessageParcel &data, MessageParcel &reply)
{
    std::shared_ptr<Want> want(data.ReadParcelable<Want>());
    if (want == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "want is nullptr");
        return ERR_INVALID_VALUE;
    }
    sptr<SessionInfo> sessionInfo(data.ReadParcelable<SessionInfo>());
    int32_t winCmd = data.ReadInt32();
    ScheduleCommandAbilityWindow(*want, sessionInfo, static_cast<WindowCommand>(winCmd));
    return NO_ERROR;
}

int AbilitySchedulerStub::SaveAbilityStateInner(MessageParcel &data, MessageParcel &reply)
{
    ScheduleSaveAbilityState();
    return NO_ERROR;
}

int AbilitySchedulerStub::RestoreAbilityStateInner(MessageParcel &data, MessageParcel &reply)
{
    std::shared_ptr<PacMap> pacMap(data.ReadParcelable<PacMap>());
    if (pacMap == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "AbilitySchedulerStub RestoreAbilityState is nullptr");
        return ERR_INVALID_VALUE;
    }
    ScheduleRestoreAbilityState(*pacMap);
    return NO_ERROR;
}

int AbilitySchedulerStub::GetFileTypesInner(MessageParcel &data, MessageParcel &reply)
{
    std::shared_ptr<Uri> uri(data.ReadParcelable<Uri>());
    if (uri == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "AbilitySchedulerStub uri is nullptr");
        return ERR_INVALID_VALUE;
    }
    std::string mimeTypeFilter = data.ReadString();
    if (mimeTypeFilter.empty()) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "AbilitySchedulerStub mimeTypeFilter is nullptr");
        return ERR_INVALID_VALUE;
    }
    std::vector<std::string> types = GetFileTypes(*uri, mimeTypeFilter);
    if (!reply.WriteStringVector(types)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "fail to WriteStringVector types");
        return ERR_INVALID_VALUE;
    }
    return NO_ERROR;
}

int AbilitySchedulerStub::OpenFileInner(MessageParcel &data, MessageParcel &reply)
{
    std::shared_ptr<Uri> uri(data.ReadParcelable<Uri>());
    if (uri == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "AbilitySchedulerStub uri is nullptr");
        return ERR_INVALID_VALUE;
    }
    std::string mode = data.ReadString();
    if (mode.empty()) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "AbilitySchedulerStub mode is nullptr");
        return ERR_INVALID_VALUE;
    }
    int fd = OpenFile(*uri, mode);
    if (fd < 0) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "OpenFile fail, fd is %{pubilc}d", fd);
        return ERR_INVALID_VALUE;
    }
    if (!reply.WriteFileDescriptor(fd)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "fail to WriteFileDescriptor fd");
        return ERR_INVALID_VALUE;
    }
    return NO_ERROR;
}

int AbilitySchedulerStub::OpenRawFileInner(MessageParcel &data, MessageParcel &reply)
{
    std::shared_ptr<Uri> uri(data.ReadParcelable<Uri>());
    if (uri == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "AbilitySchedulerStub uri is nullptr");
        return ERR_INVALID_VALUE;
    }
    std::string mode = data.ReadString();
    if (mode.empty()) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "AbilitySchedulerStub mode is nullptr");
        return ERR_INVALID_VALUE;
    }
    int fd = OpenRawFile(*uri, mode);
    if (!reply.WriteInt32(fd)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "fail to WriteInt32 fd");
        return ERR_INVALID_VALUE;
    }
    return NO_ERROR;
}

int AbilitySchedulerStub::InsertInner(MessageParcel &data, MessageParcel &reply)
{
    std::shared_ptr<Uri> uri(data.ReadParcelable<Uri>());
    if (uri == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "AbilitySchedulerStub uri is nullptr");
        return ERR_INVALID_VALUE;
    }
    int index = Insert(*uri, NativeRdb::ValuesBucket::Unmarshalling(data));
    if (!reply.WriteInt32(index)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "fail to WriteInt32 index");
        return ERR_INVALID_VALUE;
    }
    TAG_LOGI(AAFwkTag::ABILITYMGR, "AbilitySchedulerStub::InsertInner end");
    return NO_ERROR;
}

int AbilitySchedulerStub::CallInner(MessageParcel &data, MessageParcel &reply)
{
    std::shared_ptr<Uri> uri(data.ReadParcelable<Uri>());
    if (uri == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "AbilitySchedulerStub uri is nullptr");
        return ERR_INVALID_VALUE;
    }
    std::string method = data.ReadString();
    if (method.empty()) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "ReadParcelable method is nullptr");
        return ERR_INVALID_VALUE;
    }
    std::string arg = data.ReadString();
    if (arg.empty()) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "ReadParcelable arg is nullptr");
        return ERR_INVALID_VALUE;
    }

    std::shared_ptr<AppExecFwk::PacMap> pacMap(data.ReadParcelable<AppExecFwk::PacMap>());
    if (pacMap == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "ReadParcelable pacMap is nullptr");
        return ERR_INVALID_VALUE;
    }
    std::shared_ptr<AppExecFwk::PacMap> result = Call(*uri, method, arg, *pacMap);
    if (!reply.WriteParcelable(result.get())) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "fail to WriteParcelable pacMap error");
        return ERR_INVALID_VALUE;
    }
    TAG_LOGI(AAFwkTag::ABILITYMGR, "AbilitySchedulerStub::CallInner end");
    return NO_ERROR;
}

int AbilitySchedulerStub::UpdatetInner(MessageParcel &data, MessageParcel &reply)
{
    std::shared_ptr<Uri> uri(data.ReadParcelable<Uri>());
    if (uri == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "AbilitySchedulerStub uri is nullptr");
        return ERR_INVALID_VALUE;
    }
    auto value = NativeRdb::ValuesBucket::Unmarshalling(data);
    std::shared_ptr<NativeRdb::DataAbilityPredicates> predicates(
        data.ReadParcelable<NativeRdb::DataAbilityPredicates>());
    if (predicates == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "ReadParcelable predicates is nullptr");
        return ERR_INVALID_VALUE;
    }
    int index = Update(*uri, std::move(value), *predicates);
    if (!reply.WriteInt32(index)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "fail to WriteInt32 index");
        return ERR_INVALID_VALUE;
    }
    return NO_ERROR;
}

int AbilitySchedulerStub::DeleteInner(MessageParcel &data, MessageParcel &reply)
{
    std::shared_ptr<Uri> uri(data.ReadParcelable<Uri>());
    if (uri == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "AbilitySchedulerStub uri is nullptr");
        return ERR_INVALID_VALUE;
    }
    std::shared_ptr<NativeRdb::DataAbilityPredicates> predicates(
        data.ReadParcelable<NativeRdb::DataAbilityPredicates>());
    if (predicates == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "ReadParcelable predicates is nullptr");
        return ERR_INVALID_VALUE;
    }
    int index = Delete(*uri, *predicates);
    if (!reply.WriteInt32(index)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "fail to WriteInt32 index");
        return ERR_INVALID_VALUE;
    }
    return NO_ERROR;
}

int AbilitySchedulerStub::QueryInner(MessageParcel &data, MessageParcel &reply)
{
    std::shared_ptr<Uri> uri(data.ReadParcelable<Uri>());
    if (uri == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "AbilitySchedulerStub uri is nullptr");
        return ERR_INVALID_VALUE;
    }
    std::vector<std::string> columns;
    if (!data.ReadStringVector(&columns)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "fail to ReadStringVector columns");
        return ERR_INVALID_VALUE;
    }
    std::shared_ptr<NativeRdb::DataAbilityPredicates> predicates(
        data.ReadParcelable<NativeRdb::DataAbilityPredicates>());
    if (predicates == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "ReadParcelable predicates is nullptr");
        return ERR_INVALID_VALUE;
    }
    auto resultSet = Query(*uri, columns, *predicates);
    if (resultSet == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "fail to WriteParcelable resultSet");
        return ERR_INVALID_VALUE;
    }
    auto result = NativeRdb::ISharedResultSet::WriteToParcel(std::move(resultSet), reply);
    if (result == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "!resultSet->Marshalling(reply)");
        return ERR_INVALID_VALUE;
    }
    TAG_LOGI(AAFwkTag::ABILITYMGR, "AbilitySchedulerStub::QueryInner end");
    return NO_ERROR;
}

int AbilitySchedulerStub::GetTypeInner(MessageParcel &data, MessageParcel &reply)
{
    std::shared_ptr<Uri> uri(data.ReadParcelable<Uri>());
    if (uri == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "AbilitySchedulerStub uri is nullptr");
        return ERR_INVALID_VALUE;
    }
    std::string type = GetType(*uri);
    if (!reply.WriteString(type)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "fail to WriteString type");
        return ERR_INVALID_VALUE;
    }
    return NO_ERROR;
}

int AbilitySchedulerStub::ReloadInner(MessageParcel &data, MessageParcel &reply)
{
    std::shared_ptr<Uri> uri(data.ReadParcelable<Uri>());
    if (uri == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "AbilitySchedulerStub uri is nullptr");
        return ERR_INVALID_VALUE;
    }

    std::shared_ptr<PacMap> extras(data.ReadParcelable<PacMap>());
    if (extras == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "AbilitySchedulerStub extras is nullptr");
        return ERR_INVALID_VALUE;
    }
    bool ret = Reload(*uri, *extras);
    if (!reply.WriteBool(ret)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "fail to writeBool ret");
        return ERR_INVALID_VALUE;
    }
    return NO_ERROR;
}

int AbilitySchedulerStub::BatchInsertInner(MessageParcel &data, MessageParcel &reply)
{
    std::shared_ptr<Uri> uri(data.ReadParcelable<Uri>());
    if (uri == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "AbilitySchedulerStub uri is nullptr");
        return ERR_INVALID_VALUE;
    }

    int count = 0;
    if (!data.ReadInt32(count)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "fail to ReadInt32 index");
        return ERR_INVALID_VALUE;
    }

    if (count > CYCLE_LIMIT) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "count is too large");
        return ERR_INVALID_VALUE;
    }
    std::vector<NativeRdb::ValuesBucket> values;
    for (int i = 0; i < count; i++) {
        values.emplace_back(NativeRdb::ValuesBucket::Unmarshalling(data));
    }

    int ret = BatchInsert(*uri, values);
    if (!reply.WriteInt32(ret)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "fail to WriteInt32 ret");
        return ERR_INVALID_VALUE;
    }
    return NO_ERROR;
}

int AbilitySchedulerStub::RegisterObserverInner(MessageParcel &data, MessageParcel &reply)
{
    std::shared_ptr<Uri> uri(data.ReadParcelable<Uri>());
    if (uri == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "AbilitySchedulerStub uri is nullptr");
        return ERR_INVALID_VALUE;
    }
    auto obServer = iface_cast<IDataAbilityObserver>(data.ReadRemoteObject());
    if (obServer == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "AbilitySchedulerStub obServer is nullptr");
        return ERR_INVALID_VALUE;
    }

    bool ret = ScheduleRegisterObserver(*uri, obServer);
    if (!reply.WriteInt32(ret)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "fail to WriteInt32 ret");
        return ERR_INVALID_VALUE;
    }
    return NO_ERROR;
}

int AbilitySchedulerStub::UnregisterObserverInner(MessageParcel &data, MessageParcel &reply)
{
    std::shared_ptr<Uri> uri(data.ReadParcelable<Uri>());
    if (uri == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "AbilitySchedulerStub uri is nullptr");
        return ERR_INVALID_VALUE;
    }
    auto obServer = iface_cast<IDataAbilityObserver>(data.ReadRemoteObject());
    if (obServer == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "AbilitySchedulerStub obServer is nullptr");
        return ERR_INVALID_VALUE;
    }

    bool ret = ScheduleUnregisterObserver(*uri, obServer);
    if (!reply.WriteInt32(ret)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "fail to WriteInt32 ret");
        return ERR_INVALID_VALUE;
    }
    return NO_ERROR;
}

int AbilitySchedulerStub::NotifyChangeInner(MessageParcel &data, MessageParcel &reply)
{
    std::shared_ptr<Uri> uri(data.ReadParcelable<Uri>());
    if (uri == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "AbilitySchedulerStub uri is nullptr");
        return ERR_INVALID_VALUE;
    }

    bool ret = ScheduleNotifyChange(*uri);
    if (!reply.WriteInt32(ret)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "fail to WriteInt32 ret");
        return ERR_INVALID_VALUE;
    }
    return NO_ERROR;
}

int AbilitySchedulerStub::NormalizeUriInner(MessageParcel &data, MessageParcel &reply)
{
    std::shared_ptr<Uri> uri(data.ReadParcelable<Uri>());
    if (uri == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "AbilitySchedulerStub uri is nullptr");
        return ERR_INVALID_VALUE;
    }

    Uri ret("");
    ret = NormalizeUri(*uri);
    if (!reply.WriteParcelable(&ret)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "fail to WriteParcelable type");
        return ERR_INVALID_VALUE;
    }
    return NO_ERROR;
}

int AbilitySchedulerStub::DenormalizeUriInner(MessageParcel &data, MessageParcel &reply)
{
    std::shared_ptr<Uri> uri(data.ReadParcelable<Uri>());
    if (uri == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "AbilitySchedulerStub uri is nullptr");
        return ERR_INVALID_VALUE;
    }

    Uri ret("");
    ret = DenormalizeUri(*uri);
    if (!reply.WriteParcelable(&ret)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "fail to WriteParcelable type");
        return ERR_INVALID_VALUE;
    }
    return NO_ERROR;
}

int AbilitySchedulerStub::ExecuteBatchInner(MessageParcel &data, MessageParcel &reply)
{
    TAG_LOGI(AAFwkTag::ABILITYMGR, "AbilitySchedulerStub::ExecuteBatchInner start");
    int count = 0;
    if (!data.ReadInt32(count)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "AbilitySchedulerStub::ExecuteBatchInner fail to ReadInt32 count");
        return ERR_INVALID_VALUE;
    }
    TAG_LOGI(AAFwkTag::ABILITYMGR, "AbilitySchedulerStub::ExecuteBatchInner count:%{public}d", count);
    if (count > CYCLE_LIMIT) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "count is too large");
        return ERR_INVALID_VALUE;
    }
    std::vector<std::shared_ptr<AppExecFwk::DataAbilityOperation>> operations;
    for (int i = 0; i < count; i++) {
        std::shared_ptr<AppExecFwk::DataAbilityOperation> dataAbilityOperation(
            data.ReadParcelable<AppExecFwk::DataAbilityOperation>());
        if (dataAbilityOperation == nullptr) {
            TAG_LOGE(AAFwkTag::ABILITYMGR, "AbilitySchedulerStub::ExecuteBatchInner dataAbilityOperation is nullptr, "
                "index = %{public}d", i);
            return ERR_INVALID_VALUE;
        }
        operations.push_back(dataAbilityOperation);
    }

    std::vector<std::shared_ptr<AppExecFwk::DataAbilityResult>> results = ExecuteBatch(operations);
    int total = (int)results.size();
    if (!reply.WriteInt32(total)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "AbilitySchedulerStub::ExecuteBatchInner fail to WriteInt32 ret");
        return ERR_INVALID_VALUE;
    }
    TAG_LOGI(AAFwkTag::ABILITYMGR, "AbilitySchedulerStub::ExecuteBatchInner total:%{public}d", total);
    for (int i = 0; i < total; i++) {
        if (results[i] == nullptr) {
            TAG_LOGE(AAFwkTag::ABILITYMGR,
                "AbilitySchedulerStub::ExecuteBatchInner results[i] is nullptr, index = %{public}d", i);
            return ERR_INVALID_VALUE;
        }
        if (!reply.WriteParcelable(results[i].get())) {
            TAG_LOGE(AAFwkTag::ABILITYMGR,
                "AbilitySchedulerStub::ExecuteBatchInner fail to WriteParcelable operation, index = %{public}d", i);
            return ERR_INVALID_VALUE;
        }
    }
    TAG_LOGI(AAFwkTag::ABILITYMGR, "AbilitySchedulerStub::ExecuteBatchInner end");
    return NO_ERROR;
}

int AbilitySchedulerStub::ContinueAbilityInner(MessageParcel &data, MessageParcel &reply)
{
    std::string deviceId = data.ReadString();
    uint32_t versionCode = data.ReadUint32();
    ContinueAbility(deviceId, versionCode);
    return NO_ERROR;
}

int AbilitySchedulerStub::NotifyContinuationResultInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t result = data.ReadInt32();
    NotifyContinuationResult(result);
    return NO_ERROR;
}

int AbilitySchedulerStub::DumpAbilityInfoInner(MessageParcel &data, MessageParcel &reply)
{
    std::vector<std::string> infos;
    std::vector<std::string> params;
    if (!data.ReadStringVector(&params)) {
        TAG_LOGI(AAFwkTag::ABILITYMGR, "DumpAbilityInfoInner read params error");
        return ERR_INVALID_VALUE;
    }

    DumpAbilityInfo(params, infos);

    return NO_ERROR;
}

int AbilitySchedulerStub::CallRequestInner(MessageParcel &data, MessageParcel &reply)
{
    CallRequest();
    return NO_ERROR;
}

int AbilitySchedulerStub::OnExecuteIntentInner(MessageParcel &data, MessageParcel &reply)
{
    TAG_LOGI(AAFwkTag::ABILITYMGR, "AbilitySchedulerStub::OnExecuteIntentInner start");
    std::shared_ptr<Want> want(data.ReadParcelable<Want>());
    if (want == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "AbilitySchedulerStub want is nullptr");
        return ERR_INVALID_VALUE;
    }
    OnExecuteIntent(*want);
    return NO_ERROR;
}

int AbilitySchedulerStub::CreateModalUIExtensionInner(MessageParcel &data, MessageParcel &reply)
{
    std::shared_ptr<Want> want(data.ReadParcelable<Want>());
    if (want == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "AbilitySchedulerStub want is nullptr");
        return ERR_INVALID_VALUE;
    }
    int ret = CreateModalUIExtension(*want);
    if (!reply.WriteInt32(ret)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "fail to WriteInt32 ret");
        return ERR_INVALID_VALUE;
    }
    return NO_ERROR;
}

int AbilitySchedulerStub::UpdateSessionTokenInner(MessageParcel &data, MessageParcel &reply)
{
    sptr<IRemoteObject> sessionToken = data.ReadRemoteObject();
    UpdateSessionToken(sessionToken);
    return NO_ERROR;
}

#ifdef ABILITY_COMMAND_FOR_TEST
int AbilitySchedulerStub::BlockAbilityInner(MessageParcel &data, MessageParcel &reply)
{
    TAG_LOGI(AAFwkTag::ABILITYMGR, "AbilitySchedulerStub::BlockAbilityInner start");

    auto result = BlockAbility();
    if (!reply.WriteInt32(result)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "fail to WriteInt32 result");
        return ERR_INVALID_VALUE;
    }
    return NO_ERROR;
}
#endif

void AbilitySchedulerRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    TAG_LOGE(AAFwkTag::ABILITYMGR, "recv AbilitySchedulerRecipient death notice");

    if (handler_) {
        handler_(remote);
    }
}

AbilitySchedulerRecipient::AbilitySchedulerRecipient(RemoteDiedHandler handler) : handler_(handler)
{}

AbilitySchedulerRecipient::~AbilitySchedulerRecipient()
{}
}  // namespace AAFwk
}  // namespace OHOS
