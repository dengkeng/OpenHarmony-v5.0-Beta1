/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "cellular_call_rdb_helper.h"

#include "telephony_errors.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
static constexpr const char *GLOBAL_ECC_URI_SELECTION =
    "datashare:///com.ohos.globalparamsability/globalparams/ecc_data";

CellularCallRdbHelper::CellularCallRdbHelper() : globalEccUri_(GLOBAL_ECC_URI_SELECTION) {}

CellularCallRdbHelper::~CellularCallRdbHelper() = default;

std::shared_ptr<DataShare::DataShareHelper> CellularCallRdbHelper::CreateDataAbilityHelper()
{
    TELEPHONY_LOGD("Create data ability helper");
    sptr<ISystemAbilityManager> saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saManager == nullptr) {
        TELEPHONY_LOGE("CellularCallRdbHelper GetSystemAbilityManager failed.");
        return nullptr;
    }
    sptr<IRemoteObject> remoteObj = saManager->GetSystemAbility(TELEPHONY_CELLULAR_CALL_SYS_ABILITY_ID);
    if (remoteObj == nullptr) {
        TELEPHONY_LOGE("CellularCallRdbHelper GetSystemAbility Service Failed.");
        return nullptr;
    }
    return DataShare::DataShareHelper::Creator(remoteObj, GLOBAL_PARAMS_URI);
}

int32_t CellularCallRdbHelper::QueryEccList(const std::string &numeric, std::vector<EccNum> &eccVec)
{
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataAbilityHelper();
    if (dataShareHelper == nullptr) {
        TELEPHONY_LOGE("dataShareHelper is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::vector<std::string> columns;
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(EccData::NUMERIC, numeric);
    std::shared_ptr<DataShare::DataShareResultSet> result =
        dataShareHelper->Query(globalEccUri_, predicates, columns);
    if (result == nullptr) {
        TELEPHONY_LOGE("CellularCallRdbHelper: query apns error");
        dataShareHelper->Release();
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    int rowCnt = 0;
    result->GetRowCount(rowCnt);
    TELEPHONY_LOGD("CellularCallRdbHelper::query ecc_data rowCnt = %{public}d", rowCnt);
    for (int32_t index = 0; index < rowCnt; index++) {
        EccNum bean;
        result->GoToRow(index);
        result->GetColumnIndex(EccData::ID, index);
        result->GetInt(index, bean.id);
        result->GetColumnIndex(EccData::NAME, index);
        result->GetString(index, bean.name);
        result->GetColumnIndex(EccData::MCC, index);
        result->GetString(index, bean.mcc);
        result->GetColumnIndex(EccData::MNC, index);
        result->GetString(index, bean.mnc);
        result->GetColumnIndex(EccData::NUMERIC, index);
        result->GetString(index, bean.numeric);
        result->GetColumnIndex(EccData::ECC_WITH_CARD, index);
        result->GetString(index, bean.ecc_withcard);
        result->GetColumnIndex(EccData::ECC_NO_CARD, index);
        result->GetString(index, bean.ecc_nocard);
        result->GetColumnIndex(EccData::ECC_FAKE, index);
        result->GetString(index, bean.ecc_fake);
        eccVec.push_back(bean);
    }
    result->Close();
    dataShareHelper->Release();
    dataShareHelper = nullptr;
    return TELEPHONY_SUCCESS;
}
} // namespace Telephony
} // namespace OHOS
