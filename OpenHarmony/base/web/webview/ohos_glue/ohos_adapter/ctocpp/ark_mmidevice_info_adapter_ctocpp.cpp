/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "ohos_adapter/ctocpp/ark_mmidevice_info_adapter_ctocpp.h"

#include "base/ctocpp/ark_web_ctocpp_macros.h"

namespace OHOS::ArkWeb {

ARK_WEB_NO_SANITIZE
int32_t ArkMMIDeviceInfoAdapterCToCpp::GetId()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_mmidevice_info_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_id, 0);

    // Execute
    return _struct->get_id(_struct);
}

ARK_WEB_NO_SANITIZE
int32_t ArkMMIDeviceInfoAdapterCToCpp::GetType()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_mmidevice_info_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_type, 0);

    // Execute
    return _struct->get_type(_struct);
}

ARK_WEB_NO_SANITIZE
int32_t ArkMMIDeviceInfoAdapterCToCpp::GetBus()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_mmidevice_info_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_bus, 0);

    // Execute
    return _struct->get_bus(_struct);
}

ARK_WEB_NO_SANITIZE
int32_t ArkMMIDeviceInfoAdapterCToCpp::GetVersion()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_mmidevice_info_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_version, 0);

    // Execute
    return _struct->get_version(_struct);
}

ARK_WEB_NO_SANITIZE
int32_t ArkMMIDeviceInfoAdapterCToCpp::GetProduct()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_mmidevice_info_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_product, 0);

    // Execute
    return _struct->get_product(_struct);
}

ARK_WEB_NO_SANITIZE
int32_t ArkMMIDeviceInfoAdapterCToCpp::GetVendor()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_mmidevice_info_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_vendor, 0);

    // Execute
    return _struct->get_vendor(_struct);
}

ARK_WEB_NO_SANITIZE
ArkWebString ArkMMIDeviceInfoAdapterCToCpp::GetName()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_mmidevice_info_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_string_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_name, ark_web_string_default);

    // Execute
    return _struct->get_name(_struct);
}

ARK_WEB_NO_SANITIZE
ArkWebString ArkMMIDeviceInfoAdapterCToCpp::GetPhys()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_mmidevice_info_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_string_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_phys, ark_web_string_default);

    // Execute
    return _struct->get_phys(_struct);
}

ARK_WEB_NO_SANITIZE
ArkWebString ArkMMIDeviceInfoAdapterCToCpp::GetUniq()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_mmidevice_info_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_string_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_uniq, ark_web_string_default);

    // Execute
    return _struct->get_uniq(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkMMIDeviceInfoAdapterCToCpp::SetId(int32_t id)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_mmidevice_info_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, set_id, );

    // Execute
    _struct->set_id(_struct, id);
}

ARK_WEB_NO_SANITIZE
void ArkMMIDeviceInfoAdapterCToCpp::SetType(int32_t type)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_mmidevice_info_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, set_type, );

    // Execute
    _struct->set_type(_struct, type);
}

ARK_WEB_NO_SANITIZE
void ArkMMIDeviceInfoAdapterCToCpp::SetBus(int32_t bus)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_mmidevice_info_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, set_bus, );

    // Execute
    _struct->set_bus(_struct, bus);
}

ARK_WEB_NO_SANITIZE
void ArkMMIDeviceInfoAdapterCToCpp::SetVersion(int32_t version)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_mmidevice_info_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, set_version, );

    // Execute
    _struct->set_version(_struct, version);
}

ARK_WEB_NO_SANITIZE
void ArkMMIDeviceInfoAdapterCToCpp::SetProduct(int32_t product)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_mmidevice_info_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, set_product, );

    // Execute
    _struct->set_product(_struct, product);
}

ARK_WEB_NO_SANITIZE
void ArkMMIDeviceInfoAdapterCToCpp::SetVendor(int32_t vendor)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_mmidevice_info_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, set_vendor, );

    // Execute
    _struct->set_vendor(_struct, vendor);
}

ARK_WEB_NO_SANITIZE
void ArkMMIDeviceInfoAdapterCToCpp::SetName(ArkWebString name)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_mmidevice_info_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, set_name, );

    // Execute
    _struct->set_name(_struct, name);
}

ARK_WEB_NO_SANITIZE
void ArkMMIDeviceInfoAdapterCToCpp::SetPhys(ArkWebString phys)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_mmidevice_info_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, set_phys, );

    // Execute
    _struct->set_phys(_struct, phys);
}

ARK_WEB_NO_SANITIZE
void ArkMMIDeviceInfoAdapterCToCpp::SetUniq(ArkWebString uniq)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_mmidevice_info_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, set_uniq, );

    // Execute
    _struct->set_uniq(_struct, uniq);
}

ArkMMIDeviceInfoAdapterCToCpp::ArkMMIDeviceInfoAdapterCToCpp() {}

ArkMMIDeviceInfoAdapterCToCpp::~ArkMMIDeviceInfoAdapterCToCpp() {}

template<>
ArkWebBridgeType ArkWebCToCppRefCounted<ArkMMIDeviceInfoAdapterCToCpp, ArkMMIDeviceInfoAdapter,
    ark_mmidevice_info_adapter_t>::kBridgeType = ARK_MMIDEVICE_INFO_ADAPTER;

} // namespace OHOS::ArkWeb
