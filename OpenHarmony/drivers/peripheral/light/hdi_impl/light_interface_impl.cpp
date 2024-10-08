/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "light_interface_impl.h"
#include <hdf_base.h>
#include "light_uhdf_log.h"
#include "devhost_dump_reg.h"
#include "light_dump.h"
#include "light_if.h"

#define HDF_LOG_TAG     uhdf_light_service

namespace OHOS {
namespace HDI {
namespace Light {
namespace V1_0 {

int32_t LightInterfaceImpl::Init()
{
    const struct LightInterface *lightInterface = NewLightInterfaceInstance();
    if (lightInterface == nullptr || lightInterface->GetLightInfo == nullptr) {
        HDF_LOGE("%{public}s: get light Module instance failed", __func__);
        return HDF_FAILURE;
    }

    DevHostRegisterDumpHost(GetLightDump);

    return HDF_SUCCESS;
}

int32_t LightInterfaceImpl::GetLightInfo(std::vector<HdfLightInfoVdi>& info)
{
    const struct LightInterface *lightInterface = NewLightInterfaceInstance();
    if (lightInterface == nullptr || lightInterface->GetLightInfo == nullptr) {
        HDF_LOGE("%{public}s: get light Module instance failed", __func__);
        return HDF_FAILURE;
    }

    struct LightInfo *lightInfo = nullptr;
    uint32_t count = 0;
    int32_t ret = lightInterface->GetLightInfo(&lightInfo, &count);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed, error code is %{public}d", __func__, ret);
        return ret;
    }

    while (count--) {
        HdfLightInfoVdi hdfLightInfo;
        hdfLightInfo.lightId = static_cast<int32_t>(lightInfo->lightId);
        hdfLightInfo.lightType = lightInfo->lightType;
        if (strcpy_s(hdfLightInfo.lightName, LIGHT_NAME_MAX_LEN, lightInfo->lightName) != EOK) {
            HDF_LOGE("%{public}s: Light name cpy faild", __func__);
            return HDF_FAILURE;
        }
        hdfLightInfo.lightNumber = static_cast<int32_t>(lightInfo->lightNumber);
        info.push_back(hdfLightInfo);
        lightInfo++;
    }

    return HDF_SUCCESS;
}

int32_t LightInterfaceImpl::TurnOnLight(int32_t lightId, const HdfLightEffectVdi& effect)
{
    HDF_LOGI("%{public}s: Enter the TurnOnLight function, lightId is %{public}d", __func__, lightId);
    const struct LightInterface *lightInterface = NewLightInterfaceInstance();
    if (lightInterface == nullptr || lightInterface->TurnOnLight == nullptr) {
        HDF_LOGE("%{public}s: get light Module instance failed", __func__);
        return HDF_FAILURE;
    }

    LightEffect lightEffect;
    lightEffect.lightColor.colorValue.rgbColor.b = effect.lightColor.colorValue.rgbColor.b;
    lightEffect.lightColor.colorValue.rgbColor.g = effect.lightColor.colorValue.rgbColor.g;
    lightEffect.lightColor.colorValue.rgbColor.r = effect.lightColor.colorValue.rgbColor.r;
    lightEffect.lightColor.colorValue.wrgbColor.b = effect.lightColor.colorValue.wrgbColor.b;
    lightEffect.lightColor.colorValue.wrgbColor.g = effect.lightColor.colorValue.wrgbColor.g;
    lightEffect.lightColor.colorValue.wrgbColor.r = effect.lightColor.colorValue.wrgbColor.r;
    lightEffect.lightColor.colorValue.wrgbColor.w = effect.lightColor.colorValue.wrgbColor.w;
    lightEffect.flashEffect.flashMode = effect.flashEffect.flashMode;
    lightEffect.flashEffect.onTime = effect.flashEffect.onTime;
    lightEffect.flashEffect.offTime = effect.flashEffect.offTime;
    int32_t ret = lightInterface->TurnOnLight(lightId, &lightEffect);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed, error code is %{public}d", __func__, ret);
    }

    return ret;
}

int32_t LightInterfaceImpl::TurnOnMultiLights(int32_t lightId, const std::vector<HdfLightColorVdi>& colors)
{
    HDF_LOGI("%{public}s: Enter the TurnOnMultiLights function, lightId is %{public}d", __func__, lightId);
    const struct LightInterface *lightInterface = NewLightInterfaceInstance();
    if (lightInterface == nullptr || lightInterface->TurnOnMultiLights == nullptr) {
        HDF_LOGE("%{public}s: get light module instance failed", __func__);
        return HDF_FAILURE;
    }

    uint32_t num = colors.size();
    LightColor lightColor[num];
    int32_t i = 0;
    for (auto iter : colors) {
        lightColor[i].colorValue.rgbColor.b = iter.colorValue.rgbColor.b;
        lightColor[i].colorValue.rgbColor.g = iter.colorValue.rgbColor.g;
        lightColor[i].colorValue.rgbColor.r = iter.colorValue.rgbColor.r;
        lightColor[i].colorValue.wrgbColor.b = iter.colorValue.wrgbColor.b;
        lightColor[i].colorValue.wrgbColor.g = iter.colorValue.wrgbColor.g;
        lightColor[i].colorValue.wrgbColor.r = iter.colorValue.wrgbColor.r;
        lightColor[i++].colorValue.wrgbColor.w = iter.colorValue.wrgbColor.w;
    }

    int32_t ret = lightInterface->TurnOnMultiLights(lightId, lightColor, num);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed, error code is %{public}d", __func__, ret);
    }

    return ret;
}

int32_t LightInterfaceImpl::TurnOffLight(int32_t lightId)
{
    HDF_LOGI("%{public}s: Enter the TurnOffLight function, lightId is %{public}d", __func__, lightId);
    const struct LightInterface *lightInterface = NewLightInterfaceInstance();
    if (lightInterface == nullptr || lightInterface->TurnOffLight == nullptr) {
        HDF_LOGE("%{public}s: get light Module instance failed", __func__);
        return HDF_FAILURE;
    }
    int32_t ret = lightInterface->TurnOffLight(lightId);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed, error code is %{public}d", __func__, ret);
    }

    return ret;
}

static int32_t CreateLightVdiInstance(struct HdfVdiBase *vdiBase)
{
    HDF_LOGI("%{public}s: Enter the CreateLightVdiInstance function", __func__);
    if (vdiBase == nullptr) {
        HDF_LOGE("%{public}s parameter vdiBase is NULL", __func__);
        return HDF_FAILURE;
    }

    struct VdiWrapperLight *lightVdi = reinterpret_cast<VdiWrapperLight *>(vdiBase);
    lightVdi->lightModule = new LightInterfaceImpl();
    if (lightVdi->lightModule == nullptr) {
        HDF_LOGI("%{public}s: new lightModule failed!", __func__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t DestoryLightVdiInstance(struct HdfVdiBase *vdiBase)
{
    HDF_LOGI("%{public}s: Enter the DestoryLightVdiInstance function", __func__);
    if (vdiBase == nullptr) {
        HDF_LOGE("%{public}s parameter vdiBase is NULL", __func__);
        return HDF_FAILURE;
    }

    struct VdiWrapperLight *lightVdi = reinterpret_cast<VdiWrapperLight *>(vdiBase);
    LightInterfaceImpl *lightImpl = reinterpret_cast<LightInterfaceImpl *>(lightVdi->lightModule);
    if (lightImpl != nullptr) {
        delete lightImpl;
        lightVdi->lightModule = nullptr;
    }
    return HDF_SUCCESS;
}

static struct VdiWrapperLight g_lightVdi = {
    .base = {
        .moduleVersion = 1,
        .moduleName = "light_service",
        .CreateVdiInstance = CreateLightVdiInstance,
        .DestoryVdiInstance = DestoryLightVdiInstance,
    },
    .lightModule = nullptr,
};

extern "C" HDF_VDI_INIT(g_lightVdi);
} // V1_0
} // Light
} // HDI
} // OHOS
