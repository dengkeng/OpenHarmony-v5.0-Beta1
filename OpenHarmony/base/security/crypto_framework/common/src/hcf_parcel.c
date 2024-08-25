/*
* Copyright (C) 2021 Huawei Device Co., Ltd.
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#include "hcf_parcel.h"
#include "securec.h"
#include "memory.h"

const int PARCEL_DEFAULT_INCREASE_STEP = 16;
const uint32_t PARCEL_UINT_MAX = 0xffffffffU;
const int HALF_LEN = 2;

HcParcel CreateParcel(uint32_t size, uint32_t allocUnit)
{
    HcParcel parcel;
    (void)memset_s(&parcel, sizeof(parcel), 0, sizeof(parcel));
    parcel.allocUnit = allocUnit;
    if (parcel.allocUnit == 0) {
        parcel.allocUnit = PARCEL_DEFAULT_INCREASE_STEP;
    }
    if (size > 0) {
        parcel.data = (char *)HcfMalloc(size, 0);
        if (parcel.data != NULL) {
            parcel.length = size;
        }
    }
    return parcel;
}

void DeleteParcel(HcParcel *parcel)
{
    if (parcel == NULL) {
        return;
    }

    if (parcel->data != NULL) {
        HcfFree(parcel->data);
        parcel->data = 0;
    }
    parcel->length = 0;
    parcel->beginPos = 0;
    parcel->endPos = 0;
}

uint32_t GetParcelDataSize(const HcParcel *parcel)
{
    if (parcel == NULL) {
        return 0;
    }
    if (parcel->endPos >= parcel->beginPos) {
        return parcel->endPos - parcel->beginPos;
    }
    return 0;
}

const char *GetParcelData(const HcParcel *parcel)
{
    if (parcel == NULL) {
        return NULL;
    }
    return parcel->data + parcel->beginPos;
}

static bool ParcelRealloc(HcParcel *parcel, uint32_t size)
{
    if (parcel->length >= size) {
        return false;
    }
    char *newData = (char *)HcfMalloc(size, 0);
    if (newData == NULL) {
        return false;
    }
    if (memcpy_s(newData, size, parcel->data, parcel->length) != EOK) {
        HcfFree(newData);
        return false;
    }
    HcfFree(parcel->data);
    parcel->data = newData;
    parcel->length = size;
    return true;
}

static bool ParcelIncrease(HcParcel *parcel, uint32_t size)
{
    if (parcel == NULL || size == 0) {
        return false;
    }
    if (parcel->data == NULL) {
        if (parcel->length != 0) {
            return false;
        }
        *parcel = CreateParcel(size, parcel->allocUnit);
        if (parcel->data == NULL) {
            return false;
        } else {
            return true;
        }
    } else {
        return ParcelRealloc(parcel, size);
    }
}

static void ParcelRecycle(HcParcel *parcel)
{
    if (parcel == NULL) {
        return;
    }
    if (parcel->data == NULL || parcel->beginPos < parcel->allocUnit) {
        return;
    }

    uint32_t contentSize = parcel->endPos - parcel->beginPos;
    if (contentSize > 0) {
        if (memmove_s(parcel->data, parcel->endPos - parcel->beginPos,
            parcel->data + parcel->beginPos, parcel->endPos - parcel->beginPos) != EOK) {
        }
    }
    parcel->beginPos = 0;
    parcel->endPos = contentSize;
}

static uint32_t GetParcelIncreaseSize(HcParcel *parcel, uint32_t newSize)
{
    if (parcel == NULL || parcel->allocUnit == 0) {
        return 0;
    }
    if (newSize % parcel->allocUnit) {
        return (newSize / parcel->allocUnit + 1) * parcel->allocUnit;
    } else {
        return (newSize / parcel->allocUnit) * parcel->allocUnit;
    }
}

bool ParcelWrite(HcParcel *parcel, const void *src, uint32_t dataSize)
{
    errno_t rc;
    if (parcel == NULL || src == NULL || dataSize == 0) {
        return false;
    }
    if (parcel->endPos > PARCEL_UINT_MAX - dataSize) {
        return false;
    }
    if (parcel->endPos + dataSize > parcel->length) {
        ParcelRecycle(parcel);
        if (parcel->endPos + dataSize > parcel->length) {
            uint32_t newSize = GetParcelIncreaseSize(parcel, parcel->endPos + dataSize);
            if (!ParcelIncrease(parcel, newSize)) {
                return false;
            }
        }
    }
    rc = memmove_s(parcel->data + parcel->endPos, dataSize, src, dataSize);
    if (rc != EOK) {
        return false;
    }
    parcel->endPos += dataSize;
    return true;
}

bool ParcelWriteInt8(HcParcel *parcel, char src)
{
    return ParcelWrite(parcel, &src, sizeof(src));
}

bool ParcelPopBack(HcParcel *parcel, uint32_t size)
{
    if (parcel != NULL && size > 0 && GetParcelDataSize(parcel) >= size) {
        parcel->endPos -= size;
        return true;
    }
    return false;
}
