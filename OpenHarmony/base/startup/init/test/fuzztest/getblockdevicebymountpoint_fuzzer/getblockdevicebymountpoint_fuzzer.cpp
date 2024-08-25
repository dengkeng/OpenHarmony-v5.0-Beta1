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

#include "getblockdevicebymountpoint_fuzzer.h"
#include <iostream>
#include "fs_manager/fs_manager.h"

namespace OHOS {
    bool FuzzGetBlockDeviceByMountPoint(const uint8_t* data, size_t size)
    {
        bool result = false;
        FILE *pFile = nullptr;
        pFile = fopen("fstab.test", "w+");
        if (pFile == nullptr) {
            std::cout << "[fuzz] open file fstab.test failed";
            return false;
        }
        if (fwrite(data, 1, size, pFile) != size) {
            std::cout << "[fuzz] write data to fstab.test failed";
            (void)fclose(pFile);
            return false;
        }
        (void)fclose(pFile);
        CloseStdout();
        const Fstab *fstab = ReadFstabFromFile("fstab.test", false);
        std::string str(reinterpret_cast<const char*>(data), size);
        char deviceName[100] = {0};
        int length = sizeof(deviceName);
        if (!GetBlockDeviceByMountPoint(str.c_str(), fstab, deviceName, length)) {
            result = true;
        }
        return result;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::FuzzGetBlockDeviceByMountPoint(data, size);
    return 0;
}
