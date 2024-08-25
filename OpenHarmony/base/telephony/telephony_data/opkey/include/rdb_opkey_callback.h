/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef DATA_STORAGE_RDB_OPKEY_CALLBACK_H
#define DATA_STORAGE_RDB_OPKEY_CALLBACK_H

#include "iosfwd"
#include "rdb_base_callback.h"
#include "vector"

namespace OHOS {
namespace NativeRdb {
class RdbStore;
}
namespace Telephony {
class RdbOpKeyCallback : public RdbBaseCallBack {
public:
    explicit RdbOpKeyCallback(const std::vector<std::string> &createTableVec) : RdbBaseCallBack(createTableVec) {}
    ~RdbOpKeyCallback() = default;

    static int64_t InitData(NativeRdb::RdbStore &rdbStore, const std::string &tableName);
    int OnUpgrade(NativeRdb::RdbStore &rdbStore, int oldVersion, int newVersion) override;
    int OnDowngrade(NativeRdb::RdbStore &rdbStore, int currentVersion, int targetVersion) override;
    int OnCreate(NativeRdb::RdbStore &rdbStore) override;
    int OnOpen(NativeRdb::RdbStore &rdbStore) override;

private:
    static int ClearData(NativeRdb::RdbStore &rdbStore);
    static bool IsOpKeyDbUpdateNeeded(std::string &checkSum);
    static int SetPreferOpKeyConfChecksum(std::string &checkSum);
};
} // namespace Telephony
} // namespace OHOS
#endif // DATA_STORAGE_RDB_OPKEY_CALLBACK_H