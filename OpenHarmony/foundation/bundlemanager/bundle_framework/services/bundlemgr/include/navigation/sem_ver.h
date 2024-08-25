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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_NAVIGATION_SEM_VER_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_NAVIGATION_SEM_VER_H

#include <cstdint>
#include <regex>
#include <sstream>
#include <string>
#include <vector>

namespace OHOS {
namespace AppExecFwk {
class SemVer {
public:
    std::string major;
    std::string minor;
    std::string patch;
    std::vector<std::string> prerelease;
    std::vector<std::string> buildMeta;
    std::string raw;

    explicit SemVer(std::string version_string);
};
} // AppExecFwk
} // OHOS
#endif // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_NAVIGATION_SEM_VER_H