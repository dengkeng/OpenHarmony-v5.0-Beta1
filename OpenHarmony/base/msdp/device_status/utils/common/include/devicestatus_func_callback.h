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

#ifndef DEVICESTATUS_FUNC_CALLBACK_H
#define DEVICESTATUS_FUNC_CALLBACK_H

#include <functional>

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
template<class MemberFunType, class ClassType>
auto MsgCallbackBind2(MemberFunType func, ClassType* obj)
{
    return std::bind(func, obj, std::placeholders::_1, std::placeholders::_2);
}

template<class MemberFunType, class ClassType>
auto MsgCallbackBind1(MemberFunType func, ClassType* obj)
{
    return std::bind(func, obj, std::placeholders::_1);
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // DEVICESTATUS_FUNC_CALLBACK_H