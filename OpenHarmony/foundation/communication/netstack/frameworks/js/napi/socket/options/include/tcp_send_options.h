/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef COMMUNICATIONNETSTACK_TCP_SEND_OPTIONS_H
#define COMMUNICATIONNETSTACK_TCP_SEND_OPTIONS_H

#include <string>
#include <iosfwd>

namespace OHOS::NetStack::Socket {
class TCPSendOptions final {
public:
    TCPSendOptions() = default;

    ~TCPSendOptions() = default;

    void SetData(const std::string &data);

    void SetData(void *data, size_t size);

    void SetEncoding(const std::string &encoding);

    [[nodiscard]] const std::string &GetData() const;

    [[nodiscard]] const std::string &GetEncoding() const;

private:
    std::string data_;

    std::string encoding_;
};
} // namespace OHOS::NetStack::Socket

#endif /* COMMUNICATIONNETSTACK_TCP_SEND_OPTIONS_H */
