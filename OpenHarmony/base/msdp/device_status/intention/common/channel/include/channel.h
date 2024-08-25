/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef CHANNEL_H
#define CHANNEL_H

#include <condition_variable>
#include <deque>
#include <memory>
#include <mutex>
#include <type_traits>

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

template<typename Event>
class Channel {
    static_assert(std::is_enum_v<Event> || std::is_integral_v<Event> ||
                  (std::is_class_v<Event> &&
                   std::is_default_constructible_v<Event> &&
                   std::is_copy_constructible_v<Event>));

public:
    class Sender final {
        friend class Channel<Event>;

    public:
        Sender() = default;
        ~Sender() = default;

        Sender(const Sender &other)
            : channel_(other.channel_)
        {}

        Sender(Sender &&other)
            : channel_(other.channel_)
        {
            other.channel_ = nullptr;
        }

        Sender& operator=(const Sender &other)
        {
            channel_ = other.channel_;
            return *this;
        }

        Sender& operator=(Sender &&other)
        {
            channel_ = other.channel_;
            other.channel_ = nullptr;
            return *this;
        }

        void Send(const Event &event)
        {
            if (channel_ != nullptr) {
                channel_->Send(event);
            }
        }

    private:
        Sender(std::shared_ptr<Channel<Event>> channel)
            : channel_(channel)
        {}

        std::shared_ptr<Channel<Event>> channel_ { nullptr };
    };

    class Receiver final {
        friend class Channel<Event>;

    public:
        Receiver() = default;
        ~Receiver() = default;

        Receiver(const Receiver &other)
            : channel_(other.channel_)
        {}

        Receiver(Receiver &&other)
            : channel_(other.channel_)
        {
            other.channel_ = nullptr;
        }

        Receiver& operator=(const Receiver &other)
        {
            channel_ = other.channel_;
            return *this;
        }

        Receiver& operator=(Receiver &&other)
        {
            channel_ = other.channel_;
            other.channel_ = nullptr;
            return *this;
        }

        Event Peek()
        {
            return (channel_ != nullptr ? channel_->Peek() : Event());
        }

        void Pop()
        {
            if (channel_ != nullptr) {
                channel_->Pop();
            }
        }

        Event Receive()
        {
            return (channel_ != nullptr ? channel_->Receive() : Event());
        }

    private:
        Receiver(std::shared_ptr<Channel<Event>> channel)
            : channel_(channel)
        {}

        std::shared_ptr<Channel<Event>> channel_ { nullptr };
    };

    Channel() = default;
    ~Channel() = default;

    static std::pair<Sender, Receiver> OpenChannel();

private:
    void Send(const Event &event);
    Event Peek();
    void Pop();
    Event Receive();

    static inline constexpr size_t QUEUE_CAPACITY { 1024 };

    std::mutex lock_;
    std::condition_variable full_;
    std::condition_variable empty_;
    std::deque<Event> queue_;
};

template<typename Event>
std::pair<typename Channel<Event>::Sender, typename Channel<Event>::Receiver> Channel<Event>::OpenChannel()
{
    std::shared_ptr<Channel<Event>> channel = std::make_shared<Channel<Event>>();
    return std::make_pair(Channel<Event>::Sender(channel), Channel<Event>::Receiver(channel));
}

template<typename Event>
void Channel<Event>::Send(const Event &event)
{
    std::unique_lock<std::mutex> lock(lock_);
    if (queue_.size() >= QUEUE_CAPACITY) {
        full_.wait(lock, [this] {
            return (queue_.size() < QUEUE_CAPACITY);
        });
    }
    bool needNotify = queue_.empty();
    queue_.push_back(event);
    if (needNotify) {
        empty_.notify_one();
    }
}

template<typename Event>
Event Channel<Event>::Peek()
{
    std::unique_lock<std::mutex> lock(lock_);
    if (queue_.empty()) {
        empty_.wait(lock, [this] {
            return !queue_.empty();
        });
    }
    return queue_.front();
}

template<typename Event>
void Channel<Event>::Pop()
{
    std::unique_lock<std::mutex> lock(lock_);
    if (queue_.empty()) {
        empty_.wait(lock, [this] {
            return !queue_.empty();
        });
    }
    bool needNotify(queue_.size() >= QUEUE_CAPACITY);
    queue_.pop_front();
    if (needNotify) {
        full_.notify_one();
    }
}

template<typename Event>
Event Channel<Event>::Receive()
{
    std::unique_lock<std::mutex> lock(lock_);
    if (queue_.empty()) {
        empty_.wait(lock, [this] {
            return !queue_.empty();
        });
    }
    bool needNotify(queue_.size() >= QUEUE_CAPACITY);
    Event event = queue_.front();
    queue_.pop_front();
    if (needNotify) {
        full_.notify_one();
    }
    return event;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // CHANNEL_H