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

#include "av_trans_buffer.h"

#include <securec.h>

namespace OHOS {
namespace DistributedHardware {
AVTransBuffer::AVTransBuffer(MetaType type) : meta_()
{
    meta_ = std::make_shared<BufferMeta>(type);
}

std::shared_ptr<BufferData> AVTransBuffer::CreateBufferData(size_t capacity)
{
    auto bufData = std::make_shared<BufferData>(capacity);
    data_.push_back(bufData);
    return bufData;
}

std::shared_ptr<BufferData> AVTransBuffer::WrapBufferData(const uint8_t* data, size_t capacity, size_t size)
{
    auto bufData = std::make_shared<BufferData>(capacity,
        std::shared_ptr<uint8_t>(const_cast<uint8_t *>(data), [](void* ptr) {}));
    bufData->SetSize(size);
    data_.push_back(bufData);
    return bufData;
}

std::shared_ptr<BufferData> AVTransBuffer::GetBufferData(uint32_t index)
{
    if (data_.size() <= index) {
        return nullptr;
    }
    return data_[index];
}

std::shared_ptr<BufferMeta> AVTransBuffer::GetBufferMeta()
{
    return meta_;
}

void AVTransBuffer::UpdateBufferMeta(std::shared_ptr<BufferMeta> bufferMeta)
{
    meta_ = bufferMeta;
}

uint32_t AVTransBuffer::GetDataCount()
{
    return data_.size();
}

bool AVTransBuffer::IsEmpty()
{
    return data_.empty();
}

void AVTransBuffer::Reset()
{
    data_[0]->Reset();
    MetaType type = meta_->GetMetaType();
    meta_.reset();
    meta_ = std::make_shared<BufferMeta>(type);
}

BufferData::BufferData(size_t capacity)
    : capacity_(capacity), size_(0), address_(nullptr)
{
    address_ = std::shared_ptr<uint8_t>(new uint8_t[capacity], std::default_delete<uint8_t[]>());
}

BufferData::BufferData(size_t capacity, std::shared_ptr<uint8_t> bufData)
    : capacity_(capacity), size_(0), address_(std::move(bufData))
{
}

size_t BufferData::GetSize()
{
    return size_;
}

size_t BufferData::GetCapacity()
{
    return capacity_;
}

uint8_t* BufferData::GetAddress() const
{
    return address_.get();
}

size_t BufferData::Write(const uint8_t* in, size_t writeSize, size_t position)
{
    size_t start = 0;
    if (position == INVALID_POSITION) {
        start = size_;
    } else {
        start = std::min(position, capacity_);
    }
    size_t length = std::min(writeSize, capacity_ - start);
    if (memcpy_s(GetAddress() + start, length, in, length) != EOK) {
        return 0;
    }
    size_ = start + length;
    return length;
}

size_t BufferData::Read(uint8_t* out, size_t readSize, size_t position)
{
    size_t start = 0;
    size_t maxLength = size_;
    if (position != INVALID_POSITION) {
        start = std::min(position, size_);
        maxLength = size_ - start;
    }
    size_t length = std::min(readSize, maxLength);
    if (memcpy_s(out, length, GetAddress() + start, length) != EOK) {
        return 0;
    }
    return length;
}

void BufferData::Reset()
{
    this->size_ = 0;
}

void BufferData::SetSize(size_t size)
{
    this->size_ = size;
}

BufferMeta::BufferMeta(MetaType type) : type_(type)
{
}

bool BufferMeta::GetMetaItem(AVTransTag tag, std::string& value)
{
    if (tagMap_.count(tag) != 0) {
        value = tagMap_[tag];
        return true;
    } else {
        return false;
    }
}

void BufferMeta::SetMetaItem(AVTransTag tag, const std::string& value)
{
    tagMap_[tag] = value;
}

MetaType BufferMeta::GetMetaType() const
{
    return type_;
}
} // namespace DistributedHardware
} // namespace OHOS