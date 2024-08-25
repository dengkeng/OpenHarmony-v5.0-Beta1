/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "utils.h"

#include <string.h>
#include "log.h"

#define ERROR_STR_LENGTH 0

bool IsStrValid(const char *str, uint32_t maxLen)
{
    if (str == NULL) {
        LOGE("input string is NULL ptr");
        return false;
    }
    // One byte must be reserved for the terminator.
    if (strnlen(str, maxLen) >= maxLen) {
        LOGE("input string is beyond max length");
        return false;
    }
    return true;
}

bool IsBlobValid(const HcfBlob *blob)
{
    return ((blob != NULL) && (blob->data != NULL) && (blob->len > 0));
}

bool IsClassMatch(const HcfObjectBase *obj, const char *className)
{
    if ((obj == NULL) || (obj->getClass() == NULL) || (className == NULL)) {
        return false;
    }
    if (strcmp(obj->getClass(), className) == 0) {
        return true;
    } else {
        LOGE("class is not match. expect class: %s, input class: %s", className, obj->getClass());
        return false;
    }
}

size_t HcfStrlen(const char *str)
{
    if (str == NULL) {
        LOGE("str is null");
        return ERROR_STR_LENGTH;
    }
    return strlen(str);
}
