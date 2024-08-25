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

package com.update.check.model;

import java.util.Objects;

/**
 * ComponentKey
 *
 * @since 23-04-07
 */
public class ComponentKey<T> {
    private final Class<T> componentType;

    /**
     * ComponentKey
     *
     * @param key key
     */
    public ComponentKey(Class<T> key) {
        Objects.requireNonNull(key);
        this.componentType = key;
    }

    /**
     * getComponentType
     *
     * @return Class
     */
    public Class<T> getComponentType() {
        return this.componentType;
    }

    /**
     * safeCast
     *
     * @param value value
     * @return T
     */
    public T safeCast(Object value) {
        if (value == null) {
            return null;
        }

        if (!this.componentType.isInstance(value)) {
            return null;
        }

        return this.componentType.cast(value);
    }
}
