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

import com.intellij.openapi.util.Ref;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.function.Supplier;

/**
 * BaseContext
 *
 * @since 23-04-07
 */
public abstract class BaseContext<T> {
    private final Map<ComponentKey<?>, Object> components;

    /**
     * BaseContext
     *
     * @since 23-04-07
     */
    public BaseContext() {
        this.components = new HashMap<>();
    }

    /**
     * getContextImpl
     *
     * @return T
     */
    public abstract T getContextImpl();

    /**
     * addComponent
     *
     * @param key      key
     * @param supplier supplier
     * @param arg1     arg1
     * @param arg2     arg2
     * @param <T1>     T1
     * @param <T2>     T2
     * @param <T3>     T3
     * @return T
     */
    public synchronized <T1, T2, T3> T3 addComponent(ComponentKey<T3> key,
                                                     BiFunction<T1, T2, T3> supplier, T1 arg1, T2 arg2) {
        return addComponent(key, () -> supplier.apply(arg1, arg2));
    }

    /**
     * addComponent
     *
     * @param key        key
     * @param newCreated newCreated
     * @param supplier   supplier
     * @param arg1       arg1
     * @param arg2       arg2
     * @param <T1>       T1
     * @param <T2>       T2
     * @param <T3>       T3
     * @return T
     */
    public synchronized <T1, T2, T3> T3 addComponent(ComponentKey<T3> key,
                                                     Ref<Boolean> newCreated,
                                                     BiFunction<T1, T2, T3> supplier,
                                                     T1 arg1,
                                                     T2 arg2) {
        newCreated.set(false);
        return addComponent(key, () -> {
            newCreated.set(true);
            return supplier.apply(arg1, arg2);
        });
    }

    /**
     * addComponent
     *
     * @param key      key
     * @param supplier supplier
     * @param arg1     arg1
     * @param <T1>     T1
     * @param <T2>     T2
     * @return T
     */
    public synchronized <T1, T2> T2 addComponent(ComponentKey<T2> key, Function<T1, T2> supplier, T1 arg1) {
        return addComponent(key, () -> supplier.apply(arg1));
    }

    /**
     * addComponent
     *
     * @param key        key
     * @param newCreated newCreated
     * @param supplier   supplier
     * @param arg1       arg1
     * @param <T1>       T1
     * @param <T2>       T2
     * @return T
     */
    public synchronized <T1, T2> T2 addComponent(ComponentKey<T2> key,
                                                 Ref<Boolean> newCreated,
                                                 Function<T1, T2> supplier,
                                                 T1 arg1) {
        newCreated.set(false);
        return addComponent(key, () -> {
            newCreated.set(true);
            return supplier.apply(arg1);
        });
    }

    /**
     * addComponent
     *
     * @param key        key
     * @param newCreated newCreated
     * @param supplier   supplier
     * @param <T1>       T1
     * @return T
     */
    public synchronized <T1> T1 addComponent(ComponentKey<T1> key, Ref<Boolean> newCreated, Supplier<T1> supplier) {
        newCreated.set(false);
        return addComponent(key, () -> {
            newCreated.set(true);
            return supplier.get();
        });
    }

    /**
     * addComponent
     *
     * @param key      key
     * @param supplier supplier
     * @param <T1>     T1
     * @return T
     */
    public synchronized <T1> T1 addComponent(ComponentKey<T1> key, Supplier<T1> supplier) {
        Objects.requireNonNull(key);
        Objects.requireNonNull(supplier);

        Object preValue = this.components.get(key);
        if (preValue != null) {
            return Objects.requireNonNull(key.safeCast(preValue));
        }

        T1 value = Objects.requireNonNull(supplier.get());
        this.components.put(key, value);
        return value;
    }

    /**
     * getComponent
     *
     * @param key  key
     * @param <T1> T1
     * @return T
     */
    public synchronized <T1> T1 getComponent(ComponentKey<T1> key) {
        Objects.requireNonNull(key);

        Object value = this.components.get(key);
        return key.safeCast(value);
    }

    /**
     * removeComponent
     *
     * @param key  key
     * @param <T1> T1
     * @return T
     */
    public synchronized <T1> T1 removeComponent(ComponentKey<T1> key) {
        Objects.requireNonNull(key);
        Object value = this.components.remove(key);
        return key.safeCast(value);
    }

    /**
     * updateComponent
     *
     * @param key      key
     * @param supplier supplier
     * @param arg1     arg1
     * @param arg2     arg2
     * @param <T1>     T1
     * @param <T2>     T2
     * @param <T3>     T3
     * @return T
     */
    public synchronized <T1, T2, T3> T3 updateComponent(ComponentKey<T3> key,
                                                        BiFunction<T1, T2, T3> supplier,
                                                        T1 arg1,
                                                        T2 arg2) {
        return addComponent(key, () -> supplier.apply(arg1, arg2));
    }

    /**
     * updateComponent
     *
     * @param key      key
     * @param supplier supplier
     * @param arg1     arg1
     * @param <T1>     T1
     * @param <T2>     T2
     * @return T
     */
    public synchronized <T1, T2> T2 updateComponent(ComponentKey<T2> key, Function<T1, T2> supplier, T1 arg1) {
        return addComponent(key, () -> supplier.apply(arg1));
    }

    /**
     * updateComponent
     *
     * @param key      key
     * @param supplier supplier
     * @param <T1>     T1
     * @return T
     */
    public synchronized <T1> T1 updateComponent(ComponentKey<T1> key, Supplier<T1> supplier) {
        Objects.requireNonNull(key);
        Objects.requireNonNull(supplier);

        T1 value = Objects.requireNonNull(supplier.get());
        this.components.put(key, value);
        return value;
    }

    /**
     * removeAllComponents
     *
     * @since 23-04-07
     */
    public synchronized void removeAllComponents() {
        this.components.clear();
    }

}
