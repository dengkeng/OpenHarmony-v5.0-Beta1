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

package com.update.check.action;

import com.update.check.model.BaseContext;
import com.update.check.model.ComponentKey;
import com.intellij.openapi.Disposable;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.util.Disposer;
import org.jetbrains.annotations.NotNull;
import java.util.function.Function;

/**
 * UpdateCheckService
 *
 * @since 23-04-07
 */
public class UpdateCheckService extends BaseContext<UpdateCheckService> implements Disposable {
    private final Project project;

    private final Mode mode;

    /**
     * UpdateCheckService
     *
     * @param project project
     */
    public UpdateCheckService(@NotNull Project project) {
        this.project = project;
        this.mode = initMode(project);
        Disposer.register(this.project, this);
    }

    /**
     * Mode
     *
     * @since 23-04-07
     */
    public enum Mode {NONE, CONVERSION, FIX}

    private Mode initMode(@NotNull Project project) {
        return Mode.NONE;
    }

    @Override
    public UpdateCheckService getContextImpl() {
        return this;
    }

    /**
     * getMode
     *
     * @return Mode
     */
    @NotNull
    public Mode getMode() {
        return this.mode;
    }

    /**
     * getProject
     *
     * @return Project
     */
    @NotNull
    public Project getProject() {
        return this.project;
    }

    @Override
    public void dispose() {

    }

    /**
     * addComponent
     *
     * @param key key
     * @param supplier supplier
     * @param <T1> T1
     * @return T
     */
    public synchronized <T1> T1 addComponent(ComponentKey<T1> key, Function<? super Project, T1> supplier) {
        return super.addComponent(key, supplier, this.project);
    }

    /**
     * getInstance
     *
     * @param project project
     * @return UpdateCheckService
     */
    public static UpdateCheckService getInstance(@NotNull Project project) {
        return project.getService(UpdateCheckService.class);
    }

}
