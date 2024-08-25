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

package com.update.check.action.view;

import com.update.check.log.Logger;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.wm.ToolWindow;
import com.intellij.openapi.wm.ToolWindowFactory;
import org.jetbrains.annotations.NotNull;

/**
 * ReporterToolWindowFactory
 *
 * @since 23-04-07
 */
public class ReporterToolWindowFactory implements ToolWindowFactory {

    private static final String LOG_TAG = ReporterToolWindowFactory.class.getName();

    private static final Logger LOGGER = Logger.createLogger();

    /**
     * createToolWindowContent
     *
     * @param project    project
     * @param toolWindow toolWindow
     */
    @Override
    public void createToolWindowContent(@NotNull Project project, @NotNull ToolWindow toolWindow) {
        LOGGER.info(LOG_TAG, "Start loading report window");
        UpdateReportPanel.loadPanel(project, toolWindow);
    }
}
