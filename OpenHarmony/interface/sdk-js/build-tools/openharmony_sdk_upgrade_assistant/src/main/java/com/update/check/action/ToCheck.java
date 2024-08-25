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

import com.update.check.action.view.ConstString;
import com.update.check.action.view.MessageBox;
import com.update.check.action.view.UpdateCheckWizardDialog;
import com.update.check.log.Logger;
import com.update.check.utils.MyProjectHelper;
import com.intellij.openapi.actionSystem.AnAction;
import com.intellij.openapi.actionSystem.AnActionEvent;
import com.intellij.openapi.project.Project;
import org.jetbrains.annotations.NotNull;

import java.io.File;

/**
 * ToCheck
 *
 * @since 23-04-07
 */
public class ToCheck extends AnAction {
    private static final Logger LOGGER = Logger.createLogger();

    private static final String TAG = ToCheck.class.getName();

    @Override
    public void actionPerformed(@NotNull AnActionEvent e) {
        Project project = e.getProject();

        if (project == null) {
            return;
        }

        if (!MyProjectHelper.isOpenHarmonyProject(project.getBasePath())) {
            MessageBox.showDialog(project, "", ConstString.get("not.openHarmony.project"));
            return;
        }
        initLogConfig(project.getBasePath().concat(ConstString.get("check.log.path")));
        LOGGER.info(TAG, "Check start");
        UpdateCheckWizardDialog.showDialog(project);
    }

    /**
     * initLogConfig
     *
     * @param logDir logDir
     */
    private void initLogConfig(String logDir) {
        File logFile = new File(logDir);
        if (!logFile.exists()) {
            logFile.mkdirs();
        }
        Logger.init(logDir);
    }
}
