/*
 * Copyright (c) 2022 Shenzhen Kaihong Digital Industry Development Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.sk.ts.ng;

import com.intellij.notification.NotificationType;
import com.intellij.openapi.actionSystem.AnAction;
import com.intellij.openapi.actionSystem.AnActionEvent;
import com.intellij.openapi.actionSystem.PlatformDataKeys;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.vfs.VirtualFile;

import com.sk.ts.dialog.TsGenerateDialog;
import com.sk.ts.utils.FileUtil;
import com.sk.ts.utils.GenNotification;

/**
 * 项目文件入口
 *
 * @author: xudong
 * @see: tool conversion plug-in
 * @version: v1.0.0
 * @since 2022-02-21
 */
public class GenDTS extends AnAction {

    @Override
    public void actionPerformed(AnActionEvent anActionEvent) {
        Project project = anActionEvent.getProject();
        // 获取需要处理的.d.ts文件绝对路径
        VirtualFile file = anActionEvent.getData(PlatformDataKeys.VIRTUAL_FILE);
        if (file == null) {
            GenNotification.notifyMessage(project, "", "file is not exist", NotificationType.ERROR);
            return;
        }
        if (project == null) {
            return;
        }
        String destPath = file.getPath();
        String directoryPath = file.getParent().getPath();
        String fileName = file.getName();
        boolean isSelectedToolchain = false;
        TsGenerateDialog wrapper = new TsGenerateDialog(project, destPath, directoryPath,
                fileName, isSelectedToolchain);
        wrapper.showAndGet();
    }


    @Override
    public void update(AnActionEvent event) {
        // 根据所选文件名，判断是否显示生成菜单项
        VirtualFile file = event.getData(PlatformDataKeys.VIRTUAL_FILE);
        if (file == null) {
            event.getPresentation().setEnabledAndVisible(false);
        } else {
            event.getPresentation().setEnabledAndVisible(FileUtil.patternFileName(file.getName()));
        }
    }
}
