/*
 * Copyright (c) 2022 Guangzhou Digitalchina Information Technology Co., Ltd.
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
package com.sk.ng;

import com.intellij.openapi.actionSystem.AnAction;
import com.intellij.openapi.actionSystem.AnActionEvent;
import com.intellij.openapi.project.Project;
import com.sk.dialog.GenerateDialog;
import org.jetbrains.annotations.NotNull;

/**
 * 工具菜单入口
 *
 * @author: liulongc  digitalchina.com
 * @see: tool conversion plug-in
 * @version: v1.0.0
 * @since 2022-05-27
 */
public class GenMenuDTS extends AnAction {

    @Override
    public void actionPerformed(@NotNull AnActionEvent anActionEvent) {
        Project project = anActionEvent.getProject();

        if (project == null) {
            return;
        }
        GenerateDialog wrapper = new GenerateDialog(project, "", "", "");
        wrapper.showAndGet();
    }

}
