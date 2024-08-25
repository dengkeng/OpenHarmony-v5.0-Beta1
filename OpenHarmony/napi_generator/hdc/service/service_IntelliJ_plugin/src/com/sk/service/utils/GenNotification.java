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
package com.sk.service.utils;

import com.intellij.ide.actions.OpenFileAction;
import com.intellij.notification.Notification;
import com.intellij.notification.NotificationAction;
import com.intellij.notification.NotificationType;
import com.intellij.notification.Notifications;
import com.intellij.openapi.actionSystem.AnActionEvent;
import com.intellij.openapi.diagnostic.Logger;
import com.intellij.openapi.project.Project;
import org.jetbrains.annotations.NotNull;

import java.io.File;

/**
 * 通知框
 *
 * @author: zhaoxudong@kaihong.com
 * @see: tool conversion plug-in
 * @version: v1.0.0
 * @since 2022-05-27
 */
public class GenNotification {

    private static final Logger LOG = Logger.getInstance(FileUtil.class);

    private GenNotification() {
    }

    /**
     * 无action 通知
     *
     * @param project projectid
     * @param content 提示内容
     * @param title   提示栏内容
     * @param type    提示类型 Error,Waring,info
     */
    public static void notifyMessage(@javax.annotation.Nullable Project project, String content, String title,
        NotificationType type) {
        notifyMessage(project, content, title, type, false);
    }

    /**
     * 消息通知
     *
     * @param project projectid
     * @param content 提示内容
     * @param title   提示栏内容
     * @param type    提示类型 Error,Waring,info
     * @param addAct  是否添加action
     */
    public static void notifyMessage(@javax.annotation.Nullable Project project, String content, String title,
        NotificationType type, boolean addAct) {

        Notification notification = new Notification("Generate.Result.Group", "Notes Message", content, type);
        notification.setTitle(title);
        notification.setContent(content);

        if (NotificationType.ERROR.equals(type)) {
            LOG.error(content);
        } else if (NotificationType.WARNING.equals(type)) {
            LOG.warn(content);
        } else {
            LOG.info(content);
        }

        if (addAct) {
            notification.setContent(null);
            addAction(project, content, notification);
        }
        Notifications.Bus.notify(notification, project);

    }

    private static void addAction(Project project, String dirPath, Notification notification) {
        File genResultPath = new File(dirPath);
        if (!genResultPath.exists()) {
            LOG.info(String.format("%s not exist", genResultPath.getPath()));
        }
        LOG.info("generated file list log:");

        File[] fa = genResultPath.listFiles();
        for (int i = 0; i < fa.length; i++) {
            File fs = fa[i];
            String fileName = fs.getName();
            boolean dissFile = !fileName.endsWith(".log") || !fileName.endsWith(".txt") || !fileName.endsWith(".ts");
            if (!fs.isDirectory() && dissFile) {
                String filePath = fs.getPath();
                NotificationAction action = new NotificationAction(filePath) {
                    @Override
                    public void actionPerformed(@NotNull AnActionEvent anActionEvent,
                                                @NotNull Notification notification) {
                        OpenFileAction.openFile(filePath, project);
                    }
                };
                notification.addAction(action);
            } else {
                LOG.info(String.format("%s is Directory", fs.getPath()));
            }
        }
    }
}
