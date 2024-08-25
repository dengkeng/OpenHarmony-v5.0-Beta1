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
package com.sk.utils;

import com.intellij.ide.actions.OpenFileAction;
import com.intellij.notification.NotificationType;
import com.intellij.notification.Notification;
import com.intellij.notification.NotificationGroupManager;
import com.intellij.notification.NotificationGroup;
import com.intellij.notification.NotificationAction;
import com.intellij.notification.Notifications;
import com.intellij.openapi.actionSystem.AnActionEvent;
import com.intellij.openapi.diagnostic.Logger;
import com.intellij.openapi.project.Project;
import org.jetbrains.annotations.NotNull;

import java.util.List;

/**
 * 通知框
 *
 * @author: liulongc  digitalchina.com
 * @see: tool conversion plug-in
 * @version: v1.0.0
 * @since 2022-05-27
 */
public class GenNotification {

    private static final Logger LOG = Logger.getInstance(FileUtil.class);

    private GenNotification() {
    }

    /**
     * 消息通知
     *
     * @param project projectid
     * @param content 提示内容
     * @param title   提示栏内容
     * @param type    提示类型 Error,Waring,info
     */
    public static void notifyMessage(@javax.annotation.Nullable Project project,
        String content,
        String title,
        NotificationType type) {

        NotificationGroupManager manager = NotificationGroupManager.getInstance();
        NotificationGroup notificationGroup = manager.getNotificationGroup("Generate.Result.Group");
        Notification notification = notificationGroup.createNotification(content, type);
        notification.setTitle(title);
        notification.setContent(content);

        if (NotificationType.ERROR.equals(type)) {
            LOG.error(content);
        } else if (NotificationType.WARNING.equals(type)) {
            LOG.warn(content);
        } else {
            LOG.info(content);
        }
        Notifications.Bus.notify(notification, project);

    }

    /**
     * 消息通知
     *
     * @param project projectid
     * @param newFileList 新增文件列表
     * @param title   提示栏内容
     * @param type    提示类型 Error,Waring,info
     */
    public static void notifyGenResult(@javax.annotation.Nullable Project project, List<FileInfo> newFileList,
        String title, NotificationType type) {
        NotificationGroupManager manager = NotificationGroupManager.getInstance();
        NotificationGroup notificationGroup = manager.getNotificationGroup("Generate.Result.Group");
        Notification notification = notificationGroup.createNotification("", type);
        notification.setTitle(title);
        notification.setContent(null);
        addAction(project, newFileList, notification);
        Notifications.Bus.notify(notification, project);
    }

    private static void addAction(Project project, List<FileInfo> newFileList, Notification notification) {
        LOG.info("generated file list log:");
        for (FileInfo fs : newFileList) {
            String filePath = fs.getPath();
            NotificationAction action = new NotificationAction(filePath) {
                @Override
                public void actionPerformed(@NotNull AnActionEvent anActionEvent,
                                            @NotNull Notification notification) {
                    OpenFileAction.openFile(filePath, project);
                }
            };
            notification.addAction(action);

        }
    }
}
