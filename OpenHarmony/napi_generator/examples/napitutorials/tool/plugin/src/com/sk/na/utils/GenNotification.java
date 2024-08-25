/*
 * Copyright (c) 2024 Shenzhen Kaihong Digital Industry Development Co., Ltd.
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
package com.sk.na.utils;

import com.intellij.notification.NotificationType;
import com.intellij.notification.Notification;
import com.intellij.notification.NotificationGroupManager;
import com.intellij.notification.NotificationGroup;
import com.intellij.notification.Notifications;
import com.intellij.openapi.diagnostic.Logger;
import com.intellij.openapi.project.Project;

/**
 * 通知框
 *
 * @author: goujingjing
 * @see: tool conversion plug-in
 * @version: v1.0.0
 * @since 2024-04-02
 */
public class GenNotification {

    private static final Logger LOG = Logger.getInstance(GenNotification.class);

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
}
