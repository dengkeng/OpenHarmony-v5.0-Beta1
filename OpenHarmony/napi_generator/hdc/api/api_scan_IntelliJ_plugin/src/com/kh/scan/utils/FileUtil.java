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
package com.kh.scan.utils;

import com.intellij.notification.NotificationType;
import com.intellij.openapi.diagnostic.Logger;
import com.intellij.openapi.project.Project;
import org.apache.http.util.TextUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

/**
 * 文本文件工具
 *
 * @author: zhaoxudong@kaihong.com
 * @see: file utils
 * @version: v1.0.0
 * @since 2022-10-14
 */
public class FileUtil {
    private static final Logger LOG = Logger.getInstance(FileUtil.class);

    private static final int COMPILE_SDK_VERSION = 5;

    /**
     * 获取换行符
     *
     * @return 换行符
     */
    public static String getNewline() {
        return System.getProperty("line.separator");
    }

    /**
     * check project SDK
     *
     * @param project  projectid
     * @param baseFile project root file
     * @return boolean
     */
    public static boolean checkProjectSDK(Project project, String baseFile) {

        String gradlePath = "";
        File baseDir = new File(baseFile);
        if (baseDir.isDirectory()) {
            File[] childFile = baseDir.listFiles();
            assert childFile != null;
            for (File file : childFile) {
                if (file.getName().equals("build.gradle") || file.getName().equals("build-profile.json5")) {
                    gradlePath = file.getPath();
                }
            }
        }

        Properties properties = new Properties();
        if (TextUtils.isBlank(gradlePath)) {
            GenNotification.notifyMessage(project, "项目结构中没有grandle配置文件。", "当前项目结构不支持",
                NotificationType.WARNING);
            return true;
        }
        try {
            properties.load(new FileInputStream(gradlePath));
        } catch (IOException e) {
            GenNotification.notifyMessage(project, e.getMessage(), "提示", NotificationType.ERROR);
            LOG.error(String.format("Can not load file :%s . %s", gradlePath, e));
            return true;
        }
        String ohosSDK = properties.getProperty("compileSdkVersion");

        if (ohosSDK != null && Integer.parseInt(ohosSDK) < COMPILE_SDK_VERSION) {
            GenNotification.notifyMessage(project, "SKD版本过低，NAPI仅支持5.0及以上版本", "提示",
                NotificationType.WARNING);
            return true;
        }
        return false;
    }
}
