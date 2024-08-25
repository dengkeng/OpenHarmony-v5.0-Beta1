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
package com.sk.gn.utils;

import com.intellij.notification.NotificationType;
import com.intellij.openapi.diagnostic.Logger;
import com.intellij.openapi.project.Project;
import org.apache.http.util.TextUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;
import java.util.regex.Pattern;

/**
 * 文本文件工具
 *
 * @author: zhaoxudong@kaihong.com
 * @see: file utils
 * @version: v1.0.0
 * @since 2022-09-21
 */
public class FileUtil {
    private static final Logger LOG = Logger.getInstance(FileUtil.class);

    private static final int COMPILE_SDK_VERSION = 5;

    /**
     * 将错误信息输入到txt中
     *
     * @param path    路径
     * @param content 内容
     */
    public void writeErrorToTxt(String path, String content) {
        File file = new File(path);
        try (FileWriter fw = new FileWriter(file, true)) {
            fw.write(content + FileUtil.getNewline());
        } catch (IOException ioException) {
            LOG.error("writeErrorToTxt io error" + ioException);
        }
    }

    /**
     * 创建文件
     *
     * @param path 文件路径
     * @return 文件路径
     */
    public String makeFile(String path) {
        File file = new File(path);
        if (!file.exists()) {
            try {
                boolean isCreateFile = file.createNewFile();
                if (isCreateFile) {
                    LOG.info(String.format("makeFile %s success", path));
                }
            } catch (IOException ioException) {
                LOG.error(String.format("makeFile %s error:%s", path, ioException));
                return "";
            }
        }
        return file.getPath();
    }

    /**
     * 获取换行符
     *
     * @return 换行符
     */
    public static String getNewline() {
        return System.getProperty("line.separator");
    }

    /**
     * 正则匹配所选文件名是否符合规范
     *
     * @param fileName 文件名
     * @return boolean 是否匹配
     */
    public static boolean patternFileName(String fileName) {
        String pattern = "([.a-z_A-Z0-9]+).(am|txt)";
        return Pattern.matches(pattern, fileName);
    }

    /**
     * check project SDK
     *
     * @param project  project
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

    /**
     * 拷贝可执行文件到临时文件夹
     *
     * @param path    目标文件路径
     * @param oldPath 原文件路径
     * @param project project
     * @throws IOException exception
     */
    public static void writeTmpFile(String path, String oldPath, Project project) {
        File file = new File(path);
        try (InputStream inputStream = FileUtil.class.getClassLoader().getResourceAsStream(oldPath)) {
            if (inputStream == null) {
                throw new IOException("exec File InputStream is Null");
            }
            byte[] bs = inputStream.readAllBytes();
            file.setWritable(true);
            boolean isNewFile = file.createNewFile();
            if (!isNewFile) {
                LOG.info("writeTmpFile createNewFile error");
            }
            FileOutputStream fw = new FileOutputStream(file);
            fw.write(bs, 0, bs.length);
            fw.close();
        } catch (IOException e) {
            GenNotification.notifyMessage(project, e.getMessage(), "Can not Find File:" + oldPath,
                    NotificationType.ERROR);
            LOG.error(e);
        }
    }
}
