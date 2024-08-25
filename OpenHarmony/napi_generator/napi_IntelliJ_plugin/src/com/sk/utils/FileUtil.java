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
package com.sk.utils;

import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.JSONObject;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.intellij.notification.NotificationType;
import com.intellij.openapi.diagnostic.Logger;
import com.intellij.openapi.project.Project;
import org.apache.http.util.TextUtils;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Properties;
import java.util.regex.Pattern;

/**
 * 文本文件工具
 *
 * @author: xudong
 * @see: file utils
 * @version: v1.0.0
 * @since 2022-02-21
 */
public class FileUtil {
    private static final Logger LOG = Logger.getInstance(FileUtil.class);

    private static final int COMPILE_SDK_VERSION = 5;

    private static final String LF = getNewline(); // 换行符

    private static final String BUILD_OPTION = "{" + LF
            + "    \"externalNativeOptions\": {" + LF
            + "      \"path\": \"\"," + LF
            + "      \"arguments\": \"\"," + LF
            + "      \"cppFlags\": \"\"," + LF
            + "    }" + LF
            + "  }";

    /**
     * 改写build-profile.json5文件
     *
     * @param buildJsonFilePath build-profile.json5 文件路径
     * @param cmakeFilePath CMakeList.txt 文件路径
     */
    public void writeBuildJsonFile(String buildJsonFilePath, String cmakeFilePath) {
        try {
            String buildStr = readWholeFile(buildJsonFilePath);
            JSONObject buildObj = (JSONObject) JSON.parse(buildStr);
            JSONObject buildOptionObj = (JSONObject) JSON.parse(BUILD_OPTION);
            ((JSONObject) buildOptionObj.get("externalNativeOptions")).put("path", cmakeFilePath);
            buildObj.put("buildOption", buildOptionObj);
            ObjectMapper mapper = new ObjectMapper();
            buildStr = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(buildObj);

            writeContentToFile(buildJsonFilePath, buildStr, false);
        } catch (IOException ioException) {
            LOG.error("Failed to write file [" + buildJsonFilePath + "], error: " + ioException);
        }
    }

    /**
     * 将数据写入到指定文件中
     *
     * @param path    文件路径
     * @param content 数据内容
     * @param isAppend 文件是否追加写入
     */
    public void writeContentToFile(String path, String content, boolean isAppend) {
        File file = new File(path);
        try (FileWriter fw = new FileWriter(file, isAppend)) {
            fw.write(FileUtil.getNewline() + content + FileUtil.getNewline());
        } catch (IOException ioException) {
            LOG.error("Failed to write file [" + path + "], error: " + ioException);
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
     * 获得 pathA 相对于 pathB的相对路径
     *
     * @param pathA 路径A，如 D:\xx\yy\zz\a1\a2
     * @param pathB 路径B, 如 D:\xx\yy\zz\b1\b2\b3
     * @return pathA 相对于 pathB的相对路径: ../../../a1/a2/
     */
    public String getRelativePath(String pathA, String pathB) {
        String separatorStr = File.separator.equals("\\") ? "\\\\" : File.separator;
        String[] pathAList = pathA.split(separatorStr);
        String[] pathBList = pathB.split(separatorStr);

        int pos = 0;
        for (; pos < pathAList.length && pos < pathBList.length; ++pos) {
            if (!pathAList[pos].equals(pathBList[pos])) {
                // 找到两个path路径存在差异的位置
                break;
            }
        }
        // 截取pathA和pathB路径字符串的差异部分
        String[] diffPathAList = Arrays.copyOfRange(pathAList, pos, pathAList.length);
        String[] diffPathBList = Arrays.copyOfRange(pathBList, pos, pathBList.length);

        // pathA的差异字符串作为相对路径的结尾部分
        String pathAStr = String.join("/", diffPathAList);
        pathAStr = pathAStr.isBlank() ? "" : pathAStr + "/";

        // 根据pathB的差异目录层级生成向上跳转字符串
        String rollbackPath = "";
        for (int i = 0; i < diffPathBList.length; ++i) {
            rollbackPath += "../";
        }
        rollbackPath = rollbackPath.isEmpty() ? "./" : rollbackPath;

        // 相对路径 = 向上跳转部分 + pathA的差异部分
        return rollbackPath + pathAStr;
    }

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
     * 判断文件是否包含指定字符串
     *
     * @param path    文件路径
     * @param content 指定内容
     * @return 是否包含指定字符串
     * @throws IOException 异常信息
     */
    public boolean findStringInFile(String path, String content) throws IOException {
        File file = new File(path);
        String[] command = content.split(FileUtil.getNewline());

        try (InputStreamReader read = new InputStreamReader(new FileInputStream(file), StandardCharsets.UTF_8);
            BufferedReader bufferedReader = new BufferedReader(read)) {
            return isContainString(bufferedReader, command[1]);
        } catch (FileNotFoundException foundException) {
            LOG.error("file not found" + foundException);
            return false;
        }
    }

    private boolean isContainString(BufferedReader bufferedReader, String command) {
        String line = null;
        while (true) {
            try {
                if ((line = bufferedReader.readLine()) == null) {
                    return false;
                }
            } catch (IOException ioException) {
                LOG.error("findStringInFile IOException" + ioException);
            }

            if (line.contains(command)) {
                return true;
            }
        }
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
        String pattern = "((@ohos\\.)*([.a-z_A-Z0-9]+).d.ts)";
        return Pattern.matches(pattern, fileName);
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
            GenNotification.notifyMessage(project, "项目结构中没有grandle配置文件。",
                    "当前项目结构不支持",
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
            GenNotification.notifyMessage(project, "SKD版本过低，NAPI仅支持5.0及以上版本",
                    "提示",
                    NotificationType.WARNING);
            return true;
        }
        return false;
    }

    private String readWholeFile(String fileName) {
        File file = new File(fileName);
        byte[] rdBuf = new byte[(int) file.length()];
        try(FileInputStream in = new FileInputStream(file)) {
            in.read(rdBuf);
            return new String(rdBuf, "UTF-8");
        } catch (FileNotFoundException foundException) {
            LOG.error(String.format("File %s does not exist.", fileName));
        } catch (IOException ioException) {
            LOG.error(String.format("Failed to read file %s. Error: %s", fileName, ioException));
        }
        return "";
    }
}
