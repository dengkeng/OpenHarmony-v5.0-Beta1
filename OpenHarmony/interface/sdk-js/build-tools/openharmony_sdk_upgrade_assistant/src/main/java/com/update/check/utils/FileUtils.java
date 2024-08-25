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

package com.update.check.utils;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.update.check.log.Logger;
import com.update.check.dto.ApiDiffResultDto;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.compress.compressors.gzip.GzipCompressorInputStream;
import org.apache.commons.compress.utils.IOUtils;

import java.io.File;
import java.io.InputStream;
import java.io.IOException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.OutputStreamWriter;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.io.BufferedWriter;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;
import java.util.Properties;

/**
 * FileUtils
 *
 * @since 23-04-07
 */
public class FileUtils {
    private static final String LOG_TAG = FileUtils.class.getName();
    private static final Logger LOGGER = Logger.createLogger();

    /**
     * getApiTools
     *
     * @since 23-04-07
     */
    public void getApiTools() {
        try {

            // getLastDir
            String lastDir = getLastDir();
            File updateCheck = new File(lastDir, "updateCheck");
            if (!updateCheck.exists()) {
                updateCheck.mkdirs();
            }

            // api diff tool
            File diffPath = new File(updateCheck.toString(), "api-diff");
            if (!diffPath.exists()) {
                InputStream apiDiffInputStream = this.getToolsInputStream("api-diff.tar.gz");
                if (apiDiffInputStream != null) {
                    unGzipFile(apiDiffInputStream, updateCheck);
                }
            }

            // application api scanning tool
            File applicationPath = new File(updateCheck.toString(), "collect_application_api");
            if (!applicationPath.exists()) {
                InputStream applicationInputStream = this.getToolsInputStream("collect_application_api.tar.gz");
                if (applicationInputStream != null) {
                    unGzipFile(applicationInputStream, updateCheck);
                }
            }
        } catch (IOException e) {
            LOGGER.error(LOG_TAG, "get api tools error! " + e.getMessage());
        }

    }

    /**
     * getLastDir
     *
     * @return last dir
     */
    public static String getLastDir() {
        return File.listRoots()[File.listRoots().length - 1].toString();
    }

    private InputStream getToolsInputStream(String toolName) {
        return getClass().getClassLoader().getResourceAsStream(toolName);
    }

    /**
     * unGzipFile
     *
     * @param inputStream inputStream
     * @param targetDir   targetDir
     * @throws IOException If an I/O error occurs
     */
    public static void unGzipFile(InputStream inputStream, File targetDir)
            throws IOException {
        TarArchiveInputStream tarArchiveInputStream =
                new TarArchiveInputStream(
                        new GzipCompressorInputStream(inputStream));
        TarArchiveEntry entry;
        while ((entry = tarArchiveInputStream.getNextTarEntry()) != null) {
            if (entry.isDirectory()) {
                continue;
            }
            File targetFile = new File(targetDir, entry.getName());
            File parent = targetFile.getParentFile();
            if (!parent.exists()) {
                parent.mkdirs();
            }
            IOUtils.copy(tarArchiveInputStream, Files.newOutputStream(targetFile.toPath()));
        }
    }

    /**
     * getApplicationApiType
     *
     * @param projectBasePath projectBasePath
     * @return api type
     */
    public static String getApplicationApiType(String projectBasePath) {
        File buildFile = new File(projectBasePath, "build-profile.json5");
        try {
            String jsonString = getJsonString(buildFile);
            Object childParse = JSONObject.parse(jsonString);
            JSONObject parse = null;
            if (childParse instanceof JSONObject) {
                parse = (JSONObject) childParse;
            }
            Object childModel = parse.get("modules");
            JSONArray modules = null;
            if (childModel instanceof JSONArray) {
                modules = (JSONArray) childModel;
            }
            Object childObject = modules.get(0);
            JSONObject model = null;
            if (childObject instanceof JSONObject) {
                model = (JSONObject) childObject;
            }
            String modelName = String.valueOf(model.get("name"));
            File file = new File(projectBasePath, modelName + "\\build-profile.json5");
            String modelJson = getJsonString(file);
            Object child = JSONObject.parse(modelJson);
            JSONObject parseModel = null;
            if (child instanceof JSONObject) {
                parseModel = (JSONObject) child;
            }
            String result = null;
            Object objectResult = parseModel.get("apiType");
            if (objectResult instanceof String) {
                result = (String) objectResult;
            }
            return result;
        } catch (IOException e) {
            LOGGER.error(LOG_TAG, e.getMessage());
            return null;
        }
    }

    /**
     * getSdkVersionFromJsonFile
     *
     * @param jsonFilePath jsonFilePath
     * @return sdk version
     * @throws IOException If an I/O error occurs
     */
    public static String getSdkVersionFromJsonFile(String jsonFilePath) {
        try {
            File jsonFile = new File(jsonFilePath);
            String jsonStr = getJsonString(jsonFile);
            ApiDiffResultDto dto = JSON.parseObject(jsonStr, ApiDiffResultDto.class);
            return dto.getVersion();
        } catch (IOException e) {
            LOGGER.error(LOG_TAG, e.getMessage());
            return "";
        }
    }

    /**
     * readJsonFileToJavaList
     *
     * @param jsonFilePath jsonFilePath
     * @param clazz        clazz
     * @param <T>          T
     * @return class
     * @throws IOException If an I/O error occurs
     */
    public static <T> List<T> readJsonFileToJavaList(String jsonFilePath, Class<T> clazz) throws IOException {
        File jsonFile = new File(jsonFilePath);
        String jsonStr = getJsonString(jsonFile);
        return JSON.parseArray(jsonStr, clazz);
    }

    /**
     * writerJsonToFile
     *
     * @param jsonString   jsonString
     * @param jsonFilePath jsonFilePath
     */
    public static void writerJsonToFile(String jsonString, String jsonFilePath) {
        BufferedWriter bufferedWriter = null;
        try {
            File file = new File(jsonFilePath);
            if (!file.getParentFile().exists()) {
                file.getParentFile().mkdirs();
                file.createNewFile();
            }
            bufferedWriter = new BufferedWriter(
                    new OutputStreamWriter(
                            new FileOutputStream(file), StandardCharsets.UTF_8
                    ));
            bufferedWriter.write(jsonString);
        } catch (IOException e) {
            LOGGER.error(LOG_TAG, e.getMessage());
        } finally {
            if (null != bufferedWriter) {
                try {
                    bufferedWriter.close();
                } catch (IOException exception) {
                    exception.printStackTrace();
                }
            }
        }
    }

    /**
     * getNodePath
     *
     * @param projectPath projectPath
     * @param file        file
     * @param name        name
     * @return node path
     */
    public static String getNodePath(String projectPath, String file, String name) {
        Properties properties = new Properties();
        File props = new File(projectPath, file);
        if (!props.exists()) {
            return null;
        }
        try (InputStream in = new FileInputStream(props)) {
            properties.load(in);
            return properties.getProperty(name);
        } catch (IOException e) {
            LOGGER.error(LOG_TAG, e.getMessage());
            return null;
        }
    }

    /**
     * getCompileSdkVersion
     *
     * @param projectPath projectPath
     * @return sdk version
     * @throws IOException If an I/O error occurs
     */
    public static String getCompileSdkVersion(String projectPath) throws IOException {
        if (projectPath == null) {
            return null;
        }
        File buildFile = new File(projectPath, "build-profile.json5");

        if (!buildFile.exists()) {
            return null;
        }
        return getCompileSdkVersion(buildFile);
    }

    /**
     * getCompileSdkVersion
     *
     * @param buildFile buildFile
     * @return sdk version
     * @throws IOException If an I/O error occurs
     */
    public static String getCompileSdkVersion(File buildFile) throws IOException {
        String jsonString = getJsonString(buildFile);
        Object childParse = JSONObject.parse(jsonString);
        JSONObject parse = null;
        if (childParse instanceof JSONObject) {
            parse = (JSONObject) childParse;
        }
        Object parseApp = parse.get("app");
        JSONObject appJson = null;
        if (parseApp instanceof JSONObject) {
            appJson = (JSONObject) parseApp;
        }
        if (appJson.get("compileSdkVersion") != null) {
            return String.valueOf(appJson.get("compileSdkVersion"));
        }
        Object products = appJson.get("products");
        JSONArray modules = null;
        if (products instanceof JSONArray) {
            modules = (JSONArray) products;
        }
        Object childObject = modules.get(0);
        JSONObject product = null;
        if (childObject instanceof JSONObject) {
            product = (JSONObject) childObject;
        }
        return String.valueOf(product.get("compileSdkVersion"));
    }

    /**
     * getJsonString
     *
     * @param buildFile buildFile
     * @return json string
     * @throws IOException If an I/O error occurs
     */
    public static String getJsonString(File buildFile) throws IOException {
        FileReader fileReader = new FileReader(buildFile);
        Reader reader = new InputStreamReader(new FileInputStream(buildFile), StandardCharsets.UTF_8);
        int ch = 0;
        StringBuilder stringBuilder = new StringBuilder();
        while ((ch = reader.read()) != -1) {
            stringBuilder.append((char) ch);
        }
        fileReader.close();
        reader.close();
        return stringBuilder.toString();
    }

}