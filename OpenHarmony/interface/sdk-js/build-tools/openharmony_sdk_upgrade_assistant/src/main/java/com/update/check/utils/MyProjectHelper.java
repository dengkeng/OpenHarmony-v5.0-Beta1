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

import java.io.File;

/**
 * MyProjectHelper
 *
 * @since 23-04-07
 */
public class MyProjectHelper {
    /**
     * isOpenHarmonyProject
     *
     * @param projectPath projectPath
     * @return {@code true} if this project is OpenHarmony project, {@code false} otherwise
     */
    public static boolean isOpenHarmonyProject(String projectPath) {
        if (projectPath == null) {
            return false;
        }
        return isOpenHarmonyProject(new File(projectPath));
    }

    /**
     * isOpenHarmonyProject
     *
     * @param projectPath projectPath
     * @return {@code true} if this project is OpenHarmony project, {@code false} otherwise
     */
    public static boolean isOpenHarmonyProject(File projectPath) {
        if (projectPath == null) {
            return false;
        }

        if (!projectPath.exists()) {
            return false;
        }

        if (!projectPath.isDirectory()) {
            return false;
        }

        String sdkPath = FileUtils.getNodePath(projectPath.getPath(), "local.properties", "sdk.dir");
        return sdkPath != null;
    }

}
