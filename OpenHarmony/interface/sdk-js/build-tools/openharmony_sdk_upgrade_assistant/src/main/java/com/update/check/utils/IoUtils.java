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
import java.io.IOException;
import java.util.Objects;

/**
 * IoUtils
 *
 * @since 23-04-07
 */
public class IoUtils {

    /**
     * isValidLocalPath
     *
     * @param pathStr pathStr
     * @return {@code true} if the path is valid local path, {@code false} otherwise
     */
    public static boolean isValidLocalPath(String pathStr) {
        Objects.requireNonNull(pathStr);
        File ioPath = new File(pathStr);
        try {
            String absolutePath = ioPath.getCanonicalPath().replace('\\', '/');
            String path = pathStr.replace('\\', '/');
            return absolutePath.equals(path);
        } catch (IOException e) {
            return false;
        }
    }
}
