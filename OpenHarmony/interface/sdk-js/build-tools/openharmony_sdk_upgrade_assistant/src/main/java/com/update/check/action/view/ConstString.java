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

package com.update.check.action.view;

import com.update.check.log.Logger;
import org.jetbrains.annotations.NotNull;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Properties;

/**
 * ConstString
 *
 * @since 23-04-07
 */
public class ConstString {
    private static final String LOG_TAG = ConstString.class.getName();

    private static final Logger LOGGER = Logger.createLogger();

    private static Properties properties = new Properties();

    /**
     * load .properties file
     */
    public static void loadProperties() {
        InputStream inputStream = null;
        try {
            inputStream = ConstString.class.getClassLoader().getResourceAsStream("const.properties");
            properties.load(new InputStreamReader(inputStream, StandardCharsets.UTF_8));
        } catch (IOException e) {
            LOGGER.error(LOG_TAG, "get const.properties error!");
        } finally {
            try {
                inputStream.close();
            } catch (IOException ie) {
                LOGGER.error(LOG_TAG, "inputStream close error!");
            }
        }
    }

    /**
     * get Fields
     *
     * @param key    key
     * @return field
     */
    public static String get(@NotNull String key) {
        if (properties.size() == 0) {
            loadProperties();
        }
        return properties.getProperty(key);
    }

}
