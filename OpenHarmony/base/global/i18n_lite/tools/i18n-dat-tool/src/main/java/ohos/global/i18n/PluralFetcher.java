/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

package ohos.global.i18n;

import java.util.HashMap;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.File;
import java.io.FileInputStream;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.logging.Logger;
import java.util.logging.Level;

/**
 * This class is used to extract plural data related to a locale
 *
 * @since 2022-8-22
 */
public class PluralFetcher {
    private static PluralFetcher plural = new PluralFetcher();
    private static final Logger logger = Logger.getLogger("PluralFetcher");

    static {
        plural.init();
    }

    private HashMap<String, String> map;
    private HashMap<String, String> decimalMap;

    private PluralFetcher() {}

    /**
     * Return the singleton instance
     *
     * @return plural
     */
    public static PluralFetcher getInstance() {
        return plural;
    }

    private void init() {
        try (BufferedReader fin = new BufferedReader(new InputStreamReader(new FileInputStream(
                new File(MeasureFormatPatternFetcher.class.getResource("/resource/plural.txt").toURI())),
                StandardCharsets.UTF_8))) {
            map = new HashMap<>();
            String line = "";
            while ((line = fin.readLine()) != null) {
                String[] temp = getPluralItems(line);
                map.put(temp[0], temp[1]);
            }
        } catch (IOException | URISyntaxException e) {
            logger.log(Level.SEVERE, "Init error");
        }
        try (BufferedReader fin = new BufferedReader(new InputStreamReader(new FileInputStream(
                new File(MeasureFormatPatternFetcher.class.getResource("/resource/decimalPlurals.txt").toURI())),
                StandardCharsets.UTF_8))) {
            decimalMap = new HashMap<>();
            String line = "";
            while ((line = fin.readLine()) != null) {
                String[] temp = getPluralItems(line);
                decimalMap.put(temp[0], temp[1]);
            }
        } catch (IOException | URISyntaxException e) {
            logger.log(Level.SEVERE, "Init error");
        }
    }

    /**
     * Get plural data related to lan
     *
     * @param lan Indicates which language's data to be retrieved
     * @return Language related to this PluralFetcher instance
     */
    public String get(String lan) {
        String out = map.get(lan);
        if (out == null) {
            out = "";
        }
        return out;
    }

    /**
     * Get plural data related to lan
     *
     * @param lan Indicates which language's data to be retrieved
     * @return Language related to this PluralFetcher instance
     */
    public String getDecimal(String lan) {
        String out = decimalMap.get(lan);
        if (out == null) {
            out = "";
        }
        return out;
    }

    private static String[] getPluralItems(String line) {
        String[] ret = new String[2];
        String trimedLine = line.trim();
        String[] splits = trimedLine.split(" ", 2); // Split into 2 parts
        if (splits.length != 2) {
            logger.log(Level.SEVERE, "Init error");
            return new String[0];
        }
        String languageTag = splits[0];
        if (!languageTag.contains("-")) {
            ret[0] = languageTag;
        } else {
            String[] tags = languageTag.split("-");
            ret[0] = tags[0];
        }
        String[] resources = splits[1].split(", ");
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < resources.length; ++i) {
            if (resources[i].length() > 2) { // 2 means skip ""
                int length = resources[i].length();
                sb.append(resources[i].substring(1, length - 1));
            }
            if (i != resources.length) {
                sb.append(FileConfig.SEP);
            }
        }
        ret[1] = sb.toString();
        return ret;
    }
}
