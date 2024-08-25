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
package com.kh.tools.utils;

import javax.swing.BorderFactory;
import javax.swing.border.Border;
import java.awt.Color;
import java.util.HashMap;

/**
 * 工具类
 *
 * @author: zhaoxudong@kaihong.com
 * @see: tool conversion plug-in
 * @version: v1.0.0
 * @since 2022-09-19
 */
public class PluginUtils {

    /**
     * 项目代码路径
     */
    public static final String URL = "https://gitee.com/openharmony/napi_generator/"
            + "tree/master/hdc/assist/assist_tools_IntelliJ_plugin/README.md";

    /**
     * 应用名称
     */
    public static final String TITLE = "Kaihong Assist Tools";

    /**
     * 获取焦点色值
     */
    public static final Border BORDER_FOCUS_GAINED = BorderFactory.createLineBorder(Color.decode("#385584"), 2);

    /**
     * 默认色值
     */
    public static final Border BORDER_FOCUS_LOST_SEARCH = BorderFactory.createLineBorder(Color.decode("#646567"), 2);

    /**
     * 工具描述
     */
    public static final HashMap<String, String> TOOLS = new HashMap<String, String>() {
        {
            put("NAPI Generator", "NAPI tool generates NAPI framework code by typescript file.");
            put("H2Ts Generator", "H2Ts tool generates ts framework code by .h file");
        }
    };
}
