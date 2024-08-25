/*
 * Copyright (c) 2022 Guangzhou Digitalchina Information Technology Co., Ltd.
 * All rights reserved.
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
package com.kh.scan.dialog;

import com.intellij.openapi.ui.DialogWrapper;
import org.jetbrains.annotations.Nullable;
import javax.swing.JComponent;

/**
 * 自定义确认对话框Wrapper
 *
 * @author: zhaoxudong@kaihong.com
 * @see: tool conversion plug-in
 * @version: v1.0.0
 * @since 2022-10-14
 */
public class ConfirmDialog extends DialogWrapper {
    private final ConfirmDiagPane confirmDiagPane;

    /**
     * 构造函数
     * @param message 弹出框信息内容
     */
    public ConfirmDialog(String message) {
        super(true);
        confirmDiagPane = new ConfirmDiagPane(message);
        setOKButtonText("Yes");
        setCancelButtonText("No");
        setUndecorated(true);
        setResizable(false);
        init();
    }

    @Override
    @Nullable
    protected JComponent createCenterPanel() {
        return confirmDiagPane.getContentPanel();
    }
}
