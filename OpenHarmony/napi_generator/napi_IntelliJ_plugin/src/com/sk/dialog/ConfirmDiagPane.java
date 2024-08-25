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
package com.sk.dialog;

import javax.swing.JPanel;
import javax.swing.JLabel;
import javax.swing.JDialog;
import javax.swing.ImageIcon;

/**
 * ConfirmDiagPane自定义确认对话框
 * 解决ShowConfirmDiag 在Deveco里面会出现界面错位问题。
 *
 * @author: xudong
 * @see: generator error dialog
 * @version: v1.0.0
 * @since 2022-02-21
 */
public class ConfirmDiagPane extends JDialog {
    private JPanel contentPane;
    private JLabel msgLabel;
    private JLabel iconLabel;

    /**
     * 构造函数
     *
     * @param sErrorMessage 错误信息
     */
    public ConfirmDiagPane(String sErrorMessage) {
        msgLabel.setText(sErrorMessage);
        iconLabel.setIcon(new ImageIcon(""));
    }


    JPanel getContentPanel() {
        return contentPane;
    }
}
