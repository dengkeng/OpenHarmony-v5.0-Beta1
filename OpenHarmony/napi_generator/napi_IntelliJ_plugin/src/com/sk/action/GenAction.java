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
package com.sk.action;

import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JTextField;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

/**
 * 编译文件夹选择框
 *
 * @author: xudong
 * @see: select generator file path
 * @version: v1.0.0
 * @since 2022-02-21
 */
public class GenAction implements ActionListener {
    private final JButton button;
    private final JTextField textField;

    public GenAction(JButton button, JTextField textField) {
        this.button = button;
        this.textField = textField;
    }

    @Override
    public void actionPerformed(ActionEvent actionEvent) {
        if (actionEvent.getSource().equals(button)) {
            JFileChooser fcDlg = new JFileChooser(textField.getText());
            fcDlg.setDialogTitle("请选择生成框架路径...");
            fcDlg.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
            int returnVal = fcDlg.showOpenDialog(null);
            if (returnVal == JFileChooser.APPROVE_OPTION) {
                String filepath = fcDlg.getSelectedFile().getPath();
                textField.setText(filepath);
            }
        }
    }
}
