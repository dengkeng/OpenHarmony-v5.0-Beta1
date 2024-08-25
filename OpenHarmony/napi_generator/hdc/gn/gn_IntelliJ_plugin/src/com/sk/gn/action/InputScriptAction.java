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
package com.sk.gn.action;

import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JTextField;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;

/**
 * 选择脚本路径
 *
 * @author: zhaoxudong@kaihong.com
 * @see: select script path
 * @version: v1.0.0
 * @since 2022-09-21
 */
public class InputScriptAction implements ActionListener {
    private static final String SYS_NAME = System.getProperties().getProperty("os.name").toUpperCase();

    private final JButton button;
    private final JTextField textField;
    private final JComboBox comboBox;
    private final JTextField transplantTextField;

    public InputScriptAction(JButton button, JTextField textField, JComboBox comboBox, JTextField transplantTextField) {
        this.button = button;
        this.textField = textField;
        this.comboBox = comboBox;
        this.transplantTextField = transplantTextField;
    }

    @Override
    public void actionPerformed(ActionEvent actionEvent) {
        if (actionEvent.getSource().equals(button)) {
            JFileChooser fcDlg = new JFileChooser(textField.getText());
            fcDlg.setDialogTitle("请选择输入脚本路径...");
            fcDlg.setFileSelectionMode(JFileChooser.FILES_ONLY);
            int returnVal = fcDlg.showOpenDialog(null);
            if (returnVal == JFileChooser.APPROVE_OPTION) {
                String filepath = fcDlg.getSelectedFile().getPath();
                if (filepath.contains(File.separator)) {
                    textField.setText(filepath.substring(filepath.lastIndexOf("third_party")));
                    String parentFilePath = fcDlg.getSelectedFile().getParent();
                    if (SYS_NAME.contains("WIN")) {
                        transplantTextField.setText(parentFilePath.substring(parentFilePath.lastIndexOf("\\")));
                    } else {
                        transplantTextField.setText(filepath.substring(filepath.lastIndexOf("/")));
                    }
                } else {
                    textField.setText(filepath);
                    transplantTextField.setText(filepath);
                }
                if (filepath.contains("CMake")) {
                    comboBox.setSelectedIndex(1);
                } else if (filepath.contains("Make")) {
                    comboBox.setSelectedIndex(0);
                } else {
                    comboBox.setSelectedIndex(2);
                }
            }
        }
    }
}