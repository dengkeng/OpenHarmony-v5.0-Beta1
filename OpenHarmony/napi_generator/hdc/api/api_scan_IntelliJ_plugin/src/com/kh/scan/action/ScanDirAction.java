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
package com.kh.scan.action;

import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JTextField;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.prefs.Preferences;

/**
 * 编译文件夹选择框
 *
 * @author: zhaoxudong@kaihong.com
 * @see: select generator file path
 * @version: v1.0.0
 * @since 2022-10-14
 */
public class ScanDirAction implements ActionListener {
    private final JButton button;
    private final JTextField textField;
    private final JTextField outScanResultPathTextField;

    public ScanDirAction(JButton button, JTextField textField, JTextField outScanResultPathTextField) {
        this.button = button;
        this.textField = textField;
        this.outScanResultPathTextField = outScanResultPathTextField;
    }

    @Override
    public void actionPerformed(ActionEvent actionEvent) {
        if (actionEvent.getSource().equals(button)) {
            Preferences preferences = Preferences.userRoot();
            String filePath = textField.getText();
            if (filePath.isBlank()) {
                filePath = preferences.get("interPathRecord", "");
            }
            JFileChooser fcDlg = new JFileChooser(filePath);
            fcDlg.setDialogTitle("请选择扫描项目路径...");
            fcDlg.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
            int returnVal = fcDlg.showOpenDialog(null);
            if (returnVal == JFileChooser.APPROVE_OPTION) {
                String filepath = fcDlg.getSelectedFile().getPath();
                preferences.put("interPathRecord", filepath);
                textField.setText(filepath);
                outScanResultPathTextField.setText(filepath);
            }
        }
    }
}
