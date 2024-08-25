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
import javax.swing.JFileChooser;
import javax.swing.JTextField;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;

/**
 * 选择输出路径
 *
 * @author: zhaoxudong@kaihong.com
 * @see: select out path
 * @version: v1.0.0
 * @since 2022-09-21
 */
public class SelectOutDirAction implements ActionListener {
    private static final String SYS_NAME = System.getProperties().getProperty("os.name").toUpperCase();

    private final JButton button;
    private final JTextField textField;
    private SelectPathInterface selectPathInterface;

    /**
     * 构造函数
     *
     * @param button    按钮
     * @param textField 输入框
     * @param selectPathInterface 接口
     */
    public SelectOutDirAction(JButton button, JTextField textField, SelectPathInterface selectPathInterface) {
        this.button = button;
        this.textField = textField;
        this.selectPathInterface = selectPathInterface;
        if (SYS_NAME.contains("WIN")) {
            textField.setText("out\\rk3568");
        }
    }

    @Override
    public void actionPerformed(ActionEvent actionEvent) {
        if (actionEvent.getSource().equals(button)) {
            JFileChooser fcDlg = new JFileChooser(textField.getText());
            fcDlg.setDialogTitle("请选择输出路径...");
            fcDlg.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
            int returnVal = fcDlg.showOpenDialog(null);
            if (returnVal == JFileChooser.APPROVE_OPTION) {
                String filepath = fcDlg.getSelectedFile().getPath();
                selectPathInterface.getFilePath(fcDlg.getSelectedFile());
                String fieldShowPath;
                if (filepath.contains(File.separator)) {
                    String path = filepath.substring(0, filepath.lastIndexOf(File.separator));
                    if (path.contains(File.separator)) {
                        fieldShowPath = filepath.substring(path.lastIndexOf(File.separator) + 1);
                    } else {
                        fieldShowPath = filepath.substring(filepath.lastIndexOf(File.separator) + 1);
                    }
                } else {
                    fieldShowPath = filepath;
                }
                if (SYS_NAME.contains("WIN")) {
                    textField.setText(fieldShowPath.replaceAll("/", "\""));
                } else {
                    textField.setText(fieldShowPath);
                }
            }
        }
    }

    /**
     * 文件选择接口
     */
    public interface SelectPathInterface {
        /**
         * 选择文件路径
         *
         * @param pathFile 文件路径
         */
        void getFilePath(File pathFile);
    }
}
