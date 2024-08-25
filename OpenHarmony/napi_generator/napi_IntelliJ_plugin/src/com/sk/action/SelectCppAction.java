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
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.prefs.Preferences;
import com.sk.utils.FileUtil;

/**
 * 脚本选择对话框
 *
 * @author: goujingjing
 * @see: select cpp filepath
 * @version: v1.0.3
 * @since 2023-12-20
 */
public class SelectCppAction implements ActionListener {
    private final JButton button;
    private final JTextField textField;
    private String genPath;

    /**
     * 构造函数
     * @param button .cpp文件选择按钮
     * @param textField .cpp文件文本选择框
     * @param genPath 生成框架路径
     * @throws log 输出异常
     */
    public SelectCppAction(JButton button, JTextField textField, String genPath) {
        this.button = button;
        this.textField = textField;
        this.genPath = genPath;
    }

    /**
     * 按钮监听函数
     * @param actionEvent .cpp文件选择事件
     * @throws log 输出异常
     */
    @Override
    public void actionPerformed(ActionEvent actionEvent) {
        if (actionEvent.getSource().equals(button)) {
            Preferences preferences = Preferences.userRoot();
            // 弹窗默认路径为上次选中的文件/目录路径
            String cppFilePath = textField.getText();
            if (cppFilePath.isBlank()) {
                // 如果上次选中路径为空，则取历史记录中上次打开的路径
                cppFilePath = preferences.get("cppPathRecord", "");
            }
            JFileChooser fcDlg = new JFileChooser(cppFilePath);
            fcDlg.setDialogTitle("请选择cppName路径...");
            fcDlg.setFileSelectionMode(JFileChooser.FILES_ONLY);
            FileNameExtensionFilter filter = new FileNameExtensionFilter("cpp文件(*.cpp, *.cc, *.C, *.cxx, *.c++)",
                    "cpp", "cc", "C", "cxx", "c++");
            fcDlg.setMultiSelectionEnabled(false);
            fcDlg.setFileFilter(filter);
            int returnVal = fcDlg.showOpenDialog(null);
            if (returnVal == JFileChooser.APPROVE_OPTION) {
                String filepath = fcDlg.getSelectedFile().getPath();
                preferences.put("cppPathRecord", filepath);
                FileUtil fileUtil = new FileUtil();
                String relativeCppName = fileUtil.getRelativePath(filepath, genPath);
                relativeCppName = relativeCppName.substring(0, relativeCppName.length() - 1);
                textField.setText(relativeCppName);
            }
        }
    }
}