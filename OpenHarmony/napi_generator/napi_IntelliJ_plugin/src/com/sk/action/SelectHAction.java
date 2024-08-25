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

import com.sk.utils.FileUtil;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JTextField;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.prefs.Preferences;

/**
 * 脚本选择对话框
 *
 * @author: goujingjing
 * @see: select h filepath
 * @version: v1.0.3
 * @since 2023-12-20
 */
public class SelectHAction implements ActionListener {
    private final JButton button;
    private final JTextField textField;
    private String genPath;

    /**
     * 构造函数
     * @param button .h文件选择按钮
     * @param textField .h文件文本选择框
     * @param genPath 生成框架路径
     * @throws log 输出异常
     */
    public SelectHAction(JButton button, JTextField textField, String genPath) {
        this.button = button;
        this.textField = textField;
        this.genPath = genPath;
    }

    /**
     * 按钮监听函数
     * @param actionEvent .h文件选择事件
     * @throws log 输出异常
     */
    @Override
    public void actionPerformed(ActionEvent actionEvent) {
        if (actionEvent.getSource().equals(button)) {
            Preferences preferences = Preferences.userRoot();
            // 弹窗默认路径为上次选中的文件/目录路径
            String hFilePath = textField.getText();
            if (hFilePath.isBlank()) {
                // 如果上次选中路径为空，则取历史记录中上次打开的路径
                hFilePath = preferences.get("hPathRecord", "");
            }
            JFileChooser fcDlg = new JFileChooser(hFilePath);
            fcDlg.setDialogTitle("请选择includeName路径...");
            fcDlg.setFileSelectionMode(JFileChooser.FILES_ONLY);
            FileNameExtensionFilter filter = new FileNameExtensionFilter("h文件(*.h, *.hpp, *.hxx)", "h", "hpp", "hxx");
            fcDlg.setMultiSelectionEnabled(false);
            fcDlg.setFileFilter(filter);
            int returnVal = fcDlg.showOpenDialog(null);
            if (returnVal == JFileChooser.APPROVE_OPTION) {
                String filepath = fcDlg.getSelectedFile().getPath();
                preferences.put("hPathRecord", filepath);
                FileUtil fileUtil = new FileUtil();
                String relativeIncludeName = fileUtil.getRelativePath(filepath, genPath);
                relativeIncludeName = relativeIncludeName.substring(0, relativeIncludeName.length() - 1);
                textField.setText(relativeIncludeName);
            }
        }
    }
}