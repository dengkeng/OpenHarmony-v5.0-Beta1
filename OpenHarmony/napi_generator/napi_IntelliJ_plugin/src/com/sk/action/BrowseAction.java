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

import com.intellij.notification.NotificationType;
import com.intellij.openapi.project.Project;
import com.sk.utils.FileUtil;
import com.sk.utils.GenNotification;
import org.apache.http.util.TextUtils;

import javax.swing.JButton;
import javax.swing.JTextField;
import javax.swing.JFileChooser;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.util.prefs.Preferences;

/**
 * 接口文件选择框。
 *
 * @author: xudong
 * @see: select file
 * @version: v1.0.0
 * @since 2022-02-21
 */
public class BrowseAction implements ActionListener {
    private final JButton button;
    private final JTextField interField;
    private final JTextField genField;
    private final JTextField scriptField;
    private final Project project;


    public BrowseAction(Project project, JButton button, JTextField interField,
                        JTextField geField, JTextField scriptField) {
        this.project = project;
        this.button = button;
        this.interField = interField;
        this.genField = geField;
        this.scriptField = scriptField;
    }

    @Override
    public void actionPerformed(ActionEvent actionEvent) {
        if (actionEvent.getSource().equals(button)) {
            Preferences preferences = Preferences.userRoot();
            // 弹窗默认路径为上次选中的文件/目录路径
            String tsFilePath = interField.getText().split(",")[0];
            if (tsFilePath.isBlank()) {
                // 如果上次选中路径为空，则取历史记录中上次打开的路径
                tsFilePath = preferences.get("interPathRecord", "");
            }
            JFileChooser fcDlg = new JFileChooser(tsFilePath);
            fcDlg.setDialogTitle("请选择接口文件...");
            fcDlg.setFileSelectionMode(JFileChooser.FILES_AND_DIRECTORIES);
            FileNameExtensionFilter filter = new FileNameExtensionFilter("文本文件(*.ts)", "ts");
            fcDlg.setMultiSelectionEnabled(true);
            fcDlg.setFileFilter(filter);
            int returnVal = fcDlg.showOpenDialog(null);
            if (returnVal == JFileChooser.APPROVE_OPTION) {
                String upPath = fcDlg.getSelectedFile().getParent();
                File[] files = fcDlg.getSelectedFiles();
                String interFile = setSelectFile(files);
                if (TextUtils.isBlank(interFile)) {
                    return;
                }

                // 设置默认打开路径；

                preferences.put("interPathRecord", upPath);
                interField.setText(interFile.substring(0, interFile.length() - 1));
                genField.setText(upPath);
                scriptField.setText(upPath);
            }
        }
    }

    private String setSelectFile(File[] files) {
        StringBuilder interFile = new StringBuilder();
        boolean existFile = false;
        boolean existDir = false;
        for (File file : files) {
            if (file.isDirectory()) {
                if (!existDir) {
                    existDir = true;
                    interFile.append(file.getPath()).append(",");
                } else {
                    GenNotification.notifyMessage(project,
                            "目前只支持单个文件夹转换",
                            "选择不符合要求",
                            NotificationType.WARNING);
                    interField.setText("");
                    return "";
                }
            } else {
                if (!FileUtil.patternFileName(file.getName())) {
                    GenNotification.notifyMessage(project,
                            file.getPath(),
                            file.getName() + "文件名不符合",
                            NotificationType.WARNING);
                    return "";
                }
                existFile = true;
                interFile.append(file.getPath()).append(",");
            }
        }
        if (existDir && existFile) {
            GenNotification.notifyMessage(project,
                    "不能同时转换文件和文件夹",
                    "选择不符合要求",
                    NotificationType.WARNING);
            interField.setText("");
            return "";
        }
        return interFile.toString();
    }
}
