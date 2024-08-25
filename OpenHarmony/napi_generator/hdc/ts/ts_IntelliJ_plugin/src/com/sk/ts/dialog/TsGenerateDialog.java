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
package com.sk.ts.dialog;

import com.intellij.openapi.diagnostic.Logger;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.ui.DialogWrapper;
import com.intellij.openapi.ui.ValidationInfo;
import com.sk.ts.dialog.GenerateDialogPane;
import org.jetbrains.annotations.Nullable;

import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JComponent;
import java.awt.Desktop;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.Dimension;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

import com.sk.dialog.GenerateDialog;

/**
 * 主界面对话框Wrapper
 *
 * @author: xudong
 * @see: tool conversion plug-in
 * @version: v1.0.0
 * @since 2022-05-27
 */
public class TsGenerateDialog extends DialogWrapper {
    private static final Logger LOG = Logger.getInstance(TsGenerateDialog.class);
    private static final String FRAME_TITLE = "Generate Ts Frame";
    private static final String CODE_URL = "https://gitee.com/openharmony/napi_generator";

    JButton buttonHelp = new JButton("Help");
    JButton buttonOK = new JButton("OK");
    JButton buttonCancel = new JButton("Cancel");
    private boolean IS_SELECTED = false;
    private GenerateDialogPane genDiag;

    /**
     * 构造函数
     *
     * @param project                  projectId
     * @param destPath                 目录文件
     * @param directoryPath            文件夹目录
     * @param fileName                 文件名
     * @param isSelectedToolchain      是否启用工具链
     */
    public TsGenerateDialog(Project project, String destPath, String directoryPath,
                            String fileName, boolean isSelectedToolchain) {
        super(true);
        this.setResizable(false);
        setTitle(FRAME_TITLE);
        setModal(true);
        genDiag = new GenerateDialogPane(project, destPath, directoryPath, fileName);
        IS_SELECTED = isSelectedToolchain;
        if (isSelectedToolchain) {
            buttonOK.setText("Next");
        } else {
            buttonOK.setText("OK");
        }
        init();
    }

    @Override
    protected void init() {
        super.init();
        getOKAction().setEnabled(false);
        getButton(getOKAction()).setVisible(false);
        getButton(getCancelAction()).setVisible(false);
    }

    /**
     * 创建视图
     *
     * @return 组件内容
     */
    @Nullable
    @Override
    protected JComponent createCenterPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        JPanel northPanel = new JPanel(new BorderLayout());
        northPanel.setPreferredSize(new Dimension(800, 350));
        northPanel.add(genDiag.getContentPanel());
        JPanel southPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        southPanel.setPreferredSize(new Dimension(800, 50));
        JPanel southWestPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        southWestPanel.setPreferredSize(new Dimension(390, 50));
        southWestPanel.add(buttonHelp);
        buttonHelpListener();
        JPanel southEastPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        southEastPanel.setPreferredSize(new Dimension(390, 50));
        southEastPanel.add(buttonCancel);
        buttonCancelListener();
        southEastPanel.add(buttonOK);
        buttonOKListener();
        southPanel.add(southWestPanel);
        southPanel.add(southEastPanel);
        panel.add(northPanel, BorderLayout.NORTH);
        panel.add(southPanel, BorderLayout.SOUTH);
        panel.repaint();
        return panel;
    }

    /**
     * 校验数据
     *
     * @return 检测文本框架是否有目录。
     */
    @Nullable
    @Override
    protected ValidationInfo doValidate() {
        return genDiag.validationInfo();
    }

    /**
     * help button监听事件
     * @param void 空
     * @return void 空
     * @throws log 输出异常
     */
    public void buttonHelpListener() {
        buttonHelp.addActionListener(e -> {
            try {
                Desktop.getDesktop().browse(new URI(CODE_URL));
            } catch (URISyntaxException | IOException e2) {
                LOG.error("Open help error:" + e2);
            }
        });
    }

    /**
     * cancel button监听事件
     *
     * @param void 空
     * @return void 空
     * @throws log 输出异常
     */
    public void buttonCancelListener() {
        buttonCancel.addActionListener(e -> {
            close(CANCEL_EXIT_CODE);
        });
    }

    /**
     * OK button监听事件
     * @param void 空
     * @return void 空
     * @throws log 输出异常
     */
    public void buttonOKListener() {
        buttonOK.addActionListener(e -> {
            ValidationInfo validationInfo = doValidate();
            if (validationInfo != null) {
                LOG.info(validationInfo.message);
            } else {
                if (genDiag.runFunH2ts()) {
                    if (IS_SELECTED) {
                        Project project = genDiag.getProject();
                        String destPath = genDiag.getTsFileName();
                        String directoryPath = genDiag.getTsOutPath();
                        String fileName = genDiag.getTsOutPath();
                        GenerateDialog generateDialog = new GenerateDialog(project, destPath, directoryPath, fileName);
                        generateDialog.showAndGet();
                    } else {
                        close(CANCEL_EXIT_CODE);
                    }
                }
            }
        });
    }
}

