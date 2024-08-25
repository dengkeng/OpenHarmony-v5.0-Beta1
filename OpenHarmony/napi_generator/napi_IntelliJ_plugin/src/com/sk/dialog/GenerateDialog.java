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
package com.sk.dialog;

import com.intellij.openapi.diagnostic.Logger;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.ui.DialogWrapper;
import com.intellij.openapi.ui.ValidationInfo;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import javax.swing.Action;
import javax.swing.JComponent;
import java.awt.Desktop;
import java.awt.event.ActionEvent;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

/**
 * 主界面对话框Wrapper
 *
 * @author: xudong
 * @see: tool conversion plug-in
 * @version: v1.0.0
 * @since 2022-05-27
 */
public class GenerateDialog extends DialogWrapper {
    private static final Logger LOG = Logger.getInstance(GenerateDialog.class);
    private static final String FRAME_TITLE = "Generate Napi Frame";
    private static final String CODE_URL = "https://gitee.com/openharmony/napi_generator";

    private final GenerateDialogPane genDiag;

    /**
     * 构造函数
     *
     * @param project       projectId
     * @param destPath      目录文件
     * @param directoryPath 文件夹目录
     * @param fileName      文件名
     * @throws log 输出异常
     */
    public GenerateDialog(Project project, String destPath, String directoryPath, String fileName) {
        super(true);
        this.setResizable(false);
        setTitle(FRAME_TITLE);
        setModal(true);
        genDiag = new GenerateDialogPane(project, destPath, directoryPath, fileName);
        init();
    }

    /**
     * 创建视图
     * @param void 空
     * @return 组件内容
     * @throws log 输出异常
     */
    @Nullable
    @Override
    protected JComponent createCenterPanel() {
        return genDiag.getContentPanel();
    }


    /**
     * 校验数据
     * @param void 空
     * @return 检测文本框架是否有目录。
     * @throws log 输出异常
     */
    @Nullable
    @Override
    protected ValidationInfo doValidate() {
        return genDiag.validationInfo();
    }

    /**
     * ok/cancel按钮
     * @param void 空
     * @return Action[] buttons list
     * @throws log 输出异常
     */
    @NotNull
    @Override
    protected Action[] createActions() {
        DialogWrapperExitAction exitAction = new DialogWrapperExitAction("Cancel", CANCEL_EXIT_CODE);
        CustomOKAction okAction = new CustomOKAction();

        // 设置默认的焦点按钮
        okAction.putValue(DialogWrapper.DEFAULT_ACTION, true);
        return new Action[]{exitAction, okAction};
    }

    /**
     * help 按钮
     * @param void 空
     * @return Action[] button helpAction
     * @throws log 输出异常
     */
    @NotNull
    @Override
    protected Action[] createLeftSideActions() {
        CustomHelpAction helpAction = new CustomHelpAction();
        return new Action[]{helpAction};
    }

    /**
     * 自定义 ok Action
     */
    protected class CustomOKAction extends DialogWrapperAction {

        protected CustomOKAction() {
            super("OK");
        }

        @Override
        protected void doAction(ActionEvent actionEvent) {
            ValidationInfo validationInfo = doValidate();
            if (validationInfo != null) {
                LOG.info(validationInfo.message);
            } else {
                if (genDiag.runFun()) {
                    close(CANCEL_EXIT_CODE);
                }
            }
        }
    }

    /**
     * 自定义 help Action
     */
    protected class CustomHelpAction extends DialogWrapperAction {

        protected CustomHelpAction() {
            super("Help");
        }

        @Override
        protected void doAction(ActionEvent actionEvent) {
            try {
                Desktop.getDesktop().browse(new URI(CODE_URL));
            } catch (URISyntaxException | IOException e) {
                LOG.error("Open help error:" + e);
            }
        }
    }
}
