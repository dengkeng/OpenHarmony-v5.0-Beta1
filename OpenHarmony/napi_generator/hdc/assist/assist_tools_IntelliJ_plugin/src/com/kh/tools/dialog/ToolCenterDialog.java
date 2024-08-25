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
package com.kh.tools.dialog;

import com.intellij.openapi.diagnostic.Logger;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.ui.DialogWrapper;
import com.kh.tools.utils.PluginUtils;
import com.sk.dialog.GenerateDialog;
import com.sk.ts.dialog.TsGenerateDialog;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import javax.swing.Action;
import javax.swing.JComponent;
import javax.swing.JOptionPane;
import java.awt.Desktop;
import java.awt.event.ActionEvent;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

/**
 * 自定义确认对话框Wrapper
 *
 * @author: zhaoxudong@kaihong.com
 * @see: tool conversion plug-in
 * @version: v1.0.0
 * @since 2022-09-10
 */
public class ToolCenterDialog extends DialogWrapper {
    private static final Logger LOG = Logger.getInstance(ToolCenterDialog.class);

    private final ToolCenterPanel toolCenterPanel;
    private Project project;

    /**
     * 构造函数
     * @param project Project
     */
    public ToolCenterDialog(Project project) {
        super(true);
        this.project = project;
        toolCenterPanel = new ToolCenterPanel();
        setTitle(PluginUtils.TITLE);
        init();
    }

    @Override
    @Nullable
    protected JComponent createCenterPanel() {
        return toolCenterPanel.getContentPanel();
    }

    /**
     * ok/cancel按钮
     *
     * @return Action[] buttos list
     */
    @NotNull
    @Override
    protected Action[] createActions() {
        DialogWrapperExitAction exitAction = new DialogWrapperExitAction("Cancel", CANCEL_EXIT_CODE);
        ToolCenterDialog.CustomOKAction okAction = new ToolCenterDialog.CustomOKAction();
        okAction.putValue(DialogWrapper.DEFAULT_ACTION, true);
        return new Action[]{exitAction, okAction};
    }

    @NotNull
    @Override
    protected Action[] createLeftSideActions() {
        ToolCenterDialog.CustomHelpAction helpAction = new ToolCenterDialog.CustomHelpAction();
        return new Action[]{helpAction};
    }

    /**
     * 自定义 next Action
     */
    protected class CustomOKAction extends DialogWrapperAction {

        protected CustomOKAction() {
            super("Next");
        }

        @Override
        protected void doAction(ActionEvent actionEvent) {
            if (toolCenterPanel.isSelectButton().equals("Napi")) {
                GenerateDialog generateDialog = new GenerateDialog(project, "", "", "");
                generateDialog.showAndGet();
            }
            else if (toolCenterPanel.isSelectButton().equals("H2Ts")) {
                if (toolCenterPanel.getSelectToolChain()) {
                    if (toolCenterPanel.getSelectNapiCheckBox() && toolCenterPanel.getSelectH2tsCheckBox()) {
                        TsGenerateDialog tsGenerateDialog = new TsGenerateDialog(project, "", "", "", true);
                        tsGenerateDialog.showAndGet();
                    } else {
                        JOptionPane.showMessageDialog(null, "启用工具链应至少选择两个工具！",
                                "提示", JOptionPane.INFORMATION_MESSAGE);
                    }
                } else {
                    TsGenerateDialog tsGenerateDialog = new TsGenerateDialog(project, "", "", "", false);
                    tsGenerateDialog.showAndGet();
                }
            }
            else {
                LOG.error("action is not exit");
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
                Desktop.getDesktop().browse(new URI(PluginUtils.URL));
            } catch (URISyntaxException | IOException e) {
                LOG.error("Open help error:" + e);
            }
        }
    }
}
