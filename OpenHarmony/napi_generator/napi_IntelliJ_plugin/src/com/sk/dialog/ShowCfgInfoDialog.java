/*
 * Copyright (c) 2023 Shenzhen Kaihong Digital Industry Development Co., Ltd.
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
package com.sk.dialog;

import com.intellij.openapi.diagnostic.Logger;
import com.intellij.openapi.ui.DialogWrapper;
import com.sk.utils.Data;
import com.sk.utils.DataList;
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
 * 配置config文件对话框Wrapper
 *
 * @author: goujingjing
 * @see: tool conversion plug-in
 * @version: v1.0.3
 * @since 2023-12-14
 */
public class ShowCfgInfoDialog extends DialogWrapper {
    private static final Logger LOG = Logger.getInstance(GenerateDialog.class);
    private static final String FRAME_TITLE = "Config";
    private static final String CODE_URL =
            "https://gitee.com/openharmony/napi_generator/blob/master/docs/INSTRUCTION_ZH.md";

    private final ShowCfgInfoDialogPane genDiag;
    private DataList list = null;
    private String genPath;

    /**
     * 构造函数
     * @param list  配置文件数据列表
     * @param genPath  生成框架文件路径
     * @throws log 输出异常
     */
    public ShowCfgInfoDialog(DataList list, String genPath) {
        super(true);
        this.setResizable(false);
        this.list = list;
        this.genPath = genPath;
        setTitle(FRAME_TITLE);
        setModal(true);
        genDiag = new ShowCfgInfoDialogPane(list, genPath);
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
     * ok/cancel按钮
     * @param void 空
     * @return Action[] buttons list
     * @throws log 输出异常
     */
    @NotNull
    @Override
    protected Action[] createActions() {
        DialogWrapperExitAction exitAction = new DialogWrapperExitAction("Cancel", CANCEL_EXIT_CODE);
        CustomOkAction okAction = new CustomOkAction();
        CustomDelAction delAction = new CustomDelAction();
        CustomUpdateAction updateAction = new CustomUpdateAction();

        return new Action[]{exitAction, okAction, delAction, updateAction};
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
     * 自定义 ok Action 增加配置数据
     */
    protected class CustomOkAction extends DialogWrapperAction {

        protected CustomOkAction() {
            super("Add");
        }

        @Override
        protected void doAction(ActionEvent actionEvent) {
            close(CANCEL_EXIT_CODE);
            ConfigDialog cfgDialog = new ConfigDialog(list, 0, null, true, genPath);
            cfgDialog.showAndGet();
        }
    }

    /**
     * 自定义 Delete Action 增加配置数据
     */
    protected class CustomDelAction extends DialogWrapperAction {

        protected CustomDelAction() {
            super("Delete");
        }

        @Override
        protected void doAction(ActionEvent actionEvent) {
            close(CANCEL_EXIT_CODE);
            int index = genDiag.getSelectedIndex();
            list.deleteDataListInfo(index);
            ShowCfgInfoDialog showCfgInfoDialog = new ShowCfgInfoDialog(list, genPath);
            showCfgInfoDialog.showAndGet();
        }
    }

    /**
     * 自定义 Update Action 增加配置数据
     */
    protected class CustomUpdateAction extends DialogWrapperAction {

        protected CustomUpdateAction() {
            super("Update");
        }

        @Override
        protected void doAction(ActionEvent actionEvent) {
            close(CANCEL_EXIT_CODE);
            int index = genDiag.getSelectedIndex();
            Data data = genDiag.getSelectedData();
            ConfigDialog cfgDialog = new ConfigDialog(list, index, data, false, genPath);
            cfgDialog.showAndGet();
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
