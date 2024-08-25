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
import com.intellij.openapi.ui.ValidationInfo;
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
public class ConfigDialog extends DialogWrapper {
    private static final Logger LOG = Logger.getInstance(GenerateDialog.class);
    private static final String FRAME_TITLE = "Config";
    private static final String CODE_URL =
            "https://gitee.com/openharmony/napi_generator/blob/master/docs/INSTRUCTION_ZH.md";

    private DataList list = null;
    private final ConfigDialogPane genDiag;
    private boolean isAddFlag;
    private String genPath;

    /**
     * 构造函数
     * @param list   配置文件数据列表
     * @param index  用户选择的列表行索引
     * @param data   用户选择的列表行数据
     * @param isAddFlag  增加数据或者修改数据的标志位
     * @param genPath  生成框架路径
     * @throws log 输出异常
     */
    public ConfigDialog(DataList list, int index, Data data, boolean isAddFlag, String genPath) {
        super(true);
        this.setResizable(false);
        this.list = list;
        this.isAddFlag = isAddFlag;
        this.genPath = genPath;
        setTitle(FRAME_TITLE);
        setModal(true);
        genDiag = new ConfigDialogPane(list, index, data, genPath);
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
     * @return 错误信息 检测用户是否填入配置信息。
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
        CustomOkAction okAction = new CustomOkAction();

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
    protected class CustomOkAction extends DialogWrapperAction {

        protected CustomOkAction() {
            super("OK");
        }

        @Override
        protected void doAction(ActionEvent actionEvent) {
            ValidationInfo validationInfo = doValidate();
            if (validationInfo != null) {
                LOG.info(validationInfo.message);
            } else {
                if (isAddFlag) {
                    // 增加数据
                    genDiag.setDataInfo();
                    close(CANCEL_EXIT_CODE);
                    ShowCfgInfoDialog showCfgInfoDialog = new ShowCfgInfoDialog(list, genPath);
                    showCfgInfoDialog.showAndGet();
                } else {
                    // 修改数据
                    genDiag.modifyDataInfo();
                    close(CANCEL_EXIT_CODE);
                    ShowCfgInfoDialog showCfgInfoDialog = new ShowCfgInfoDialog(list, genPath);
                    showCfgInfoDialog.showAndGet();
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
