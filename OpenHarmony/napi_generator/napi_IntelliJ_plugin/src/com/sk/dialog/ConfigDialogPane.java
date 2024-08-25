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

import com.intellij.notification.NotificationType;
import com.intellij.openapi.ui.ValidationInfo;
import com.sk.action.SelectCppAction;
import com.sk.action.SelectHAction;
import com.sk.utils.Data;
import com.sk.utils.DataList;
import com.sk.utils.GenNotification;
import org.apache.http.util.TextUtils;
import org.jetbrains.annotations.Nullable;

import javax.swing.JDialog;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.JComponent;
import javax.swing.KeyStroke;
import javax.swing.JButton;
import java.awt.event.KeyEvent;
import java.util.ArrayList;

/**
 * ConfigDialog 配置文件对话框
 *
 * @author: goujingjing
 * @see: generator config dialog
 * @version: v1.0.3
 * @since 2023-12-14
 */
public class ConfigDialogPane extends JDialog {
    private JPanel contentPane;
    private JTextField textFieldIncludeName;
    private JTextField textFieldCppName;
    private JTextField textFieldInterName;
    private JTextField textFieldServiceCode;
    private JButton buttonIncludeName;
    private JButton buttonCppName;
    private JTextField textFieldRootPath;
    private DataList list = new DataList(new ArrayList<>());
    private int index;
    private String genPath;

    /**
     * 构造函数
     * @param list  配置文件数据列表
     * @param index  用户选择的列表行索引
     * @param data   用户选择的列表行数据
     * @param genPath  生成框架路径
     * @throws log 输出异常
     */
    public ConfigDialogPane(DataList list, int index, Data data, String genPath) {
        this.list = list;
        this.index = index;
        this.genPath = genPath;
        textFieldRootPath.setText(genPath);
        textFieldRootPath.setEditable(false);
        if (data != null) {
            textFieldIncludeName.setText(data.getIncludeName());
            textFieldCppName.setText(data.getCppName());
            textFieldInterName.setText(data.getCppName());
            textFieldServiceCode.setText(data.getServiceCode());
        } else {
            textFieldIncludeName.setText("");
            textFieldCppName.setText("");
            textFieldInterName.setText("");
            textFieldServiceCode.setText("");
        }
        buttonIncludeName.addActionListener(new SelectHAction(buttonIncludeName, textFieldIncludeName,
                genPath));
        buttonCppName.addActionListener(new SelectCppAction(buttonCppName, textFieldCppName,
                genPath));

        setContentPane(contentPane);
        setModal(true);
        contentPane.registerKeyboardAction(actionEvent -> onCancel(), KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
                JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT);
    }

    /**
     * 修改dataList数据，将用户输入的文本选择框数据存入dataList列表
     *
     */
    public void modifyDataInfo() {
        String includeNameText = textFieldIncludeName.getText();
        String cppNameText = textFieldCppName.getText();
        String interNameText = textFieldInterName.getText();
        String serviceCodeText = textFieldServiceCode.getText();
        Data data = new Data(genPath, includeNameText, cppNameText, interNameText, serviceCodeText);
        list.modifyDataListInfo(index, data);
    }

    /**
     * 将用户输入的文本选择框数据存入dataList列表
     * @param void 空
     * @throws log 输出异常
     */
    public void setDataInfo() {
        String includeNameText = textFieldIncludeName.getText();
        String cppNameText = textFieldCppName.getText();
        String interNameText = textFieldInterName.getText();
        String serviceCodeText = textFieldServiceCode.getText();
        Data data = new Data(genPath, includeNameText, cppNameText, interNameText, serviceCodeText);
        list.addDataListInfo(data);
    }

    /**
     * 验证文本选择框是否空。是否替换已存在的内容
     * @param void 空
     * @return ValidationInfo 返回不符要求的信息。
     * @throws log 输出异常
     */
    @Nullable
    public ValidationInfo validationInfo() {
        ValidationInfo validationInfo = null;
        String includeNameText = textFieldIncludeName.getText();
        String cppNameText = textFieldCppName.getText();
        String interNameText = textFieldInterName.getText();
        String serviceCodeText = textFieldServiceCode.getText();
        boolean isEmptyFile =
                TextUtils.isEmpty(includeNameText) || TextUtils.isEmpty(cppNameText) || TextUtils.isEmpty(interNameText)
                || TextUtils.isEmpty(serviceCodeText);
        if (isEmptyFile) {
            String warnMsg = "业务代码配置不能为空";
            warningMessage(warnMsg);
            validationInfo = new ValidationInfo(warnMsg);
            return validationInfo;
        }
        return validationInfo;
    }

    private void onCancel() {
        dispose();
    }

    private void warningMessage(String title) {
        String notifyContent = "请配置业务代码";
        GenNotification.notifyMessage(null, notifyContent, title, NotificationType.WARNING);
    }

    JPanel getContentPanel() {
        return contentPane;
    }
}