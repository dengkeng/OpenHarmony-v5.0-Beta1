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
package com.sk.dialog;

import com.intellij.openapi.diagnostic.Logger;

import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import javax.swing.KeyStroke;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;

/**
 * ErrorDialog错误对话框
 *
 * @author: xudong
 * @see: generator error dialog
 * @version: v1.0.0
 * @since 2022-02-21
 */
public class ErrorDialog extends JDialog {
    private static final Logger LOG = Logger.getInstance(ErrorDialog.class);
    private static final String URL =
            "rundll32 url.dll,FileProtocolHandler" + " https://gitee" + ".com/openharmony" + "-sig/napi_generator";

    private JPanel contentPane;
    private JButton buttonOK;
    private JButton buttonHelp;
    private JTextArea textAreaError;
    private String errorMessage;

    public ErrorDialog(String sErrorMessage) {
        errorMessage = sErrorMessage;
    }

    /**
     * 初始化
     */
    public void initDialog() {
        setContentPane(contentPane);
        setModal(true);
        getRootPane().setDefaultButton(buttonOK);
        setTitle("执行失败");
        textAreaError.setText(errorMessage);
        buttonOK.addActionListener(actionEvent -> onOK());

        buttonHelp.addActionListener(actionEvent -> onCancel());

        // call onCancel() when cross is clicked
        setDefaultCloseOperation(DO_NOTHING_ON_CLOSE);
        addWindowListener(new WindowAdapter() {
            /**
             * close dialog
             * @param windowEvent WindowEvent
             */
            @Override
            public void windowClosing(WindowEvent windowEvent) {
                onCancel();
            }
        });

        // call onCancel() on ESCAPE
        contentPane.registerKeyboardAction(actionEvent -> onCancel(),
                KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
                JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT);
    }

    private void onOK() {
        dispose();
    }

    private void onCancel() {
        try {
            Runtime.getRuntime().exec(URL);
        } catch (IOException ioException) {
            LOG.error("exec command help error" + ioException);
        }
        dispose();
    }
}