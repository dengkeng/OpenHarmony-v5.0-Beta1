/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

package com.update.check.action.view;

import com.intellij.openapi.project.Project;
import com.intellij.openapi.ui.MessageDialogBuilder;
import com.intellij.openapi.ui.Messages;
import javax.swing.JDialog;
import javax.swing.JPanel;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JComponent;
import javax.swing.KeyStroke;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;

/**
 * MessageBox
 *
 * @since 23-04-07
 */
public class MessageBox extends JDialog {
    private JPanel contentPane;

    private JButton buttonOK;

    private JLabel labelContent;

    private final JComponent parentComponent;

    private final String msgContent;

    private final Runnable okAction;

    private final Runnable cancelAction;

    /**
     * MessageBox
     *
     * @param parent       jComponent
     * @param msgContent   message
     * @param okAction     ok action
     * @param cancelAction cancel action
     */
    public MessageBox(JComponent parent, String msgContent,
                      Runnable okAction, Runnable cancelAction) {
        this.parentComponent = parent;
        this.msgContent = msgContent;
        this.okAction = okAction;
        this.cancelAction = cancelAction;
        setContentPane(contentPane);
        setModal(true);
        getRootPane().setDefaultButton(buttonOK);

        buttonOK.addActionListener(e -> onOK());

        // call onCancel() when cross is clicked
        setDefaultCloseOperation(DO_NOTHING_ON_CLOSE);
        addWindowListener(new WindowAdapter() {

            /**
             * windowClosing
             *
             * @param e the event to be processed
             */
            public void windowClosing(WindowEvent e) {
                onCancel();
            }
        });

        // call onCancel() on ESCAPE
        contentPane.registerKeyboardAction(e -> onCancel(), KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
                JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT);

        this.setTitle("失败");
        this.labelContent.setText(this.msgContent);
    }

    private void onOK() {
        Runnable runnable = this.okAction;

        // add your code here
        dispose();
        if (runnable != null) {
            runnable.run();
        }
    }

    private void onCancel() {
        Runnable runnable = this.cancelAction;

        // add your code here if necessary
        dispose();
        if (runnable != null) {
            runnable.run();
        }
    }

    /**
     * showDialog
     *
     * @param project    project
     * @param title      title
     * @param msgContent message
     */
    public static void showDialog(Project project, String title, String msgContent) {
        showDialog(project, title, msgContent, null);
    }

    /**
     * showDialog
     *
     * @param project    project
     * @param title      title
     * @param msgContent message
     * @param okAction   ok action
     */
    public static void showDialog(Project project, String title,
                                  String msgContent, Runnable okAction) {
        showDialog(project, title, msgContent, okAction, null);
    }

    /**
     * showDialog
     *
     * @param project      project
     * @param title        title
     * @param msgContent   message
     * @param okAction     ok action
     * @param cancelAction cancel action
     */
    public static void showDialog(Project project, String title, String msgContent,
                                  Runnable okAction, Runnable cancelAction) {

        boolean isOK = MessageDialogBuilder.okCancel(title, msgContent)
                .icon(Messages.getInformationIcon()).ask(project);
        if (isOK) {
            if (okAction != null) {
                okAction.run();
            }
            return;
        }

        if (cancelAction != null) {
            cancelAction.run();
        }
    }
}
