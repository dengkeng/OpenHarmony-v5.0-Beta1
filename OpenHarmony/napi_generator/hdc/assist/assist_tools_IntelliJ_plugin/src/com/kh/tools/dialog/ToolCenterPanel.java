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

import com.kh.tools.utils.PluginUtils;

import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.JTextField;
import javax.swing.KeyStroke;
import javax.swing.border.EmptyBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.JRadioButton;
import javax.swing.JCheckBox;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.event.FocusEvent;
import java.awt.event.FocusListener;
import java.awt.event.KeyEvent;
import java.util.HashMap;

/**
 * 插件中心
 *
 * @author: zhaoxudong@kaihong.com
 * @see: tool conversion plug-in
 * @version: v1.0.0
 * @since 2022-09-16
 */
public class ToolCenterPanel extends JDialog {
    private JPanel contentPane;
    private JPanel searchPanel;
    private JTextField searchTextField;
    private JTabbedPane tabbedPane;
    private JLabel toolSecondNameLabel;
    private JLabel toolDescLabel;
    private JButton buttonNapi;
    private JButton buttonNapiName;
    private JButton tsButton;
    private JButton buttonTs;
    private JButton buttonClose;
    private JPanel napiPanel;
    private JPanel servicePanel;
    private String isSelectButton = "Napi";
    private JRadioButton selectToolchain;
    private JCheckBox checkNAPI;
    private JCheckBox checkH2Ts;
    private JLabel selectToolchainLabel;

    /**
     * 构造函数
     */
    public ToolCenterPanel() {
        tabbedPane.removeTabAt(1);
        setContentPane(contentPane);
        setModal(true);
        contentPane.registerKeyboardAction(e -> onCancel(), KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
                JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT);
        searchTextField.addFocusListener(new FocusListener() {
            @Override
            public void focusGained(FocusEvent focusEvent) {
                searchPanel.setBorder(PluginUtils.BORDER_FOCUS_GAINED);
                if (searchTextField.getText().equals("search")) {
                    searchTextField.setText("");
                }
            }

            @Override
            public void focusLost(FocusEvent focusEvent) {
                searchPanel.setBorder(PluginUtils.BORDER_FOCUS_LOST_SEARCH);
                if (searchTextField.getText().trim().length() < 1) {
                    searchTextField.setText("search");
                }
            }
        });
        setSelectToolChainVisible(false);
        setNapiCheckBoxVisible(false);
        setH2tsCheckBoxVisible(false);
        searchTextField.setForeground(Color.white);
        searchTextField.setBackground(Color.decode("#3c3f41"));
        searchTextField.setBorder(new EmptyBorder(0, 0, 0, 0));
        searchTextField.setCaretColor(Color.white);
        searchTextField.setFont(new Font(null, Font.PLAIN, 15));
        setButtonStyle();
        textFieldAction();
        buttonAction();
    }

    private void setButtonStyle() {
        buttonClose.setPreferredSize(new Dimension(40, 10));
        buttonClose.setContentAreaFilled(false);
        buttonClose.setBorder(new EmptyBorder(0, 0, 0, 0));
        buttonNapiName.setContentAreaFilled(false);
        buttonNapiName.setBorder(new EmptyBorder(0, 0, 0, 0));
        tsButton.setContentAreaFilled(false);
        tsButton.setBorder(new EmptyBorder(0, 0, 0, 0));
    }

    private void textFieldAction() {
        searchTextField.getDocument().addDocumentListener(new DocumentListener() {
            HashMap<String, String> result;

            @Override
            public void insertUpdate(DocumentEvent documentEvent) {
                result = searchTools(searchTextField.getText().trim());
                if (result.containsKey(buttonNapi.getToolTipText())) {
                    napiPanel.setVisible(true);
                } else {
                    napiPanel.setVisible(false);
                }
                if (result.containsKey(buttonTs.getToolTipText())) {
                    servicePanel.setVisible(true);
                } else {
                    servicePanel.setVisible(false);
                }
            }

            @Override
            public void removeUpdate(DocumentEvent documentEvent) {
                result = searchTools(searchTextField.getText().trim());
                if (result.containsKey(buttonNapi.getToolTipText())) {
                    napiPanel.setVisible(true);
                } else {
                    napiPanel.setVisible(false);
                }
                if (result.containsKey(buttonTs.getToolTipText())) {
                    servicePanel.setVisible(true);
                } else {
                    servicePanel.setVisible(false);
                }
            }

            @Override
            public void changedUpdate(DocumentEvent documentEvent) {
            }
        });
        buttonClose.addActionListener(actionEvent -> searchTextField.setText("search"));
    }

    private void buttonAction() {
        buttonNapi.addActionListener(e -> {
            isSelectButton = "Napi";
            toolSecondNameLabel.setText(buttonNapi.getToolTipText());
            toolDescLabel.setText(PluginUtils.TOOLS.get(buttonNapi.getToolTipText()));
            setSelectToolChainVisible(false);
            setNapiCheckBoxVisible(false);
            setH2tsCheckBoxVisible(false);
            setButtonVisible(true);
            buttonNapiName.setForeground(Color.white);
            tsButton.setForeground(Color.decode("#BBBBBB"));
        });
        buttonTs.addActionListener(e -> {
            isSelectButton = "H2Ts";
            toolSecondNameLabel.setText(buttonTs.getToolTipText());
            toolDescLabel.setText(PluginUtils.TOOLS.get(buttonTs.getToolTipText()));
            setSelectToolChainVisible(true);
            if (selectToolchain.isSelected()) {
                setButtonVisible(false);
                setNapiCheckBoxVisible(true);
                setH2tsCheckBoxVisible(true);
            } else {
                tsButton.setForeground(Color.white);
                buttonNapiName.setForeground(Color.decode("#BBBBBB"));
            }
            tsButton.setForeground(Color.white);
            buttonNapiName.setForeground(Color.decode("#BBBBBB"));
        });
        selectToolchain.addActionListener(e -> {
            if (selectToolchain.isSelected()) {
                checkH2Ts.setForeground(Color.white);
                setButtonVisible(false);
                setNapiCheckBoxVisible(true);
                setH2tsCheckBoxVisible(true);
            } else {
                setNapiCheckBoxVisible(false);
                setH2tsCheckBoxVisible(false);
                setButtonVisible(true);
            }
        });
    }

    private void onCancel() {
        dispose();
    }

    @Override
    public Dimension getPreferredSize() {
        return new Dimension(1000, 600);
    }

    JPanel getContentPanel() {
        return contentPane;
    }

    public String isSelectButton() {
        return isSelectButton;
    }

    /**
     * 功能描述 get radiobutton
     *
     * @return 是否选中
     */
    public boolean getSelectToolChain() {
        return selectToolchain.isSelected();
    }

    /**
     * 功能描述 set button visible or not
     *
     * @param isTrue 是否可见标志
     * @return null
     */
    public void setSelectToolChainVisible(boolean isTrue) {
        selectToolchain.setVisible(isTrue);
        selectToolchainLabel.setVisible(isTrue);
        repaint();

    }

    /**
     * 功能描述 get napi checkbox
     *
     * @return 是否选中
     */
    public boolean getSelectNapiCheckBox() {
        return checkNAPI.isSelected();
    }

    /**
     * 功能描述 get h2ts checkbox
     *
     * @return 是否选中
     */
    public boolean getSelectH2tsCheckBox() {
        return checkH2Ts.isSelected();
    }

    /**
     * 功能描述 set napi checkbox visible or not
     *
     * @param isTrue 是否可见标志
     * @return null
     */
    public void setNapiCheckBoxVisible(boolean isTrue) {
        checkNAPI.setVisible(isTrue);
        repaint();
    }

    /**
     * 功能描述 set h2ts checkbox visible or not
     *
     * @param isTrue 是否可见标志
     * @return null
     */
    public void setH2tsCheckBoxVisible(boolean isTrue) {
        checkH2Ts.setVisible(isTrue);
        repaint();
    }

    /**
     * 功能描述 set checkbox visible or not
     *
     * @param isTrue 是否可见标志
     * @return null
     */
    public void setButtonVisible(boolean isTrue) {
        buttonNapiName.setVisible(isTrue);
        tsButton.setVisible(isTrue);
    }

    /**
     * 搜索结果
     *
     * @param key 关键字
     * @return 搜索结果
     */
    private HashMap<String, String> searchTools(String key) {
        if (key.equals("search")) {
            return PluginUtils.TOOLS;
        }
        HashMap<String, String> searchResultList = new HashMap<>();
        for (HashMap.Entry<String, String> entry : PluginUtils.TOOLS.entrySet()) {
            if (entry.getKey().contains(key)) {
                searchResultList.put(entry.getKey(), entry.getValue());
            }
        }
        return searchResultList;
    }
}
