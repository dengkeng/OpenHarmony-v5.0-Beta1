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
import javax.swing.JDialog;
import javax.swing.JList;
import javax.swing.JPanel;
import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * GenResultDialog结果生成框
 *
 * @author: xudong
 * @see: generate success dialog
 * @version: v1.0.0
 * @since 2022-02-21
 */
public class GenResultDialog extends JDialog {
    private static final Logger LOG = Logger.getInstance(GenResultDialog.class);

    private JPanel contentPane;
    private JButton buttonOK;
    private JList resultList;
    private String path;

    public GenResultDialog(String directoryPath) {
        path = directoryPath;
    }

    /**
     * 初始化
     */
    public void initResultDialog() {
        setContentPane(contentPane);
        setModal(true);
        getRootPane().setDefaultButton(buttonOK);
        setTitle("执行成功");
        buttonOK.addActionListener(actionEvent -> onOK());
        List<String> fileList = getDirFileName(path);
        resultList.setListData(fileList.toArray(new String[fileList.size()]));
    }

    private void onOK() {
        dispose();
    }

    private List<String> getDirFileName(String path) {
        List<String> files = new ArrayList<>();
        File file = new File(path);
        if (!file.exists()) {
            LOG.info("getDirFileName f not exist");
            return files;
        }
        File[] fileArray = file.listFiles();
        for (int i = 0; i < fileArray.length; i++) {
            File fs = fileArray[i];
            if (!fs.isDirectory()) {
                files.add(fs.getPath());
            } else {
                LOG.info("getDirFileName this file is dir");
            }
        }
        return files;
    }
}
