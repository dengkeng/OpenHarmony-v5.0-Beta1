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
package com.sk.gn.dialog;

import com.intellij.notification.NotificationType;
import com.intellij.openapi.diagnostic.Logger;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.ui.ValidationInfo;
import com.sk.gn.action.InputScriptAction;
import com.sk.gn.action.SelectBankAction;
import com.sk.gn.action.SelectOriginCodeAction;
import com.sk.gn.action.SelectOutDirAction;
import com.sk.gn.utils.FileUtil;
import com.sk.gn.utils.GenNotification;
import org.apache.http.util.TextUtils;
import org.jetbrains.annotations.Nullable;

import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.KeyStroke;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.awt.event.WindowListener;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import static com.sk.gn.utils.FileUtil.writeTmpFile;

/**
 * GenerateDialogPane生成工具主界面
 *
 * @author: zhaoxudong@kaihong.com
 * @see: select generate dialog
 * @version: v1.0.0
 * @since 2022-02-21
 */
public class GenDialogPane extends JDialog implements SelectOutDirAction.SelectPathInterface {
    private static final Logger LOG = Logger.getInstance(GenDialogPane.class);
    private static final String SYS_NAME = System.getProperties().getProperty("os.name").toUpperCase();

    private JPanel contentPane;
    private JTextField opOutPathTextField;
    private JTextField opOriginTextField;
    private JTextField transplantTextField;
    private JButton selectOPOutButton;
    private JButton selectOPOriginButton;
    private JButton selectTransplantButton;
    private JButton selectScriptButton;
    private JTextField subsystemTextField;
    private JTextField test_partTextField;
    private JTextField compileTextField;
    private JTextField inputScriptTextField;
    private JComboBox comboBox;
    private boolean generateSuccess = true;
    private String sErrorMessage = "";

    /**
     * 输出路径 -o
     */
    private String outputCodeDir;

    /**
     * 源码路径 -p
     */
    private String originCodeDir;

    /**
     * 输入脚本路径 -f
     */
    private String inputScriptDir;

    /**
     * 输入脚本类型 -t
     */
    private String scriptType;

    /**
     * 移植库路径/GN生成路径 -m
     */
    private String transplantDir;

    /**
     * 子系统名称 -s
     */
    private String subsystemName;

    /**
     * 组件名称 -m
     */
    private String componentName;

    /**
     * 编译选项 -a
     */
    private String compileOptions;

    private final Project project;
    private BlockingQueue blockingQueue = new LinkedBlockingQueue(100);
    private ThreadPoolExecutor threadPool = new ThreadPoolExecutor(2, 64, 60L,
            TimeUnit.SECONDS, blockingQueue,
            new ThreadPoolExecutor.AbortPolicy());

    /**
     * 构造函数
     *
     * @param project  projectId
     * @param filePath 文件路径
     */
    public GenDialogPane(Project project, String filePath) {
        this.project = project;
        // call onCancel() on ESCAPE
        contentPane.registerKeyboardAction(actionEvent -> onCancel(), KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
                JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT);

        selectOPOutButton.addActionListener(new SelectOutDirAction(selectOPOutButton, opOutPathTextField, this));
        selectOPOriginButton.addActionListener(new SelectOriginCodeAction(selectOPOriginButton, opOriginTextField,
                opOutPathTextField));
        selectTransplantButton.addActionListener(new SelectBankAction(selectTransplantButton, transplantTextField));
        selectScriptButton.addActionListener(new InputScriptAction(selectScriptButton, inputScriptTextField, comboBox,
                transplantTextField));
        inputScriptTextField.setText(filePath);
    }

    @Override
    public synchronized void addWindowListener(WindowListener windowListener) {
        super.addWindowListener(windowListener);
        new WindowAdapter() {
            /**
             * close dialog
             *
             * @param windowEvent WindowEvent
             */
            @Override
            public void windowClosing(WindowEvent windowEvent) {
                onCancel();
            }
        };
    }

    /**
     * 验证文本选择框是否空。是否替换已存在的内容
     *
     * @return ValidationInfo 返回不符要求的信息。
     */
    @Nullable
    public ValidationInfo validationInfo() {
        getEditText();
        ValidationInfo validationInfo = null;
        String warnMsg;
        if (TextUtils.isEmpty(outputCodeDir)) {
            warnMsg = "输出路径不能为空";
            warningMessage(warnMsg);
            validationInfo = new ValidationInfo(warnMsg);
            return validationInfo;
        }
        if (TextUtils.isEmpty(originCodeDir)) {
            warnMsg = "源码路径不能为空";
            warningMessage(warnMsg);
            validationInfo = new ValidationInfo(warnMsg);
            return validationInfo;
        }
        if (TextUtils.isEmpty(transplantDir)) {
            warnMsg = "库移植的路径不能为空";
            warningMessage(warnMsg);
            validationInfo = new ValidationInfo(warnMsg);
            return validationInfo;
        }
        if (TextUtils.isEmpty(inputScriptDir)) {
            warnMsg = "输入脚本路径不能为空";
            warningMessage(warnMsg);
            validationInfo = new ValidationInfo(warnMsg);
            return validationInfo;
        }
        if (TextUtils.isEmpty(subsystemName)) {
            warnMsg = "子系统名称不能为空";
            warningMessage(warnMsg);
            validationInfo = new ValidationInfo(warnMsg);
            return validationInfo;
        }
        if (TextUtils.isEmpty(componentName)) {
            warnMsg = "组件名称不能为空";
            warningMessage(warnMsg);
            validationInfo = new ValidationInfo(warnMsg);
            return validationInfo;
        }
        File file = new File(transplantTextField.getText() + "/build_tmp");
        if (file.exists()) {
            ConfirmDialog confirmDialog = new ConfirmDialog("是否替换已存在的生成结果?");
            if (!confirmDialog.showAndGet()) {
                validationInfo = new ValidationInfo(String.format("不替换现有生成结果：%s", file));
                return validationInfo;
            }
        }
        return validationInfo;
    }

    private void getEditText() {
        // 输出路径
        outputCodeDir = opOutPathTextField.getText().trim();
        // 源码路径
        originCodeDir = opOriginTextField.getText().trim();
        // 库移植的路径
        transplantDir = transplantTextField.getText().trim();
        // 输入脚本路径
        inputScriptDir = inputScriptTextField.getText().trim();
        // 输入脚本类型
        scriptType = comboBox.getSelectedItem().toString().trim();
        // 子系统名称
        subsystemName = subsystemTextField.getText().trim();
        // 组件名称
        componentName = test_partTextField.getText().trim();
        // 编译选项
        compileOptions = compileTextField.getText().trim();
    }

    private void onCancel() {
        dispose();
    }

    private void warningMessage(String title) {
        String notifyContent = "带*号均为必填项";
        GenNotification.notifyMessage(this.project, notifyContent, title, NotificationType.WARNING);
    }

    /**
     * 执行主程序入口
     *
     * @return 执行状态
     */
    public boolean runFun() {
        createCopyResMakeFile();
        createCopyResMakeRawFile();
        createCopyResToolChainFile();
        GenNotification.notifyMessage(this.project, "", "正在生成", NotificationType.INFORMATION);
        String command;
        command = genCommand();
        try {
            if (!TextUtils.isEmpty(command) && callExtProcess(command)) {
                GenNotification.notifyMessage(project, opOriginTextField.getText(), "提示",
                        NotificationType.INFORMATION, true);
                return true;
            }
        } catch (IOException | InterruptedException ex) {
            GenNotification.notifyMessage(project, opOriginTextField.getText(), "Command exec error",
                    NotificationType.ERROR);
            LOG.error(ex);
        }
        return false;
    }

    /**
     * 生成命令行指令
     *
     * @return 返回命令行执行内容
     */
    private String genCommand() {
        String tmpDirFile = System.getProperty("java.io.tmpdir");
        String execFn;
        if (SYS_NAME.contains("WIN")) {
            execFn = "cmds/win/gn-gen-win.exe";
            tmpDirFile += "/gn-gen-win.exe";
        } else if (SYS_NAME.contains("LINUX")) {
            execFn = "cmds/linux/gn-gen-linux";
            tmpDirFile += "/gn-gen-linux";
        } else {
            execFn = "cmds/mac/gn-gen-macos";
            tmpDirFile += "/gn-gen-macos";
        }
        File file = new File(tmpDirFile);
        writeTmpFile(tmpDirFile, execFn, project);
        if (SYS_NAME.contains("LINUX") || SYS_NAME.contains("MAC OS")) {
            try {
                executable(tmpDirFile);
            } catch (IOException | InterruptedException e) {
                GenNotification.notifyMessage(this.project, e.getMessage(), "Can not Find File:" + execFn,
                        NotificationType.ERROR);
                LOG.error(e);
            }
        }
        String command = file.toString();
        command += " -o " + outputCodeDir + " -p " + originCodeDir + " -f " + inputScriptDir + " -t " + scriptType
            + " -s " + subsystemName + " -m " + componentName + " -d " + transplantDir;
        if (!TextUtils.isEmpty(compileTextField.getText().trim())) {
            command += " -a " + "\"" + compileOptions + "\"";
        }
        if (SYS_NAME.contains("WIN")) {
            return command.replaceAll("\\\\", "/");
        }
        return command;
    }

    private void createCopyResMakeFile() {
        String makeFilePath = "cmds/res/linux/bin/make";
        if (SYS_NAME.contains("WIN")) {
            makeFilePath = "cmds/res/win/bin/make.exe";
        }
        String tmpDirFile = System.getProperty("java.io.tmpdir") + "/res/linux/bin/";
        File file = new File(tmpDirFile);
        if (file.mkdirs()) {
            LOG.info("create dir success");
        }
        String tmp = SYS_NAME.contains("WIN") ? file.getPath() + "/make.exe" : file.getPath() + "/make";
        writeTmpFile(tmp, makeFilePath, project);
        if (SYS_NAME.contains("LINUX") || SYS_NAME.contains("MAC OS")) {
            try {
                executable(tmp);
            } catch (IOException | InterruptedException e) {
                GenNotification.notifyMessage(this.project, e.getMessage(), "Can not Find File:" + makeFilePath,
                    NotificationType.ERROR);
                LOG.error(e);
            }
        }
    }

    private void createCopyResMakeRawFile() {
        String makeFilePath = "cmds/res/linux/bin/make_raw";
        if (SYS_NAME.contains("WIN")) {
            makeFilePath = "cmds/res/win/bin/make_raw.exe";
        }
        String tmpDirFile = System.getProperty("java.io.tmpdir") + "/res/linux/bin/";
        File file = new File(tmpDirFile);
        if (file.mkdirs()) {
            LOG.info("create dir success");
        }
        String tmp = SYS_NAME.contains("WIN") ? file.getPath() + "/make_raw.exe" : file.getPath() + "/make_raw";
        writeTmpFile(tmp, makeFilePath, project);
        if (SYS_NAME.contains("LINUX") || SYS_NAME.contains("MAC OS")) {
            try {
                executable(tmp);
            } catch (IOException | InterruptedException e) {
                GenNotification.notifyMessage(this.project, e.getMessage(), "Can not Find File:" + makeFilePath,
                    NotificationType.ERROR);
                LOG.error(e);
            }
        }
    }

    private void createCopyResToolChainFile() {
        String toolchainFileDir = "cmds/res/linux/ohos.toolchain.cmake";
        if (SYS_NAME.contains("WIN")) {
            toolchainFileDir = "cmds/res/win/ohos.toolchain.cmake";
        }
        String tmpDirFile = System.getProperty("java.io.tmpdir") + "/res/linux/";
        File file = new File(tmpDirFile);
        if (file.mkdirs()) {
            LOG.info("create dir success");
        }
        String tmp = file.getPath() + "/ohos.toolchain.cmake";
        writeTmpFile(tmp, toolchainFileDir, project);
        if (SYS_NAME.contains("LINUX") || SYS_NAME.contains("MAC OS")) {
            try {
                executable(tmp);
            } catch (IOException | InterruptedException e) {
                GenNotification.notifyMessage(this.project, e.getMessage(), "Can not Find File:" + toolchainFileDir,
                    NotificationType.ERROR);
                LOG.error(e);
            }
        }
    }

    private boolean callExtProcess(String command) throws IOException, InterruptedException {
        if (TextUtils.isEmpty(command)) {
            GenNotification.notifyMessage(this.project, "执行命令文件为空", "空命令行提示", NotificationType.ERROR);
            return false;
        }
        final Process process = Runtime.getRuntime().exec(command);
        threadPool.execute(new BlockThread(process));
        StreamConsumer errConsumer = new StreamConsumer(process.getErrorStream());
        StreamConsumer outputConsumer = new StreamConsumer(process.getInputStream());
        errConsumer.start();
        outputConsumer.start();
        if (generateSuccess) {
            GenNotification.notifyMessage(project, "执行成功", "提示", NotificationType.INFORMATION);
        } else {
            GenNotification.notifyMessage(project, sErrorMessage, "提示", NotificationType.ERROR);
            return false;
        }
        errConsumer.join();
        outputConsumer.join();
        process.destroy();
        return true;
    }

    /**
     * 赋值可执行文件权限。
     *
     * @param execFn 可执行命令
     * @throws IOException          打开文件异常
     * @throws InterruptedException 中断异常
     */
    private void executable(String execFn) throws IOException, InterruptedException {
        callExtProcess("chmod a+x " + execFn);
    }

    /**
     * 获取生成成功结果文件。
     *
     * @param process 进程ID
     */
    private void genResultLog(Process process) {
        BufferedReader stdInput = new BufferedReader(new InputStreamReader(process.getInputStream()));
        BufferedReader stdError = new BufferedReader(new InputStreamReader(process.getErrorStream()));
        String sErr;
        String sOut;
        sErr = getErrorResult(stdError);
        if (TextUtils.isEmpty(sErr)) {
            sOut = genInputLog(stdInput);
            if (!generateIsSuccess(sOut)) {
                sErrorMessage = sOut;
            }
            return;
        }
        generateSuccess = false;
        sErrorMessage = sErr;
    }

    /**
     * 获取生成失败结果文件。
     *
     * @param stdError error buff
     * @return ErrorResult
     */
    private String getErrorResult(BufferedReader stdError) {
        StringBuilder sErr = new StringBuilder();
        while (true) {
            String sTmp;
            try {
                if ((sTmp = stdError.readLine()) == null) {
                    break;
                }
                sErr.append(sTmp).append(FileUtil.getNewline());
            } catch (IOException ioException) {
                LOG.error(" genResultLog stdInput error" + ioException);
            }
        }
        return sErr.toString();
    }

    private boolean generateIsSuccess(String sOut) {
        generateSuccess = sOut.contains("success") || TextUtils.isEmpty(sOut);
        return generateSuccess;
    }

    /**
     * 获取生成文本内容。
     *
     * @param stdInput input buff
     * @return 返回当前输入框内容
     */
    private String genInputLog(BufferedReader stdInput) {
        StringBuilder sOut = new StringBuilder();
        while (true) {
            String sTmp;
            try {
                if ((sTmp = stdInput.readLine()) == null) {
                    break;
                }
                sOut.append(sTmp).append(FileUtil.getNewline());
            } catch (IOException ioException) {
                LOG.error(" genResultLog stdInput error" + ioException);
            }
        }
        return sOut.toString();
    }

    @Override
    public void getFilePath(File pathFile) {
        if (pathFile.getParentFile() != null && pathFile.getParentFile().getParent() != null) {
            opOriginTextField.setText(pathFile.getParentFile().getParent());
            inputScriptTextField.setText(pathFile.getParentFile().getParent());
        }
    }

    static class StreamConsumer extends Thread {
        InputStream is;

        StreamConsumer(InputStream is) {
            super.setName("StreamConsumer");
            this.is = is;
        }

        @Override
        public void run() {
            try {
                InputStreamReader isr = new InputStreamReader(is);
                BufferedReader br = new BufferedReader(isr);
                String line;
                while ((line = br.readLine()) != null) {
                    LOG.error("StreamConsumer" + line);
                }
            } catch (IOException ioException) {
                LOG.error("StreamConsumer io error" + ioException);
            }
        }
    }

    JPanel getContentPanel() {
        return contentPane;
    }

    class BlockThread extends Thread {
        Process process;

        BlockThread(Process process) {
            super.setName("BlockThread");
            this.process = process;
        }

        @Override
        public void run() {
            BufferedReader br = new BufferedReader(new InputStreamReader(process.getInputStream()));
            genResultLog(process);
            try {
                while (br.readLine() != null) {
                    LOG.info(" callExtProcess ");
                }
            } catch (IOException ioException) {
                LOG.error(" callExtProcess error" + ioException);
            }
        }
    }
}
