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
package com.kh.scan.dialog;

import com.intellij.notification.NotificationType;
import com.intellij.openapi.diagnostic.Logger;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.ui.ValidationInfo;
import com.kh.scan.action.ScanDirAction;
import com.kh.scan.action.ScanResultDirAction;
import com.kh.scan.utils.FileInfo;
import com.kh.scan.utils.FileUtil;
import com.kh.scan.utils.GenNotification;
import org.apache.http.util.TextUtils;
import org.jetbrains.annotations.Nullable;

import javax.swing.JButton;
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
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/**
 * GenerateDialogPane生成工具主界面
 *
 * @author: zhaoxudong@kaihong.com
 * @see: select generate dialog
 * @version: v1.0.0
 * @since 2022-10-14
 */
public class ApiScanDialogPane extends JDialog {
    private static final Logger LOG = Logger.getInstance(ApiScanDialogPane.class);

    private JPanel contentPane;
    private JTextField scanDirPathTextField;
    private JTextField outScanResultPathTextField;
    private JButton selectScanPath;
    private JButton outSelectPath;
    private boolean generateSuccess = true;
    private String sErrorMessage = "";
    private String scanDir;
    private String scanResultDir;
    private final Project project;
    private BlockingQueue blockingQueue = new LinkedBlockingQueue(100);
    private ThreadPoolExecutor threadPool = new ThreadPoolExecutor(2, 64, 60L,
            TimeUnit.SECONDS, blockingQueue,
            new ThreadPoolExecutor.AbortPolicy());


    /**
     * 构造函数
     *
     * @param project projectId
     */
    public ApiScanDialogPane(Project project) {
        this.project = project;
        contentPane.registerKeyboardAction(actionEvent -> onCancel(), KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
                JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT);
        selectScanPath.addActionListener(new ScanDirAction(selectScanPath, scanDirPathTextField,
                outScanResultPathTextField));
        outSelectPath.addActionListener(new ScanResultDirAction(outSelectPath, outScanResultPathTextField));
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
        String scanResultDirPath = outScanResultPathTextField.getText();
        String scanDirPath = scanDirPathTextField.getText();
        boolean isEmptyFile = TextUtils.isEmpty(scanDirPath) || TextUtils.isEmpty(scanResultDirPath);

        ValidationInfo validationInfo = null;
        if (isEmptyFile) {
            String warnMsg = "扫描项目路径、结果输出路径不能为空";
            warningMessage(warnMsg);
            validationInfo = new ValidationInfo(warnMsg);
            return validationInfo;
        }

        File file = new File(scanResultDirPath + "/result.xlsx");
        if (file.exists()) {
            ConfirmDialog confirmDialog = new ConfirmDialog("是否替换已存在的扫描结果?");
            if (!confirmDialog.showAndGet()) {
                validationInfo = new ValidationInfo(String.format("不替换现有扫描结果文件：%s", file));
                return validationInfo;
            }
        }
        return validationInfo;
    }

    private void onCancel() {
        dispose();
    }

    private void warningMessage(String title) {
        String notiContent = "请选择扫描项目路径、结果输出路径";
        GenNotification.notifyMessage(this.project, notiContent, title, NotificationType.WARNING);
    }

    /**
     * 获取指定输出目录下的文件列表
     *
     * @param outPath 输出目录
     * @return 文件信息列表
     */
    public List<FileInfo> getFileInfoList(File outPath) {
        List<FileInfo> fileInfoList = new ArrayList<>();
        File[] files = outPath.listFiles();
            for (File file : files) {
                fileInfoList.add(new FileInfo(file));
            }
        return fileInfoList;
    }

    /**
     * 执行主程序入口
     *
     * @return 执行状态
     */
    public boolean runFun() {
        GenNotification.notifyMessage(this.project, "", "正在生成", NotificationType.INFORMATION);
        scanDir = scanDirPathTextField.getText();
        scanResultDir = outScanResultPathTextField.getText();
        String command;
        command = genCommand();

        File outPath = new File(outScanResultPathTextField.getText());
        List<FileInfo> oldFileList = getFileInfoList(outPath);

        try {
            if (!TextUtils.isEmpty(command) && callExtProcess(command)) {
                List<FileInfo> newFileList = getFileInfoList(outPath);
                newFileList.removeAll(oldFileList);
                if (generateSuccess) {
                    GenNotification.notifyGenResult(project, newFileList, "Api Scan Successfully",
                            NotificationType.INFORMATION);
                    return true;
                } else {
                    GenNotification.notifyMessage(project, sErrorMessage, "提示", NotificationType.ERROR);
                    return false;
                }
            }
        } catch (IOException | InterruptedException ex) {
            GenNotification.notifyMessage(project, scanDirPathTextField.getText(), "Command exec error",
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
        String sysName = System.getProperties().getProperty("os.name").toUpperCase();
        String tmpDirFile = System.getProperty("java.io.tmpdir");
        String execFn;
        if (sysName.contains("WIN")) {
            execFn = "cmds/win/search-win.exe";
            tmpDirFile += "search-win.exe";
        } else if (sysName.contains("LINUX")) {
            execFn = "cmds/linux/search-linux";
            tmpDirFile += "/search-linux";
        } else {
            execFn = "cmds/mac/search-macos";
            tmpDirFile += "/search-macos";
        }
        File file = new File(tmpDirFile);
        try (InputStream inputStream = getClass().getClassLoader().getResourceAsStream(execFn)) {
            if (inputStream == null) {
                throw new IOException("exec File InputStream is Null");
            }
            byte[] bs = inputStream.readAllBytes();
            writeTmpFile(tmpDirFile, bs);
            if (sysName.contains("LINUX") || sysName.contains("MAC OS")) {
                executable(tmpDirFile);
            }
        } catch (IOException | InterruptedException e) {
            GenNotification.notifyMessage(this.project, e.getMessage(), "Can not Find File:" + execFn,
                    NotificationType.ERROR);
            LOG.error(e);

            return "";
        }
        String command = file.toString();
        command = command + " -d " + scanDir + " -o " + scanResultDir;
        return command;
    }

    private boolean callExtProcess(String command) throws IOException, InterruptedException {
        if (TextUtils.isEmpty(command)) {
            GenNotification.notifyMessage(this.project, "执行命令文件为空", "空命令行提示", NotificationType.ERROR);
            return false;
        }
        String tmpDirFile = System.getProperty("java.io.tmpdir");
        Process process = Runtime.getRuntime().exec(command, null, new File(tmpDirFile));
        threadPool.execute(new BlockThread(process));
        StreamConsumer outputConsumer = new StreamConsumer(process.getInputStream());
        outputConsumer.start();
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
     * 拷贝可执行文件到临时文件夹
     *
     * @param path 目标文件路径
     * @param bs   字节内容
     * @throws IOException exception
     */
    private void writeTmpFile(String path, byte[] bs) throws IOException {
        File file = new File(path);
        if (!file.exists()) {
            boolean isNewFile = file.createNewFile();
            if (!isNewFile) {
                LOG.info("writeTmpFile createNewFile error");
            }
        }
        FileOutputStream fw = new FileOutputStream(file);
        fw.write(bs, 0, bs.length);
        fw.close();
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
                    LOG.info(line);
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
