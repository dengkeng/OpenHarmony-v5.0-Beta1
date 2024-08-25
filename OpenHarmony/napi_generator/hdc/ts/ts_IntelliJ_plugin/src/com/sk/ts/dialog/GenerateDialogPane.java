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
package com.sk.ts.dialog;

import com.intellij.notification.NotificationType;
import com.intellij.openapi.diagnostic.Logger;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.ui.ValidationInfo;

import com.sk.ts.action.SelectHAction;
import com.sk.ts.action.SelectOutPathAction;
import com.sk.ts.utils.FileInfo;
import com.sk.ts.utils.FileUtil;
import com.sk.ts.utils.GenNotification;
import org.apache.http.util.TextUtils;
import org.jetbrains.annotations.Nullable;
import javax.swing.JDialog;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.JButton;
import javax.swing.JComponent;
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

/**
 * 配置对话框
 *
 * @author: xudong
 * @see: generator dialog
 * @version: v1.0.0
 * @since 2022-02-21
 */
public class GenerateDialogPane extends JDialog {
    private static final Logger LOG = Logger.getInstance(GenerateDialogPane.class);

    private final Project project;
    private List<String> tsFileList = new ArrayList<>();
    private JPanel contentPane;
    private JTextField textFieldSelectH;
    private JTextField textFieldSelectOutPath;

    private JButton buttonSelectH;
    private JButton buttonSelectOutPath;

    private boolean generateSuccess = true;
    private String sErrorMessage = "";
    private String interFileOrDir;
    private String genOutDir;
    private String scriptOutDir;
    private String hGenFileName;
    private String tsGenFileName;
    private String tsOutPath;


    /**
     * 构造函数
     *
     * @param project       projectid
     * @param interFilePath 接口文件路径
     * @param genDir        生成框架文件路径
     * @param scriptDir     脚本目录
     */
    public GenerateDialogPane(Project project, String interFilePath, String genDir, String scriptDir) {
        setContentPane(contentPane);
        setModal(true);
        this.project = project;
        this.interFileOrDir = interFilePath;
        this.genOutDir = genDir;
        this.scriptOutDir = scriptDir;
        if (FileUtil.patternFileNameH(scriptDir)) {
            textFieldSelectH.setText(interFileOrDir);
            textFieldSelectOutPath.setText(genOutDir);
        }
        contentPane.registerKeyboardAction(actionEvent -> onCancel(), KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
                JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT);

        buttonSelectH.addActionListener(new SelectHAction(buttonSelectH, textFieldSelectH,
                textFieldSelectOutPath, project));
        buttonSelectOutPath.addActionListener(new SelectOutPathAction(buttonSelectOutPath, textFieldSelectOutPath));

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
     * 检查输入的.h文件转换后的同名.d.ts文件是否在输出目录中已存在
     *
     * @param fileObj .h文件对象
     * @param outPutDir 输出目录
     * @return 如果ts文件已存在，返回文件名；否则返回空字符串
     */
    private String getExistFileName(File fileObj, String outPutDir) {
        if (fileObj.isDirectory()) {
            // 遇到文件夹直接跳过不检查，只检查普通.h文件是否存在对应的.ts
            return "";
        }
        String hFileName = fileObj.getName();
        String tsFileName = hFileName.substring(0, hFileName.lastIndexOf(".")) + ".d.ts";
        File tsFile = new File(outPutDir + "/" + tsFileName);
        return tsFile.exists() ? tsFile.toString() : "";
    }

    /**
     * 检查待生成的ts文件在输出目录中是否已存在
     *
     * @param hFilePath 待转换的.h文件/目录路径
     * @param outPutDir 输出目录路径
     * @return 如果ts文件已存在，返回文件名；否则返回空字符串
     */
    private String checkTsFileExist(String hFilePath, String outPutDir) {
        File hFileObj = new File(hFilePath);
        if (!hFileObj.isDirectory()) {
            return getExistFileName(hFileObj, outPutDir);
        } else {
            File[] fileList = hFileObj.listFiles();
            for (File fileObj : fileList) {
                String existFileName = getExistFileName(fileObj, outPutDir);
                if (!existFileName.equals("")) {
                    return existFileName;
                }
            }
        }
        return "";
    }

    /**
     * 验证文本选择框是否空。是否替换已存在的内容
     *
     * @return ValidationInfo 返回不符要求的信息。
     */
    @Nullable
    public ValidationInfo validationInfo() {
        ValidationInfo validationInfo = null;

        String hFile = textFieldSelectH.getText();
        String outPutDir = textFieldSelectOutPath.getText();
        boolean isEmptyFile = TextUtils.isEmpty(hFile) || TextUtils.isEmpty(outPutDir);
        if (isEmptyFile) {
            String warnMsg = "文件路径、输出路径不能为空";
            warningMessage(warnMsg);
            validationInfo = new ValidationInfo(warnMsg);
            return validationInfo;
        }

        String existFileName = checkTsFileExist(hFile, outPutDir);
        if (!existFileName.equals("")) {
            ConfirmDialog confirmDialog = new ConfirmDialog(
                    String.format("是否替换已存在的文件：%s ?", existFileName));
            if (!confirmDialog.showAndGet()) {
                validationInfo = new ValidationInfo(String.format("不替换现有文件：%s", existFileName));
                return validationInfo;
            }
        }

        return validationInfo;
    }

    private void onCancel() {
        dispose();
    }

    private void warningMessage(String title) {
        String notifyContent = "请选择接口文件或文件夹，生成框架路径，编译脚本路径";
        GenNotification.notifyMessage(this.project, notifyContent, title, NotificationType.WARNING);
    }

    /**
     * 拷贝文件到本地临时目录
     *
     * @param fileName 文件名
     */
    private void copyFileToLocalPath(String fileName) {
        String sysName = System.getProperties().getProperty("os.name").toUpperCase();
        String tmpDirFile = System.getProperty("java.io.tmpdir");
        String execFn;
        if (sysName.contains("WIN")) {
            execFn = "cmds/win/" + fileName + ".exe";
            tmpDirFile += fileName + ".exe";
        } else if (sysName.contains("LINUX")) {
            execFn = "cmds/linux/" + fileName;
            tmpDirFile += fileName;
        } else {
            execFn = "cmds/mac/" + fileName;
            tmpDirFile += fileName;
        }
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
        }
    }

    /**
     * 生成 -f -d 输入参数。
     *
     * @param fileOrDir 选中的文件或文件夹路径
     * @return 生成后的 -f -d的值
     */
    private String genInArgs(String fileOrDir) {
        tsFileList.clear();
        String[] interArr = fileOrDir.split(",");
        StringBuilder tsParam = new StringBuilder(" -f ");
        StringBuilder dirParam = new StringBuilder(" -d ");
        String inputCommand = "";
        if (interArr.length > 0) {
            for (String interStr : interArr) {
                File interFile = new File(interStr);
                if (interFile.isDirectory()) {
                    dirParam.append(interStr).append(" ");
                    for (File tsFile : interFile.listFiles()) {
                        tsFileList.add(tsFile.getPath());
                    }
                } else {
                    tsParam.append(interStr).append(",");
                    tsFileList.add(interStr);
                }
            }
            if (!TextUtils.isBlank(tsParam.toString().replaceAll("-f", ""))) {
                inputCommand += tsParam.substring(0, tsParam.length() - 1);
            }
            if (!TextUtils.isBlank(dirParam.toString().replace("-d", ""))) {
                inputCommand += dirParam.substring(0, dirParam.length() - 1);
            }
        }
        return inputCommand;
    }

    private boolean callExtProcess(String command) throws IOException, InterruptedException {

        if (TextUtils.isEmpty(command)) {
            GenNotification.notifyMessage(this.project, "执行命令文件为空", "空命令行提示", NotificationType.ERROR);
            return false;
        }
        Process process = Runtime.getRuntime().exec(command);
        genResultLog(process);
        StreamConsumer errConsumer = new StreamConsumer(process.getErrorStream());
        StreamConsumer outputConsumer = new StreamConsumer(process.getInputStream());
        errConsumer.start();
        outputConsumer.start();

        if (!generateSuccess) {
            GenNotification.notifyMessage(project, sErrorMessage, "提示", NotificationType.ERROR);
            return false;
        }

        errConsumer.join();
        outputConsumer.join();
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
                InputStreamReader inputStreamReader = new InputStreamReader(is);
                BufferedReader bufferedReader = new BufferedReader(inputStreamReader);
                String readLine;
                while ((readLine = bufferedReader.readLine()) != null) {
                    LOG.error("StreamConsumer" + readLine);
                }
            } catch (IOException ioException) {
                LOG.error("StreamConsumer io error" + ioException);
            }
        }
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
    public boolean runFunH2ts() {
        GenNotification.notifyMessage(this.project, "", "Generating Ts", NotificationType.INFORMATION);
        copyFileToLocalPath("header_parser");
        String command;
        command = genCommandH2ts();

        File outPath = new File(textFieldSelectOutPath.getText());
        List<FileInfo> oldFileList = getFileInfoList(outPath);
        try {
            if (!TextUtils.isEmpty(command) && callExtProcess(command)) {
                List<FileInfo> newFileList = getFileInfoList(outPath);
                newFileList.removeAll(oldFileList); // 对比命令执行前后的文件列表差异，得到新生成的文件列表
                GenNotification.notifyGenResult(project, newFileList, "Generate Ts Successfully",
                        NotificationType.INFORMATION);
                return true;
            }
        } catch (IOException | InterruptedException ex) {
            GenNotification.notifyMessage(project, textFieldSelectOutPath.getText(), "Command exec error",
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
    private String genCommandH2ts() {
        String sysName = System.getProperties().getProperty("os.name").toUpperCase();
        String tmpDirFile = System.getProperty("java.io.tmpdir");
        if (sysName.contains("WIN")) {
            copyFileToLocalPath("napi_generator-win");
            tmpDirFile += "napi_generator-win.exe";
        } else if (sysName.contains("LINUX")) {
            copyFileToLocalPath("napi_generator-linux");
            tmpDirFile += "napi_generator-linux";
        } else {
            copyFileToLocalPath("napi_generator-macos");
            tmpDirFile += "napi_generator-macos";
        }

        File file = new File(tmpDirFile);
        String command = file.toString();
        String inArgs = genInArgs(textFieldSelectH.getText());
        command += inArgs + " -o " + textFieldSelectOutPath.getText() + " -t " + true;
        return command;
    }

    JPanel getContentPanel() {
        return contentPane;
    }

    /**
     * 获取生成的.d.ts文件名
     *
     * @return 生成的.d.ts文件名
     */
    public String getTsFileName() {
        hGenFileName = textFieldSelectH.getText();
        tsGenFileName = hGenFileName.substring(0, hGenFileName.lastIndexOf(".")) + ".d.ts";
        return tsGenFileName;
    }

    /**
     * 获取生成的.d.ts文件输出路径
     *
     * @return .d.ts文件输出路径
     */
    public String getTsOutPath() {
        tsOutPath = textFieldSelectOutPath.getText();
        return tsOutPath;
    }

    /**
     * 获取工程
     *
     * @return 当前工程
     */
    public Project getProject() {
        return this.project;
    }

}
