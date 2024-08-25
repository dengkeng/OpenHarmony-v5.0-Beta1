/*
 * Copyright (c) 2024 Shenzhen Kaihong Digital Industry Development Co., Ltd.
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
package com.sk.na.ng;

import com.intellij.openapi.diagnostic.Logger;
import com.intellij.notification.NotificationType;
import com.intellij.openapi.actionSystem.AnAction;
import com.intellij.openapi.actionSystem.AnActionEvent;
import com.intellij.openapi.actionSystem.PlatformDataKeys;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.vfs.VirtualFile;

import com.sk.na.utils.GenNotification;
import org.apache.http.util.TextUtils;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.regex.Pattern;
import java.nio.charset.StandardCharsets;

/**
 * 项目文件入口
 *
 * @author: goujingjing
 * @see: tool conversion plug-in
 * @version: v1.0.0
 * @since 2024-03-29
 */
public class GenDts extends AnAction {
    private static final Logger LOG = Logger.getInstance(GenDts.class);

    private boolean generateSuccess = true;
    private String sErrorMessage = "";

    @Override
    public void actionPerformed(AnActionEvent anActionEvent) {
        Project project = anActionEvent.getProject();
        // 获取需要处理的.h文件绝对路径
        VirtualFile file = anActionEvent.getData(PlatformDataKeys.VIRTUAL_FILE);
        if (file == null) {
            GenNotification.notifyMessage(project, "", "file is not exist", NotificationType.ERROR);
            return;
        }
        if (project == null) {
            return;
        }
        String destPath = file.getPath();
        runFun(destPath);
    }

    @Override
    public void update(AnActionEvent event) {
        // 根据所选文件名，判断是否显示生成菜单项
        VirtualFile file = event.getData(PlatformDataKeys.VIRTUAL_FILE);
        if (file == null) {
            event.getPresentation().setEnabledAndVisible(false);
        } else {
            event.getPresentation().setEnabledAndVisible(patternFileName(file.getName()));
        }
    }

    /**
     * 正则匹配所选文件名是否符合规范
     *
     * @param fileName 文件名
     * @return boolean 是否匹配
     */
    public static boolean patternFileName(String fileName) {
        String pattern = "(([a-z_A-Z0-9]+).h)";
        return Pattern.matches(pattern, fileName);
    }

    /**
     * 获取生成成功结果文件。
     *
     * @param process 进程ID
     */
    private void genResultLog(Process process) {
        BufferedReader stdInput = new BufferedReader(new InputStreamReader(process.getErrorStream(),
                StandardCharsets.UTF_8));
        BufferedReader stdError = new BufferedReader(new InputStreamReader(process.getErrorStream(),
                StandardCharsets.UTF_8));
        String sErr = getErrorResult(stdError);
        String sOut;
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
                sOut.append(sTmp).append(getNewline());
            } catch (IOException ioException) {
                LOG.error(" genResultLog stdInput error" + ioException);
            }
        }
        return sOut.toString();
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
                sErr.append(sTmp).append(getNewline());
            } catch (IOException ioException) {
                LOG.error(" genResultLog stdInput error" + ioException);
            }
        }
        return sErr.toString();
    }

    /**
     * 获取换行符
     *
     * @return 换行符
     */
    public static String getNewline() {
        return System.getProperty("line.separator");
    }

    private boolean generateIsSuccess(String sOut) {
        generateSuccess = sOut.contains("success") || TextUtils.isEmpty(sOut);
        return generateSuccess;
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
                InputStreamReader isr = new InputStreamReader(is, StandardCharsets.UTF_8);
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

    private boolean callExtProcess(String command) throws IOException, InterruptedException {

        if (TextUtils.isEmpty(command)) {
            GenNotification.notifyMessage(null, "执行命令文件为空", "空命令行提示", NotificationType.ERROR);
            return false;
        }
        Process process = Runtime.getRuntime().exec(command);
        genResultLog(process);
        StreamConsumer errConsumer = new StreamConsumer(process.getErrorStream());
        StreamConsumer outputConsumer = new StreamConsumer(process.getInputStream());
        errConsumer.start();
        outputConsumer.start();

        if (!generateSuccess) {
            GenNotification.notifyMessage(null, sErrorMessage, "提示", NotificationType.ERROR);
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
            GenNotification.notifyMessage(null, e.getMessage(), "Can not Find File:" + execFn,
                    NotificationType.ERROR);
            LOG.error(e);
        }
    }

    /**
     * 生成命令行指令
     *
     * @param hFilePath .h文件路径
     * @return 返回命令行执行内容
     */
    private String genCommand(String hFilePath) {
        String sysName = System.getProperties().getProperty("os.name").toUpperCase();
        String tmpDirFile = System.getProperty("java.io.tmpdir");
        if (sysName.contains("WIN")) {
            copyFileToLocalPath("native_gen-win");
            tmpDirFile += "native_gen-win.exe";
        } else if (sysName.contains("LINUX")) {
            copyFileToLocalPath("native_gen-linux");
            tmpDirFile += "native_gen-linux";
        } else {
            copyFileToLocalPath("native_gen-macos");
            tmpDirFile += "native_gen-macos";
        }

        File file = new File(tmpDirFile);
        String command = file.toString();
        command += " -f " + hFilePath;
        // 判断用户是否输入了 "-o"+cpp文件路径， "-i"+dts文件路径，"-t"+test文件路径 从界面获取
        return command;
    }

    /**
     * 执行主程序入口
     *
     * @param hFilePath .h文件路径
     * @return 执行状态
     */
    public boolean runFun(String hFilePath) {
        copyFileToLocalPath("header_parser");
        String command;
        command = genCommand(hFilePath);
        GenNotification.notifyMessage(null, command, "command",
                NotificationType.INFORMATION);

        try {
            if (!TextUtils.isEmpty(command) && callExtProcess(command)) {
                GenNotification.notifyMessage(null, "", "Generate Native Successfully",
                        NotificationType.INFORMATION);

                return true;
            }
        } catch (IOException | InterruptedException ex) {
            GenNotification.notifyMessage(null, "", "Command exec error",
                    NotificationType.ERROR);
            LOG.error(ex);
        }
        return false;
    }
}
