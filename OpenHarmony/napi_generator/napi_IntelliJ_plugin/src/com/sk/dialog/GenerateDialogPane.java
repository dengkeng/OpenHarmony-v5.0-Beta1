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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.intellij.notification.NotificationType;
import com.intellij.openapi.diagnostic.Logger;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.ui.ValidationInfo;
import com.sk.action.BrowseAction;
import com.sk.action.GenAction;
import com.sk.action.ScriptAction;
import com.sk.utils.FileInfo;
import com.sk.utils.FileUtil;
import com.sk.utils.GenNotification;
import com.sk.utils.Data;
import com.sk.utils.DataList;
import org.apache.http.util.TextUtils;
import org.jetbrains.annotations.Nullable;


import javax.swing.JDialog;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.JRadioButton;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.KeyStroke;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.awt.event.WindowListener;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
    private static final String FILE_NAME_REGEX = "(\\@ohos\\.)(.*?)(\\.d\\.ts)";
    private static final Pattern FILE_NAME_PATTERN = Pattern.compile(FILE_NAME_REGEX, Pattern.CASE_INSENSITIVE);
    private static final String NAMESPACE_REGEX = "declare namespace ([a-zA-Z_0-9]+) *(\\{)";
    private static final Pattern NAMESPACE_PATTERN = Pattern.compile(NAMESPACE_REGEX, Pattern.CASE_INSENSITIVE);
    private static final String CMAKE_SETCXX_TEMPLATE = "cmake_minimum_required(VERSION 3.4.1)"
            + FileUtil.getNewline() + "project(napi_lib)" + FileUtil.getNewline() + "set(CMAKE_CXX_STANDARD 17)"
            + FileUtil.getNewline() + FileUtil.getNewline();
    private static final String CMAKE_SETCXX_HASCMAKEFILE_TEMPLATE = FileUtil.getNewline()
            + "set(CMAKE_CXX_STANDARD 17)" + FileUtil.getNewline() + FileUtil.getNewline();
    private static final String CMAKE_ADD_LIB_TEMPLATE =
            "add_library(LIBNAME SHARED PATH/tool_utility.cpp PATH/FILE_PREFIX.cpp PATH/FILE_PREFIX_middle.cpp"
                    + " SERVICECODE)";
    private static final String CMAKE_LINK_TEMPLATE =
            "target_link_libraries(LIBNAME PUBLIC libace_napi.z.so libuv.so libhilog_ndk.z.so)";

    private final Project project;
    private List<String> tsFileList = new ArrayList<>();
    private List<Data> dataList = new ArrayList<>();
    private JPanel contentPane;

    private JTextField textFieldInterPath;
    private JTextField textFieldGenPath;
    private JTextField textFieldScriptPath;
    private JRadioButton radioButton;
    private JButton buttonSelectInter;
    private JButton buttonSelectGenPath;
    private JButton buttonSelectScriptPath;
    private JComboBox comboBox;
    private JButton buttonCfg;
    private String interFileOrDir;
    private String genOutDir;
    private String scriptOutDir;
    private String numberType;
    private boolean generateSuccess = true;
    private String sErrorMessage = "";
    private boolean isExistCmakeFile = false;
    private DataList list = new DataList(dataList);

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

        textFieldInterPath.setText(interFileOrDir);
        textFieldGenPath.setText(genOutDir);
        textFieldScriptPath.setText(genOutDir);

        // call onCancel() on ESCAPE
        contentPane.registerKeyboardAction(actionEvent -> onCancel(), KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
                JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT);

        BrowseAction browseAction = new BrowseAction(project, buttonSelectInter, textFieldInterPath,
                textFieldGenPath, textFieldScriptPath);
        buttonSelectInter.addActionListener(browseAction);
        buttonSelectGenPath.addActionListener(new GenAction(buttonSelectGenPath, textFieldGenPath));
        buttonSelectScriptPath.addActionListener(new ScriptAction(buttonSelectScriptPath, textFieldScriptPath));

        buttonCfg.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String genPath = textFieldGenPath.getText().trim();
                if (genPath.isEmpty()) {
                    // 提醒用户填写生成框架路径
                    GenNotification.notifyMessage(project, "请填写生成框架路径...", "生成框架路径不能为空",
                            NotificationType.WARNING);
                } else {
                    ShowCfgInfoDialog showCfgInfoDialog = new ShowCfgInfoDialog(list, genPath);
                    showCfgInfoDialog.showAndGet();
                }
            }
        });
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
        ValidationInfo validationInfo = null;
        String fileInter = textFieldInterPath.getText();
        String scriptDir = textFieldScriptPath.getText();
        String filegypDir = textFieldGenPath.getText();
        boolean isEmptyFile =
                TextUtils.isEmpty(fileInter) || TextUtils.isEmpty(scriptDir) || TextUtils.isEmpty(filegypDir);
        if (isEmptyFile) {
            String warnMsg = "接口文件、框架、编译脚本路径不能为空";
            warningMessage(warnMsg);
            validationInfo = new ValidationInfo(warnMsg);
            return validationInfo;
        }
        File file = new File(filegypDir + "/binding.gyp");
        if (file.exists()) {
            ConfirmDialog confirmDialog = new ConfirmDialog("是否替换已存在的编译脚本?");
            if (!confirmDialog.showAndGet()) {
                validationInfo = new ValidationInfo(String.format("不替换现有编译脚本：%s", file));
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
     * 执行主程序入口
     *
     * @return 执行状态
     */
    public boolean runFun() {
        // 获取dataList数据
        dataList = list.getDataList();
        // 写入cfg.json文件
        if (dataList.size() > 0) {
            writeJsonFile(dataList);
        }
        GenNotification.notifyMessage(this.project, "", "Generating Napi", NotificationType.INFORMATION);
        interFileOrDir = textFieldInterPath.getText();
        genOutDir = textFieldGenPath.getText();
        scriptOutDir = textFieldScriptPath.getText();
        numberType = comboBox.getSelectedItem().toString();
        String command;
        command = genCommand();

        File outPath = new File(textFieldGenPath.getText());
        List<FileInfo> oldFileList = getFileInfoList(outPath);
        try {
            if (!TextUtils.isEmpty(command) && callExtProcess(command)) {
                List<FileInfo> newFileList = getFileInfoList(outPath);
                newFileList.removeAll(oldFileList);

                GenNotification.notifyGenResult(project, newFileList, "Generate Napi Successfully",
                        NotificationType.INFORMATION);
                return true;
            }
        } catch (IOException | InterruptedException ex) {
            GenNotification.notifyMessage(project, textFieldGenPath.getText(), "Command exec error",
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
        String inArgs = genInArgs(interFileOrDir);
        command += inArgs + " -o " + genOutDir + " -i " + radioButton.isSelected() + " -n " + genNumbertypeArgs();
        // 用户未配置业务代码则不加 -s 参数
        String cfgFilePath = textFieldScriptPath.getText().trim() + "/cfg.json";
        File fileExist = new File(cfgFilePath);
        if (fileExist.exists()) {
            command += " -s " + cfgFilePath;
        }
        return command;
    }

    /**
     * 生成 -n 输入参数。
     *
     * @return 生成后的值-n的值
     */
    private String genNumbertypeArgs() {
        String type = "uint32_t";
        if (numberType != "") {
            type = numberType;
        }
        return type;
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

        if (generateSuccess) {
            writeCompileCfg();
        } else {
            GenNotification.notifyMessage(project, sErrorMessage, "提示", NotificationType.ERROR);
            return false;
        }

        errConsumer.join();
        outputConsumer.join();
        return true;
    }

    /**
     * 获取NAPI工具生成的cpp文件前缀
     *
     * @param tsFilePath ts接口文件名
     * @return cpp文件前缀
     */
    private String getCppNamePrefix(String tsFilePath) {
        File tsFile = new File(tsFilePath);

        // NAPI工具中cpp前缀名取的是ts文件中声明的首个namespace的名称，插件这里按同样方法获取。
        try (InputStreamReader read = new InputStreamReader(new FileInputStream(tsFile), StandardCharsets.UTF_8);
            BufferedReader bufferedReader = new BufferedReader(read)) {
            String line = "";
            while ((line = bufferedReader.readLine()) != null) {
                // 找到 "declare namespace" 这一行并将 namespace名称作为cpp文件前缀名返回。
                Matcher tsNamespaceMatcher = NAMESPACE_PATTERN.matcher(line);
                if (tsNamespaceMatcher.find()) {
                    return tsNamespaceMatcher.group(1);
                }
            }
        } catch (FileNotFoundException foundException) {
            LOG.error("The ts file " + tsFilePath + " does not exist.");
        } catch (IOException ioException) {
            LOG.error("Failed to read file, error: " + ioException);
        }
        return "";
    }

    /**
     * 使用 ts文件@ohos.xxx.d.ts中的xxx作为编译c++lib库的名字
     *
     * @param tsFileName ts文件名
     * @return 解析出的lib库名称
     */
    private String getLibNameFromTsFile(String tsFileName) {
        Matcher tsFileNameMatcher = FILE_NAME_PATTERN.matcher(tsFileName);
        if (!tsFileNameMatcher.find()) {
            LOG.warn("Invalid ts file name format, should be @ohos.xxx.d.ts.");
            return tsFileName;
        }
        return tsFileNameMatcher.group(2);
    }

    /**
     * 创建路径，将业务配置数据dataList写入Json文件,Json文件路径与Cmake路径一致
     * @param dataList 用户配置的数据
     * @throws IOException e
     */
    private void writeJsonFile(List<Data> dataList) {
        FileUtil fileUtil = new FileUtil();
        String cfgFilePath = fileUtil.makeFile(textFieldScriptPath.getText().trim() + "/cfg.json");

        if (TextUtils.isEmpty(cfgFilePath)) {
            LOG.info("cfgFile is fail");
            return;
        }
        try {
            // 创建 ObjectMapper 对象
            ObjectMapper mapper = new ObjectMapper();
            mapper.enable(SerializationFeature.INDENT_OUTPUT);

            // 将数据转换为 JSON 字符串
            String json = mapper.writeValueAsString(dataList);
            StringBuilder cfgJson = new StringBuilder(json);
            // 将 JSON 字符串写入文件
            String content = cfgJson.toString().replaceAll("\\\\n", "\\n");
            fileUtil.writeContentToFile(cfgFilePath, content, false);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * 生成编译文件
     */
    private void writeCompileCfg() {
        FileUtil fileUtil = new FileUtil();
        String cmakePath = scriptOutDir + "/CMakeLists.txt";
        File fileTmp = new File(cmakePath);
        if (fileTmp.exists()) {
            isExistCmakeFile = true;
        }
        // 若没有，则创建CMakeLists.txt文件
        String cmakeFilePath = fileUtil.makeFile(scriptOutDir + "/CMakeLists.txt");
        if (TextUtils.isEmpty(cmakeFilePath)) {
            LOG.info("makeFile is fail");
            return;
        }

        try {
            // 生成 CMakeList.txt文件内容
            StringBuilder cmakeBuilder = new StringBuilder(CMAKE_SETCXX_TEMPLATE);
            // 若工程目录存在CMakeLists.txt文件
            if (isExistCmakeFile) {
                cmakeBuilder = new StringBuilder(CMAKE_SETCXX_HASCMAKEFILE_TEMPLATE);
            }
            // 获取工具代码cpp文件相对于CMakeList.txt文件的路径
            String cppRelativePath = fileUtil.getRelativePath(new File(genOutDir).getPath(),
                    new File(scriptOutDir).getPath());
            String serviceCodeCfg = getCmakeLib();
            for (String tsFilePath : tsFileList) {
                String cppNamePrefix = getCppNamePrefix(tsFilePath);
                String libName = getLibNameFromTsFile(new File(tsFilePath).getName());
                String libStr = CMAKE_ADD_LIB_TEMPLATE.replaceAll("LIBNAME", libName)
                        .replaceAll("PATH/", cppRelativePath).replaceAll("FILE_PREFIX", cppNamePrefix)
                                .replaceAll("SERVICECODE", serviceCodeCfg);
                cmakeBuilder.append(libStr).append(FileUtil.getNewline());

                cmakeBuilder.append(CMAKE_LINK_TEMPLATE.replaceAll("LIBNAME", libName))
                        .append(FileUtil.getNewline());
            }
            fileUtil.writeContentToFile(cmakeFilePath, cmakeBuilder.toString(), true);

            // 需要在main文件夹下创建cpp目录, 如果没有此目录，DevEco 3.0版本编译时不会编译任何目录中的c++代码。
            Path path = Paths.get(project.getBasePath() + "/entry/src/main/cpp");
            Files.createDirectories(path);

            // 在{ProjectRoot}/entry/build-profile.json5 中增加 externalNativeOptions 配置
            String buildJsonFilePath = project.getBasePath() + "/entry/build-profile.json5";

            // 获取CMakeLists.txt相对于build-profile.json5构建文件的相对路径
            String cmakeRelativePath = fileUtil.getRelativePath(new File(cmakeFilePath).getParent(),
                    new File(buildJsonFilePath).getParent());

            fileUtil.writeBuildJsonFile(buildJsonFilePath, cmakeRelativePath + "CMakeLists.txt");
        } catch (IOException ioException) {
            LOG.error("writeCommand io error" + ioException);
        }
    }

    /**
     * 获取业务代码相对于CMakeLists.txt的相对路径。
     *
     * @return 业务代码相对于CMakeLists.txt的相对路径
     */
    private String getCmakeLib() {
        FileUtil fileUtil = new FileUtil();
        String serviceCodeCfg = "";
        // 获取用户配置的业务cpp相对路径
        for (Data data : dataList) {
            String cppNamePath = data.getCppName();
            // 获取cppNamePath的绝对路径
            Path absGenPath = Paths.get(new File(scriptOutDir).getPath());
            Path relativePath = Paths.get(cppNamePath);
            Path resolvedPath = absGenPath.resolveSibling(relativePath).normalize();
            String absCppNamePath = resolvedPath.toAbsolutePath().toString();
            // 获取业务代码cpp文件相对于CMakeLists.txt的路径
            String codeRelativePath = fileUtil.getRelativePath(new File(absCppNamePath).getPath(),
                    new File(scriptOutDir).getPath());
            // 去掉最后的斜杠"/"
            codeRelativePath = codeRelativePath.substring(0, codeRelativePath.length() - 1);
            if (serviceCodeCfg.indexOf(codeRelativePath) < 0) {
                serviceCodeCfg += codeRelativePath + " ";
            }
        }
        return serviceCodeCfg;
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
                    LOG.error("StreamConsumer" + line);
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


    JPanel getContentPanel() {
        return contentPane;
    }

}
