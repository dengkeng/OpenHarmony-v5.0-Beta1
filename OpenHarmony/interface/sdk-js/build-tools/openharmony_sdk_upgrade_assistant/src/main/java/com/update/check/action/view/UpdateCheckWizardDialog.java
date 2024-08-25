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

import com.alibaba.fastjson.JSON;
import com.update.check.dto.UpdateCheckReportDto;
import com.update.check.utils.IoUtils;
import com.update.check.action.DataUpdateNotifier;
import com.update.check.dto.ApiDiffResultDto;
import com.update.check.dto.CollectApplicationApiDto;
import com.update.check.log.Logger;
import com.update.check.utils.FileUtils;
import com.intellij.openapi.fileChooser.FileChooserDescriptor;
import com.intellij.openapi.progress.ProgressManager;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.ui.DialogWrapper;
import com.intellij.openapi.ui.TextFieldWithBrowseButton;
import org.apache.commons.lang.StringUtils;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import javax.swing.JPanel;
import javax.swing.JLabel;
import javax.swing.KeyStroke;
import javax.swing.JComponent;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.io.File;
import java.io.IOException;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.util.List;
import java.util.ArrayList;
import java.util.Locale;
import java.util.LinkedHashMap;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ForkJoinPool;

/**
 * UpdateCheckWizardDialog
 *
 * @since 23-04-07
 */
public class UpdateCheckWizardDialog extends DialogWrapper {
    private static final String LOG_TAG = UpdateCheckWizardDialog.class.getName();

    private static final Logger LOGGER = Logger.createLogger();

    private static final int DELETE = 0;

    private static final int MODEL_CHANGES = 13;

    private static final int SYSTEM_API_CHANGES = 9;

    private static final int PERMISSION_CHANGES = 12;

    private static final int NEW_ERROR_CODE = 6;

    private static final int DEPRECATED_CHANGES = 5;

    private static final int FUNCTION_CHANGES = 16;

    private static final int BEHAVIOR_CHANGE = 17;

    private static final String REPORT_DEPRECATED = "api已废弃";

    private static final String REPORT_NEW_ERROR_CODE = "api新增(错误码)";

    private static final String REPORT_PERMISSION_CHANGE = "api权限有变化";

    private static final String REPORT_SYSTEM_API_CHANGES = "api访问级别有变化";

    private static final String REPORT_MODEL_CHANGE = "api模型使用限制变化";

    private static final String REPORT_CHANGELOG = "api底层行为变更";

    private static final String REPORT_FUNCTION_CHANGES = "api函数有变化";

    private static final String REPORT_DELETE = "api删除";

    private static final int DIFF_ADD_NEW_API = 3;

    private JPanel centerPanel;

    private TextFieldWithBrowseButton textFieldOldSdkPath;

    private TextFieldWithBrowseButton textFieldNewSdkPath;

    private JLabel labelErrorNotice;

    private Project project;

    private String lastDir;

    private String applicationApiType;

    private List<UpdateCheckReportDto> updateCheckReportDtos = new ArrayList<>();

    private List<CollectApplicationApiDto> deprecatedApiResults = new ArrayList<>();

    private String newSdkVersion;

    private String oldSdkVersion;

    private String newSdkFilePath;

    private String reportPath;

    private FileUtils fileUtils;

    /**
     * UpdateCheckWizardDialog
     *
     * @param project project
     */
    public UpdateCheckWizardDialog(@NotNull Project project) {
        super(project, false);
        this.project = project;
        this.fileUtils = new FileUtils();
        this.getNewSdkFilePath();
        this.setTitle(ConstString.get("check.dialog.title"));
        this.textFieldNewSdkPath.setText(this.newSdkFilePath);
        this.applicationApiType = FileUtils.getApplicationApiType(project.getBasePath());
        this.initEventListeners();
        this.lastDir = FileUtils.getLastDir();
        this.init();
    }

    /**
     * UpdateCheckWizardDialog
     *
     * @param project project
     * @param canBeParent canBeParent
     * @param okAction okAction
     */
    protected UpdateCheckWizardDialog(@Nullable Project project, boolean canBeParent, @Nullable Runnable okAction) {
        super(project, canBeParent);
    }

    private void initEventListeners() {
        this.textFieldNewSdkPath.addBrowseFolderListener(ConstString.get("check.dir.path"),
                ConstString.get("check.dir.path"),
                this.project,
                new FileChooserDescriptor(false, true, false, false, false, false)
        );

        this.textFieldOldSdkPath.addBrowseFolderListener(ConstString.get("check.old.dir.path"),
                ConstString.get("check.old.dir.path"),
                this.project,
                new FileChooserDescriptor(false, true, false, false, false, false)
        );
        this.centerPanel.registerKeyboardAction(this::onCancel,
                KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
                JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT);
    }

    private void getNewSdkFilePath() {
        try {
            String sdkDir = FileUtils.getNodePath(this.project.getBasePath(), "local.properties", "sdk.dir");
            if (sdkDir == null) {
                return;
            }
            String compileSdkVersion = FileUtils.getCompileSdkVersion(this.project.getBasePath());
            if ("null".equals(compileSdkVersion)) {
                this.labelErrorNotice.setText(ConstString.get("check.unable.to.obtain.sdk"));
                return;
            }
            File file = new File(sdkDir, compileSdkVersion + ConstString.get("check.ets"));
            this.newSdkFilePath = file.getPath();
        } catch (IOException e) {
            LOGGER.error(LOG_TAG, "Get new sdk file path error! " + e.getMessage());
        }
    }

    private void process() {

        // decompression tools
        this.fileUtils.getApiTools();

        // get old and new sdk version
        this.getSdkVersion();

        // run api tools asynchronously
        CompletableFuture.allOf(CompletableFuture.runAsync(this::runApiDiffTool,
                        ForkJoinPool.commonPool()),
                CompletableFuture.runAsync(this::runApiCollectTool,
                        ForkJoinPool.commonPool())).join();

        // process and filter data
        this.processAndFilterData();

        // updateReport Save to disk
        this.saveReportToDisk();
    }

    private void saveReportToDisk() {
        LOGGER.info(LOG_TAG, "Start save report to disk");
        String reportStr = JSON.toJSONString(this.updateCheckReportDtos);
        FileUtils.writerJsonToFile(reportStr, this.reportPath + ConstString.get("check.report"));
        LOGGER.info(LOG_TAG, "Save report to disk end");
    }

    private void runApiDiffTool() {
        BufferedReader bufferedReader = null;
        try {
            LOGGER.info(LOG_TAG, "Start run api diff tool");
            // is it cached
            File diffResultPath = new File(this.lastDir + ConstString.get("check.diff.result")
                    + "diff(" + this.oldSdkVersion + "_" + this.newSdkVersion + ")" + ".json");
            if (diffResultPath.exists()) {
                LOGGER.info(LOG_TAG, "diff result already exists");
                return;
            }
            File resultPath = new File(this.lastDir + ConstString.get("check.diff.result"));
            if (!resultPath.exists()) {
                resultPath.mkdirs();
            }
            String orders = "node api-diff.js --old " + this.textFieldOldSdkPath.getText() + " --new " +
                    this.newSdkFilePath + " --oldVersion " + this.oldSdkVersion + " --newVersion " +
                    this.newSdkVersion + " --output " + this.lastDir +
                    ConstString.get("check.format");
            LOGGER.info(LOG_TAG, "diff order:" + orders);
            ProcessBuilder builder = new ProcessBuilder();
            builder.directory(new File(FileUtils.getLastDir().split(":")[0] + ":\\updateCheck\\api-diff"));
            builder.command("cmd.exe", "/c", orders);
            Process start = builder.start();
            bufferedReader = new BufferedReader(
                    new InputStreamReader(start.getInputStream(), Charset.forName("GBK")));
            String line;
            while ((line = bufferedReader.readLine()) != null) {
                System.out.println(line);
            }
            LOGGER.info(LOG_TAG, "Run api diff tool end");
        } catch (IOException e) {
            LOGGER.error(LOG_TAG, "Run api diff tool error! " + e.getMessage());
        } finally {
            try {
                if (bufferedReader != null) {
                    bufferedReader.close();
                }
            } catch (IOException e) {
                LOGGER.error(LOG_TAG, "Run api diff tool IO flow shutdown exception. " + e.getMessage());
            }
        }
    }

    private void runApiCollectTool() {
        BufferedReader bufferedReader = null;
        try {
            LOGGER.info(LOG_TAG, "Start run api collect tool");
            File updateCheck = new File(this.project.getBasePath(), "updateCheck");
            this.reportPath = updateCheck.toString();
            String orders = "node api-collector.js --app " + this.project.getBasePath() +
                    " --output " + updateCheck + " --sdk " +
                    this.textFieldOldSdkPath.getText() + " --format json";
            ProcessBuilder builder = new ProcessBuilder();
            builder.directory(new File(FileUtils.getLastDir().split(":")[0] +
                    ":\\updateCheck\\collect_application_api"));
            LOGGER.info(LOG_TAG, "application order:" + orders);
            builder.command("cmd.exe", "/c", orders);
            Process start = builder.start();
            bufferedReader = new BufferedReader(
                    new InputStreamReader(start.getInputStream(), Charset.forName("GBK")));
            String line;
            while ((line = bufferedReader.readLine()) != null) {
                System.out.println(line);
            }
            LOGGER.info(LOG_TAG, "Run api collect tool end");
        } catch (IOException e) {
            LOGGER.error(LOG_TAG, "Run api collect tool error! " + e.getMessage());
        } finally {
            try {
                if (bufferedReader != null) {
                    bufferedReader.close();
                }
            } catch (IOException e) {
                LOGGER.error(LOG_TAG, "Run api collect tool IO flow shutdown exception. " + e.getMessage());
            }
        }
    }

    private List<ApiDiffResultDto> getApiDiffResult() {
        List<ApiDiffResultDto> apiDiffResults = new ArrayList<>();
        try {
            String diffJsonFilePath = this.lastDir + ConstString.get("check.diff.path") +
                    this.oldSdkVersion + "_" + this.newSdkVersion + ").json";
            apiDiffResults = FileUtils.readJsonFileToJavaList(diffJsonFilePath, ApiDiffResultDto.class);
            return apiDiffResults;
        } catch (IOException e) {
            LOGGER.error(LOG_TAG, "Get api diff result error! " + e.getMessage());
            return apiDiffResults;
        }
    }

    private List<CollectApplicationApiDto> getAllCollectApiResult() {
        List<CollectApplicationApiDto> collectApplicationApiDtos = new ArrayList<>();
        try {
            File allApiJsonFilePath = new File(this.reportPath, "collectedApi.json");
            collectApplicationApiDtos = FileUtils.readJsonFileToJavaList(allApiJsonFilePath.toString(),
                    CollectApplicationApiDto.class);
            if (collectApplicationApiDtos == null) {
                return new ArrayList<>();
            }
            for (CollectApplicationApiDto allApi : collectApplicationApiDtos) {
                if (StringUtils.isNotBlank(allApi.getDeprecated())) {
                    this.deprecatedApiResults.add(allApi);
                }
            }
            return collectApplicationApiDtos;
        } catch (IOException e) {
            LOGGER.error(LOG_TAG, "Get collect api result error! " + e.getMessage());
            return collectApplicationApiDtos;
        }
    }

    private void processAndFilterData() {
        LOGGER.info(LOG_TAG, "Start process and filter data");
        List<ApiDiffResultDto> apiDiffResultDtos = this.getApiDiffResult();
        List<CollectApplicationApiDto> allApiResult = this.getAllCollectApiResult();
        List<Integer> subscript = new ArrayList<>();

        // filter data
        for (ApiDiffResultDto apiDto : apiDiffResultDtos) {
            if (apiDto.getStatusCode() == null || apiDto.getStatusCode() == DIFF_ADD_NEW_API) {
                continue;
            }
            if (apiDto.getStatusCode() == BEHAVIOR_CHANGE) {
                UpdateCheckReportDto updateCheckReportDto = new UpdateCheckReportDto();
                updateCheckReportDto.setPos(ConstString.get("not.involved"));
                updateCheckReportDto.setReminderInformation(
                        ConstString.get("underlying.behavior"));
                updateCheckReportDto.setApiDefinition(ConstString.get("not.involved"));
                updateCheckReportDto.setSourceFileName(ConstString.get("not.involved"));
                updateCheckReportDto.setChangelogs(apiDto.getChangelogs());
                updateCheckReportDto.setChangeType(REPORT_CHANGELOG);
                this.updateCheckReportDtos.add(updateCheckReportDto);
                continue;
            }
            this.handleDeprecatedApi(subscript, apiDto);
            this.judgeCollDiff(allApiResult, apiDto);
        }
        this.addDeprecatedToReport(subscript);
        LOGGER.info(LOG_TAG, "Process and filter data end");
    }

    private void judgeCollDiff(List<CollectApplicationApiDto> allApiResult, ApiDiffResultDto apiDto) {
        for (CollectApplicationApiDto collApiDto : allApiResult) {
            if (this.judgeApi(apiDto, collApiDto)) {
                UpdateCheckReportDto reportDtoToCheck = this.generateReportData(apiDto, collApiDto);
                if (reportDtoToCheck != null) {
                    this.updateCheckReportDtos.add(reportDtoToCheck);
                }
            }
        }
    }

    private void handleDeprecatedApi(List<Integer> subscript, ApiDiffResultDto apiDto) {
        for (int i = 0; i < this.deprecatedApiResults.size(); i++) {
            if (apiDto.getStatusCode() == DEPRECATED_CHANGES || apiDto.getStatusCode() == DELETE) {
                if (this.judgeApi(apiDto, this.deprecatedApiResults.get(i))) {
                    subscript.add(i);
                }
            }
        }
    }

    private void addDeprecatedToReport(List<Integer> subscript) {
        for (int i = 0; i < this.deprecatedApiResults.size(); i++) {
            if (!subscript.contains(i)) {
                UpdateCheckReportDto updateCheckReportDto = new UpdateCheckReportDto();

                // fill data
                updateCheckReportDto.setApiDefinition(this.deprecatedApiResults.get(i).getApiText());
                String reminderInformation =
                        (StringUtils.isBlank(this.deprecatedApiResults.get(i).getUseinstead()))
                                ? ConstString.get("obsolete.version.change.to")
                                : ConstString.get("obsolete.version.change.to") +
                                ConstString.get("api.recommended.use") +
                                this.deprecatedApiResults.get(i).getUseinstead();
                updateCheckReportDto.setReminderInformation(reminderInformation);
                updateCheckReportDto.setChangeType(REPORT_DEPRECATED);
                updateCheckReportDto.setSourceFileName(this.deprecatedApiResults.get(i).getSourceFileName());
                updateCheckReportDto.setPos(this.deprecatedApiResults.get(i).getPos());
                updateCheckReportDto.setChangelogs(null);
                this.updateCheckReportDtos.add(updateCheckReportDto);
            }
        }
    }

    private boolean judgeApi(ApiDiffResultDto apiDto, CollectApplicationApiDto collApiDto) {
        return apiDto.getDtsName().equals(collApiDto.getDtsName())
                && apiDto.getRawText().equals(collApiDto.getApiText())
                && apiDto.getClassName().equals(collApiDto.getTypeName());
    }

    private UpdateCheckReportDto generateReportData(ApiDiffResultDto apiDto,
                                                    CollectApplicationApiDto collApiDto) {
        UpdateCheckReportDto updateCheckReportDto = null;
        int statusCode = apiDto.getStatusCode();
        String checkOld = convertString(apiDto.getOldMessage());
        String checkNew = convertString(apiDto.getNewMessage());
        switch (statusCode) {
            case FUNCTION_CHANGES:
                updateCheckReportDto = new UpdateCheckReportDto(apiDto,
                        ConstString.get("version.change") +
                                apiDto.getNewMessage(), collApiDto, REPORT_FUNCTION_CHANGES);
                break;
            case MODEL_CHANGES:
                UpdateCheckReportDto report = this.setApiModelChange(apiDto, collApiDto);
                if (report != null) {
                    updateCheckReportDto = report;
                }
                break;
            case SYSTEM_API_CHANGES:
                updateCheckReportDto = new UpdateCheckReportDto(apiDto,
                        ConstString.get("level.change.to") + checkOld +
                                ConstString.get("check.change.to") + checkNew, collApiDto, REPORT_SYSTEM_API_CHANGES);
                break;
            case PERMISSION_CHANGES:
                updateCheckReportDto = new UpdateCheckReportDto(apiDto,
                        ConstString.get("authority.change.to") +
                                checkOld + ConstString.get("check.change.to") + checkNew,
                        collApiDto, REPORT_PERMISSION_CHANGE);
                break;
        }
        if (updateCheckReportDto != null) {
            return updateCheckReportDto;
        }
        return this.assignmentReport(statusCode, apiDto, collApiDto);
    }

    private UpdateCheckReportDto assignmentReport(int statusCode,
                                                  ApiDiffResultDto apiDto, CollectApplicationApiDto collApiDto) {
        UpdateCheckReportDto reportDto = null;
        String checkNew = convertString(apiDto.getNewMessage());
        switch (statusCode) {
            case NEW_ERROR_CODE:
                reportDto = new UpdateCheckReportDto(apiDto,
                        ConstString.get("add.error.code") + checkNew, collApiDto, REPORT_NEW_ERROR_CODE);
                break;
            case DEPRECATED_CHANGES:
                String useInstead = apiDto.getHint();
                if (StringUtils.isBlank(useInstead)) {
                    reportDto = new UpdateCheckReportDto(apiDto,
                            ConstString.get("obsolete.version.change.to"), collApiDto, REPORT_DEPRECATED);
                } else {
                    reportDto = new UpdateCheckReportDto(apiDto,
                            ConstString.get("obsolete.version.change.to") + ConstString.get("api.recommended.use") +
                                    useInstead.replace("useinstead: ", ""), collApiDto, REPORT_DEPRECATED);
                }
                break;
            case DELETE:
                reportDto = new UpdateCheckReportDto(apiDto,
                        ConstString.get("check.api.deleted"), collApiDto, REPORT_DELETE);
                break;
        }
        return reportDto;
    }

    private String convertString(String str) {
        return StringUtils.isBlank(str) ? ConstString.get("check.nothing") : str;
    }

    private UpdateCheckReportDto setApiModelChange(ApiDiffResultDto apiDto, CollectApplicationApiDto collApiDto) {
        if (StringUtils.isBlank(apiDto.getNewMessage())) {
            return null;
        }

        if (apiDto.getNewMessage().toLowerCase().startsWith(this.applicationApiType.toLowerCase(Locale.ROOT))) {
            return null;
        }

        String oldModelOnly = StringUtils.isBlank(
                apiDto.getOldMessage())
                ? ConstString.get("check.nothing")
                : apiDto.getOldMessage();

        return new UpdateCheckReportDto(apiDto, ConstString.get("check.model.change.to") +
                oldModelOnly + ConstString.get("check.change.to") +
                apiDto.getNewMessage(), collApiDto, REPORT_MODEL_CHANGE);

    }

    private File readOldSdkPath() {
        if (!IoUtils.isValidLocalPath(this.textFieldOldSdkPath.getText())) {
            this.labelErrorNotice.setText(ConstString.get("check.old.sdk.path"));
            return null;
        }
        if (this.isEtsFilePath(this.textFieldOldSdkPath.getText())) {
            this.labelErrorNotice.setText(ConstString.get("check.old.sdk.file.path"));
            return null;
        }
        return new File(this.textFieldOldSdkPath.getText());
    }

    private File readNewSdkPath() {
        if (!IoUtils.isValidLocalPath(this.textFieldNewSdkPath.getText())) {
            this.labelErrorNotice.setText(ConstString.get("check.new.sdk.path"));
            return null;
        }
        if (this.isEtsFilePath(this.textFieldNewSdkPath.getText())) {
            this.labelErrorNotice.setText(ConstString.get("check.new.sdk.file.path"));
            return null;
        }
        return new File(this.textFieldNewSdkPath.getText());
    }

    private void getSdkVersion() {
        this.oldSdkVersion = FileUtils.getSdkVersionFromJsonFile(
                this.textFieldOldSdkPath.getText() + ConstString.get("check.package"));
        this.newSdkVersion = FileUtils.getSdkVersionFromJsonFile(
                this.newSdkFilePath + ConstString.get("check.package"));
    }

    @Override
    protected JComponent createCenterPanel() {
        return this.centerPanel;
    }

    @Override
    protected void doOKAction() {
        File oldSdkPath = this.readOldSdkPath();
        if (oldSdkPath == null) {
            LOGGER.info(LOG_TAG, "old sdk path is null.");
            return;
        }

        File newSdkPath = this.readNewSdkPath();
        if (newSdkPath == null) {
            LOGGER.info(LOG_TAG, "new sdk path is null.");
            return;
        }
        super.doOKAction();
        ProgressManager.getInstance().runProcessWithProgressSynchronously(
                this::process, ConstString.get("check.generating.report"), false, this.project);
        MessageBox.showDialog(this.project,
                ConstString.get("report.successfully"),
                ConstString.get("check.view.report"));
        DataUpdateNotifier
                .getInstance()
                .notifyDataChange(new LinkedHashMap<String, Boolean>(), "executeAgain");
    }

    private void onCancel(@Nullable ActionEvent event) {
        super.doCancelAction();
        dispose();
    }

    private boolean isEtsFilePath(String filePath) {
        File apiFile = new File(filePath, "api");
        File componentFile = new File(filePath, "component");
        return !apiFile.exists() || !componentFile.exists();
    }

    @Override
    public void doCancelAction() {
        this.onCancel(null);
    }

    /**
     * showDialog
     *
     * @param project project
     */
    public static synchronized void showDialog(Project project) {
        UpdateCheckWizardDialog updateCheckWizardDialog = new UpdateCheckWizardDialog(project);
        updateCheckWizardDialog.show();
    }

}
