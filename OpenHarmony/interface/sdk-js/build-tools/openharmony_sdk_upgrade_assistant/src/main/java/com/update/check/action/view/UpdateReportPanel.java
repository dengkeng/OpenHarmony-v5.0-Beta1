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

import com.update.check.dto.UpdateCheckReportDto;
import com.update.check.action.DataUpdateNotifier;
import com.update.check.dto.ApiDiffResultDto;
import com.update.check.log.Logger;
import com.update.check.utils.FileUtils;
import com.intellij.openapi.Disposable;
import com.intellij.openapi.editor.Editor;
import com.intellij.openapi.editor.CaretModel;
import com.intellij.openapi.editor.LogicalPosition;
import com.intellij.openapi.editor.ScrollType;
import com.intellij.openapi.editor.ScrollingModel;
import com.intellij.openapi.fileEditor.FileEditorManager;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.util.Disposer;
import com.intellij.openapi.vfs.LocalFileSystem;
import com.intellij.openapi.vfs.VirtualFile;
import com.intellij.openapi.wm.ToolWindow;
import com.intellij.ui.content.Content;
import com.intellij.ui.content.ContentManager;
import org.apache.commons.lang.StringUtils;
import org.jetbrains.annotations.NotNull;

import javax.swing.JPanel;
import javax.swing.JButton;
import javax.swing.JTable;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.table.TableColumn;
import javax.swing.table.AbstractTableModel;
import java.awt.Desktop;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;
import java.util.List;
import java.util.LinkedHashMap;
import java.util.ArrayList;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * UpdateReportPanel
 *
 * @since 23-04-07
 */
public class UpdateReportPanel implements Disposable {
    private static final Logger LOGGER = Logger.createLogger();

    private static final String LOG_TAG = UpdateReportPanel.class.getName();

    private JPanel rootPanel;

    private JTable updateReport;

    private JLabel sumLabel;

    private JButton chooseTypeButton;

    private Project project;

    private Map<String, String> changeLogs = new HashMap<>();

    private List<UpdateCheckReportDto> reportDtos = new ArrayList<>();

    private LinkedHashMap<String, Boolean> arrayTypes = new LinkedHashMap<>();

    /**
     * UpdateReportPanel
     *
     * @param project project
     */
    public UpdateReportPanel(Project project) {
        this.project = project;
        Report report = new Report();
        this.updateReport.setModel(report);
        this.setTableStyle();
    }

    @Override
    public void dispose() {

    }

    /**
     * loadPanel
     *
     * @param project    project
     * @param toolWindow toolWindow
     */
    public static void loadPanel(@NotNull Project project, @NotNull ToolWindow toolWindow) {
        UpdateReportPanel updateReportPanel = new UpdateReportPanel(project);
        ContentManager contentManager = toolWindow.getContentManager();
        Content content = contentManager.getFactory().createContent(
                updateReportPanel.getPanel(), "Report", false);
        contentManager.addContent(content);
        Disposer.register(project, updateReportPanel);
    }

    /**
     * getPanel
     *
     * @return rootPanel
     */
    public JComponent getPanel() {
        return this.rootPanel;
    }

    private void filterType() {
        this.updateChooseType();
        this.setUpdateReportStyle();
    }

    private void updateChooseType() {
        List<UpdateCheckReportDto> typeDto = reportDtos.stream().distinct()
                .filter(distinctByKey(UpdateCheckReportDto::getChangeType))
                .collect(Collectors.toList());
        arrayTypes.clear();
        arrayTypes.put(ConstString.get("check.choose.all"), true);
        if (typeDto.size() == 0) {
            return;
        }
        for (UpdateCheckReportDto dto : typeDto) {
            if (dto == null) {
                break;
            }
            arrayTypes.put(dto.getChangeType(), true);
        }
    }

    private void setTableStyle() {
        LOGGER.info(LOG_TAG, "Start rendering JTable");
        this.filterType();
        this.chooseTypeButton.setText(ConstString.get("check.choose.type"));
        this.chooseTypeButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                ShowTypeDialog.showDialog(project, arrayTypes);
            }
        });
        LOGGER.info(LOG_TAG, "Rendering JTable end");
    }

    private void setUpdateReportStyle() {

        // Set Table Row Height
        this.updateReport.setRowHeight(30);

        // add addMouseListener
        this.updateReport.setRowSelectionAllowed(true);
        this.updateReport.setColumnSelectionAllowed(true);
        this.setUpdateStyle();
        this.setListenerToReportPanel();
    }

    private void setUpdateStyle() {
        TableColumn tc = this.updateReport.getColumnModel().getColumn(0);
        tc.setCellEditor(this.updateReport.getDefaultEditor(Boolean.class));
        tc.setCellRenderer(this.updateReport.getDefaultRenderer(Boolean.class));
        tc.setPreferredWidth(100);
        tc.setMaxWidth(100);
        tc.setMinWidth(100);
        TableColumn tableColumn = this.updateReport.getColumnModel().getColumn(5);
        tableColumn.setPreferredWidth(200);
        tableColumn.setMaxWidth(200);
        tableColumn.setMinWidth(200);
    }

    private void setListenerToReportPanel() {
        this.updateReport.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                int col = updateReport.columnAtPoint(e.getPoint());
                int row = updateReport.getSelectedRow();

                // api in simple address
                if (col == 4 && e.getClickCount() == 2) {
                    Object valueAt1 = updateReport.getValueAt(row, 4);
                    String valueAt = null;
                    if (valueAt1 instanceof String) {
                        valueAt = (String) valueAt1;
                    }
                    if (StringUtils.isBlank(valueAt)) {
                        return;
                    }
                    if (getApiInApplicationPath(valueAt) == null) {
                        return;
                    }
                    try {
                        VirtualFile fileByIoFile = LocalFileSystem
                                .getInstance()
                                .findFileByIoFile(new File(project.getBasePath(),
                                        getApiInApplicationPath(valueAt)));
                        FileEditorManager.getInstance(project).openFile(fileByIoFile, true);
                        gotoLine(Integer.parseInt(valueAt.replaceAll(ConstString.get("check.replace"), "$1")));
                    } catch (IllegalArgumentException exception) {
                        MessageBox.showDialog(project, "", ConstString.get("can.not.find.file"));
                    }
                } else if (col == 5) {
                    Object childValue = updateReport.getValueAt(row, 5);
                    String valueAt = null;
                    if (childValue instanceof String) {
                        valueAt = (String) childValue;
                    }
                    if (StringUtils.isBlank(valueAt)) {
                        return;
                    }
                    if (valueAt.split(",").length == 1) {
                        clickUrl(changeLogs.get(valueAt));
                        return;
                    }
                    ShowChangeLogsDialog.showDialog(project, changeLogs, valueAt);
                }
            }
        });
    }

    private String getApiInApplicationPath(String apiAddress) {
        String pattern = ConstString.get("check.report.pattern");
        Pattern r = Pattern.compile(pattern);
        Matcher m = r.matcher(apiAddress);
        if (m.find()) {
            return m.group(0);
        }
        return null;
    }

    private void clickUrl(String url) {
        try {
            if (StringUtils.isNotBlank(url)) {
                Desktop desktop = Desktop.getDesktop();
                URI uri = new URI(url);
                desktop.browse(uri);
            }
        } catch (URISyntaxException | IOException exception) {
            exception.printStackTrace();
            LOGGER.error(LOG_TAG, "Click " + url + " error! " + exception.getMessage());
        }
    }

    private void gotoLine(int lineNumber) {
        Editor editor = FileEditorManager.getInstance(this.project).getSelectedTextEditor();
        if (editor == null) {
            return;
        }
        CaretModel caretModel = editor.getCaretModel();
        int totalLineCount = editor.getDocument().getLineCount();
        if (lineNumber > totalLineCount) {
            return;
        }

        // Moving caret to line number
        caretModel.moveToLogicalPosition(new LogicalPosition(lineNumber - 1, 0));

        // Scroll to the caret
        ScrollingModel scrollingModel = editor.getScrollingModel();
        scrollingModel.scrollToCaret(ScrollType.CENTER);
    }

    class Report extends AbstractTableModel implements DataUpdateNotifier.UpdateListener {
        List<Object[]> dataList = new ArrayList<>();
        String[] titles = new String[7];
        int sum = 0;

        /**
         * Report
         */
        public Report() {
            LOGGER.info(LOG_TAG, "Start loading report window");
            DataUpdateNotifier.getInstance().addUpdateListener(this);
            this.getReportResult();
            this.initReport(new LinkedHashMap<>());
            LOGGER.info(LOG_TAG, "Loading report window end");
        }

        private void getReportResult() {
            try {
                File resultJsonFile = new File(project.getBasePath(),
                        ConstString.get("check.report.json"));
                List<UpdateCheckReportDto> updateCheckReportDtos =
                        FileUtils.readJsonFileToJavaList(resultJsonFile.toString(),
                                UpdateCheckReportDto.class);
                reportDtos = updateCheckReportDtos;
                LOGGER.info(LOG_TAG, "Report size:" + updateCheckReportDtos.size());
            } catch (IOException e) {
                LOGGER.error(LOG_TAG, e.getMessage());
            }
        }

        private List<UpdateCheckReportDto> screenResult(LinkedHashMap<String, Boolean> changeTypes) {
            if (changeTypes.size() == 0) {
                return reportDtos;
            }
            List<String> chooseTypes = new ArrayList<>();
            for (Map.Entry<String, Boolean> entry : changeTypes.entrySet()) {
                if (entry.getValue()) {
                    chooseTypes.add(entry.getKey());
                }
            }
            return this.multipleChoice(chooseTypes);
        }

        private List<UpdateCheckReportDto> multipleChoice(List<String> chooseTypes) {
            List<UpdateCheckReportDto> multipleChoice = new ArrayList<>();
            for (String changeType : chooseTypes) {
                for (UpdateCheckReportDto dto : reportDtos) {
                    if (dto != null && dto.getChangeType().equals(changeType)) {
                        multipleChoice.add(dto);
                    }
                }
            }
            return multipleChoice;
        }

        private void update(LinkedHashMap<String, Boolean> chooseType, String type) {
            LOGGER.info(LOG_TAG, "Start reload report window");
            dataList.clear();
            if ("executeAgain".equals(type)) {
                this.getReportResult();
                updateChooseType();
            } else {
                arrayTypes = chooseType;
            }
            this.initReport(chooseType);
            fireTableDataChanged();
            LOGGER.info(LOG_TAG, "Reload report window end");
        }

        private void initReport(LinkedHashMap<String, Boolean> changeTypes) {
            List<UpdateCheckReportDto> reportResult = this.screenResult(changeTypes);
            if (reportResult == null) {
                return;
            }
            sum = reportResult.size();
            sumLabel.setText(ConstString.get("sum.report") + sum);
            for (int i = 0; i < reportResult.size(); i++) {
                UpdateCheckReportDto report = reportResult.get(i);
                String filePath = report
                        .getSourceFileName()
                        .replace(project.getBasePath() + "/", "");
                dataList.add(new Object[]{false
                        , ConstString.get("not.involved")
                        .equals(report.getSourceFileName())
                        ? report.getSourceFileName()
                        : getFileName(report.getSourceFileName())
                        , report.getApiDefinition(), report.getReminderInformation()
                        , ConstString.get("not.involved").equals(report.getPos())
                        ? report.getPos() : filePath + "(" + report.getPos() + ")"
                        , this.setChangeLogUrl(report.getChangelogs())});
            }
            titles[0] = ConstString.get("check.report.order.number");
            titles[1] = ConstString.get("check.report.ets.name");
            titles[2] = ConstString.get("report.old.method.text");
            titles[3] = ConstString.get("report.new.method.text");
            titles[4] = ConstString.get("report.function.position");
            titles[5] = ConstString.get("report.change.log");
        }

        private String setChangeLogUrl(List<ApiDiffResultDto.Changelog> changelogs) {
            if (changelogs == null) {
                return "";
            }
            StringBuilder sb = new StringBuilder();
            for (ApiDiffResultDto.Changelog changelog : changelogs) {
                if (changelog == null) {
                    continue;
                }
                changeLogs.put(changelog.getVersion(), changelog.getUrl());
                sb.append(changelog.getVersion() + ",");
            }
            return sb.toString().replaceFirst(",$", "");
        }

        private String getFileName(String filePath) {
            File file = new File(filePath);
            if (file.isFile()) {
                return file.getName();
            }
            return "";
        }

        @Override
        public boolean isCellEditable(int row, int col) {
            return col == 0;
        }

        @Override
        public String getColumnName(int column) {
            return titles[column];
        }

        @Override
        public int getRowCount() {
            return sum;
        }

        @Override
        public int getColumnCount() {
            return 6;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            return this.dataList.get(rowIndex)[columnIndex];
        }

        @Override
        public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
            this.dataList.get(rowIndex)[columnIndex] = aValue;
        }

        @Override
        public void onUpdate(LinkedHashMap<String, Boolean> chooseType, String type) {
            update(chooseType, type);
        }
    }

    private <T> Predicate<T> distinctByKey(Function<? super T, Object> keyExtractor) {
        Map<Object, Boolean> seen = new ConcurrentHashMap<>();
        return object -> seen.putIfAbsent(keyExtractor.apply(object), Boolean.TRUE) == null;
    }

}
