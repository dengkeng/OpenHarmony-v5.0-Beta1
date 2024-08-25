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
import com.intellij.openapi.ui.DialogWrapper;
import com.update.check.action.DataUpdateNotifier;
import com.update.check.log.Logger;
import org.jetbrains.annotations.NotNull;

import javax.swing.JPanel;
import javax.swing.JTable;
import javax.swing.JComponent;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableColumn;
import java.awt.event.ActionEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Popup box for selecting change type within the tool.
 *
 * @since 23-07-18
 */
public class ShowTypeDialog extends DialogWrapper {
    private static final Logger LOGGER = Logger.createLogger();

    private static final String LOG_TAG = ShowTypeDialog.class.getName();

    private JPanel rootPanel;

    private JTable typeTable;

    private LinkedHashMap<String, Boolean> types = new LinkedHashMap<>();

    private Project project;

    private List<String> result = new ArrayList<>();

    /**
     * ShowTypeDialog
     *
     * @param project project
     * @param types   change type
     */
    public ShowTypeDialog(Project project, LinkedHashMap<String, Boolean> types) {
        super(project, false);
        LOGGER.info(LOG_TAG, "start filter changeType");
        this.types = types;
        this.project = project;
        this.setStyle();
        this.setListenerToReportPanel();
        this.init();
    }

    private void setStyle() {
        ChangeType changeType = new ChangeType(types);
        this.typeTable.setModel(changeType);
        this.typeTable.setRowSelectionAllowed(true);
        this.typeTable.setColumnSelectionAllowed(true);
        TableColumn tc = this.typeTable.getColumnModel().getColumn(0);
        tc.setCellEditor(this.typeTable.getDefaultEditor(Boolean.class));
        tc.setCellRenderer(this.typeTable.getDefaultRenderer(Boolean.class));
        tc.setPreferredWidth(50);
        tc.setMaxWidth(200);
        tc.setMinWidth(100);
    }

    private void setListenerToReportPanel() {
        this.typeTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                int col = typeTable.columnAtPoint(e.getPoint());
                int row = typeTable.getSelectedRow();
                processSelectionBox((boolean) typeTable.getValueAt(row, col), row);
            }
        });
    }

    private void processSelectionBox(boolean valueAt, int row) {
        changeTypes(row, valueAt);
        if (row == 0) {
            LOGGER.info(LOG_TAG, "select all or deselect all");
            for (int i = 1; i < typeTable.getRowCount(); i++) {
                changeTypes(i, valueAt);
            }
        }
        if (!valueAt && (boolean) typeTable.getValueAt(0, 0)) {
            changeTypes(0, valueAt);
        }
        setStyle();
    }

    private void changeTypes(int row, boolean isSelected) {
        this.types.computeIfPresent(String.valueOf(typeTable.getValueAt(row, 1)),
                (String key, Boolean value) -> isSelected);
    }

    class ChangeType extends AbstractTableModel {
        List<Object[]> dataList = new ArrayList<>();
        String[] titles = new String[3];
        int sum = types.size();

        /**
         * ChangeType
         *
         * @param types change types
         */
        public ChangeType(LinkedHashMap<String, Boolean> types) {
            for (Map.Entry<String, Boolean> entry : types.entrySet()) {
                dataList.add(new Object[]{entry.getValue(), entry.getKey()});
            }
            titles[0] = ConstString.get("check.choose.type");
            titles[1] = ConstString.get("check.types");
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
            return 2;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            return this.dataList.get(rowIndex)[columnIndex];
        }

        @Override
        public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
            this.dataList.get(rowIndex)[columnIndex] = aValue;
        }
    }

    /**
     * Load Popup
     *
     * @param project project
     * @param types   change type
     */
    public static void showDialog(@NotNull Project project, LinkedHashMap<String, Boolean> types) {
        ShowTypeDialog showTypeDialog = new ShowTypeDialog(project, types);
        showTypeDialog.show();
    }

    @Override
    protected JComponent createCenterPanel() {
        return this.rootPanel;
    }

    @Override
    public void doCancelAction() {
        this.onCancel(null);
    }

    private void onCancel(ActionEvent event) {
        super.doCancelAction();
        dispose();
    }

    @Override
    protected void doOKAction() {
        LOGGER.info(LOG_TAG, "filter completed");
        super.doOKAction();
        DataUpdateNotifier
                .getInstance()
                .notifyDataChange(types, "chooseType");
    }
}
