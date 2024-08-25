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
import com.intellij.ui.JBColor;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import javax.swing.JTable;
import javax.swing.JPanel;
import javax.swing.JComponent;
import javax.swing.event.MouseInputListener;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.Component;
import java.awt.Cursor;
import java.awt.Rectangle;
import java.awt.Point;
import java.awt.Desktop;
import java.awt.event.ActionEvent;
import java.awt.event.MouseEvent;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.ArrayList;
import java.util.Arrays;

/**
 * ShowChangeLogsDialog
 *
 * @since 23-04-07
 */
public class ShowChangeLogsDialog extends DialogWrapper {
    private JTable showChangeLogs;

    private JPanel rootPanel;

    private Project project;

    private Map<String, String> changeLogs = new HashMap<>();

    private List<String> changeVersions = new ArrayList<>();

    /**
     * ShowChangeLogsDialog
     *
     * @param project        project
     * @param changeLogs     changelogs
     * @param changeVersions change version
     */
    public ShowChangeLogsDialog(@NotNull Project project, Map<String, String> changeLogs, String changeVersions) {
        super(project, false);
        this.project = project;
        this.changeLogs = changeLogs;
        this.changeVersions.addAll(Arrays.asList(changeVersions.split(",")));
        this.setTitle(ConstString.get("view.changes.url"));
        Report report = new Report();
        this.showChangeLogs.setModel(report);
        LinkCellRenderer renderer = new LinkCellRenderer();
        this.showChangeLogs.setDefaultRenderer(Object.class, renderer);
        this.showChangeLogs.addMouseListener(renderer);
        this.showChangeLogs.addMouseMotionListener(renderer);
        this.init();
    }

    /**
     * ShowChangeLogsDialog
     *
     * @param project project
     * @param canBeParent canBeParent
     */
    protected ShowChangeLogsDialog(@Nullable Project project, boolean canBeParent) {
        super(project, canBeParent);
    }

    /**
     * createCenterPanel
     *
     * @return this rootPanel
     */
    @Override
    protected JComponent createCenterPanel() {
        return this.rootPanel;
    }

    private void onCancel(@Nullable ActionEvent event) {
        super.doCancelAction();
        dispose();
    }

    @Override
    public void doCancelAction() {
        this.onCancel(null);
    }

    /**
     * LinkCellRenderer
     *
     * @since 23-04-07
     */
    static class LinkCellRenderer extends DefaultTableCellRenderer implements MouseInputListener {
        private int row = -1;
        private int col = -1;
        private JTable table = null;

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                                                       boolean isSelected, boolean hasFocus, int row, int column) {
            this.table = table;
            super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            table.setCursor(Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
            this.setText(value.toString());
            if (row == this.row && column == this.col) {
                if (column == 1) {
                    this.setForeground(JBColor.BLUE);
                    table.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
                    this.setText("<html><u>" + value + "</u></html>");
                }
                setBackground(table.getSelectionBackground());
            } else if (isSelected) {
                setForeground(table.getSelectionForeground());
                setBackground(table.getSelectionBackground());
            } else {
                setBackground(JBColor.WHITE);
            }
            return this;
        }

        /**
         * Invoked when the mouse exits a component.
         *
         * @param e the event to be processed
         */
        public void mouseExited(MouseEvent e) {
            if (table != null) {
                int oldRow = row;
                int oldCol = col;
                row = -1;
                col = -1;
                if (oldRow != -1 && oldCol != -1) {
                    Rectangle rect = table.getCellRect(oldRow, oldCol, false);
                    table.repaint(rect);
                }
            }
        }

        /**
         * Invoked when a mouse button is pressed on a component and then
         * dragged.  {@code MOUSE_DRAGGED} events will continue to be
         * delivered to the component where the drag originated until the
         * mouse button is released (regardless of whether the mouse position
         * is within the bounds of the component).
         * <p>
         * Due to platform-dependent Drag&amp;Drop implementations,
         * {@code MOUSE_DRAGGED} events may not be delivered during a native
         * Drag&amp;Drop operation.
         *
         * @param e the event to be processed
         */
        public void mouseDragged(MouseEvent e) {
            mouseMoved(e);
        }

        /**
         * Invoked when the mouse cursor has been moved onto a component
         * but no buttons have been pushed.
         *
         * @param e the event to be processed
         */
        public void mouseMoved(MouseEvent e) {
            if (table != null) {
                Point p = e.getPoint();
                int oldRow = row;
                int oldCol = col;
                row = table.rowAtPoint(p);
                col = table.columnAtPoint(p);
                if (oldRow != -1 && oldCol != -1) {
                    Rectangle rect = table.getCellRect(oldRow, oldCol, false);
                    table.repaint(rect);
                }
                if (row != -1 && col != -1) {
                    Rectangle rect = table.getCellRect(row, col, false);
                    table.repaint(rect);
                }
            }
        }

        /**
         * mouse click event
         *
         * @param e the event to be processed
         */
        public void mouseClicked(MouseEvent e) {
            Point p = e.getPoint();
            int c = table.columnAtPoint(p);
            if (c != 1) {
                return;
            }
            int r = table.rowAtPoint(p);
            URL url = null;
            try {
                url = new URL(table.getValueAt(r, c).toString());
                Desktop.getDesktop().browse(url.toURI());
            } catch (IOException | URISyntaxException ex) {
                ex.printStackTrace();
            }
        }

        /**
         * Invoked when a mouse button has been pressed on a component.
         *
         * @param e the event to be processed
         */
        public void mousePressed(MouseEvent e) {
            e.getClickCount();
        }

        /**
         * Invoked when a mouse button has been released on a component.
         *
         * @param e the event to be processed
         */
        public void mouseReleased(MouseEvent e) {
            e.getClickCount();
        }

        /**
         * Invoked when the mouse enters a component.
         *
         * @param e the event to be processed
         */
        public void mouseEntered(MouseEvent e) {
            e.getClickCount();
        }
    }

    /**
     * Report
     *
     * @since 23-04-07
     */
    class Report extends AbstractTableModel {
        List<Object[]> dataList = new ArrayList<>();
        String[] titles = new String[3];
        int sum = changeVersions.size();

        /**
         * Report
         *
         * @since 23-04-07
         */
        public Report() {
            for (int i = 0; i < sum; i++) {
                dataList.add(new Object[]{changeVersions.get(i), changeLogs.get(changeVersions.get(i))});
            }
            titles[0] = ConstString.get("sdk.version");
            titles[1] = ConstString.get("changelog.url");
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
     * showDialog
     *
     * @param project project
     * @param changeLogs changeLogs
     * @param changeVersions changeVersions
     */
    public static void showDialog(Project project, Map<String,
            String> changeLogs, String changeVersions) {
        ShowChangeLogsDialog showChangeLogsDialog = new ShowChangeLogsDialog(project, changeLogs, changeVersions);
        showChangeLogsDialog.show();
    }
}
