/*
 * Copyright (c) 2023 Shenzhen Kaihong Digital Industry Development Co., Ltd.
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
import com.sk.utils.Data;
import com.sk.utils.DataList;

import javax.swing.JDialog;
import javax.swing.JPanel;
import javax.swing.JTable;
import javax.swing.JScrollPane;
import javax.swing.JComponent;
import javax.swing.KeyStroke;
import javax.swing.table.DefaultTableModel;
import java.awt.event.KeyEvent;
import java.util.List;
import java.util.Vector;
import javax.swing.ListSelectionModel;

/**
 * ShowCfgInfoDialogPane 显示用户配置的信息
 *
 * @author: goujingjing
 * @see: generator showConfig dialog
 * @version: v1.0.3
 * @since 2023-12-19
 */
public class ShowCfgInfoDialogPane extends JDialog {
    private static final Logger LOG = Logger.getInstance(GenerateDialog.class);

    private JPanel contentPane;
    private JTable table;
    private JScrollPane scrollPane;
    private DefaultTableModel tableModel;
    private String genPath;

    /**
     * 构造函数
     * @param list  配置文件数据列表
     * @param genPath  生成框架路径
     * @throws log 输出异常
     */
    public ShowCfgInfoDialogPane(DataList list, String genPath) {
        String[] tableColNames = new String[] {"includeName", "cppName", "interfaceName", "serviceCode"};
        // 初始化table: 获取List中的数据并展示在表格中
        List<Data> dataList = list.getDataList();
        this.genPath = genPath;
        tableModel = new DefaultTableModel(tableColNames, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        for (Data data : dataList) {
            Vector<String> rowData = new Vector<>();
            rowData.add(data.getIncludeName());
            rowData.add(data.getCppName());
            rowData.add(data.getInterfaceName());
            rowData.add(data.getServiceCode());
            tableModel.addRow(rowData);
        }
        table = new JTable();
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setModel(tableModel);
        table.setVisible(true);
        scrollPane.setViewportView(table);

        contentPane.registerKeyboardAction(actionEvent -> onCancel(), KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
                JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT);
    }

    /**
     * 获得选中行的数据
     * @param void 空
     * @return 选中行的用户已配置数据(Data)
     * @throws log 输出异常
     */
    public Data getSelectedData() {
        int index = table.getSelectedRow();
        Data data = null;
        if (index != -1) {
            // 获取原数据
            Object valueIncludeName = table.getValueAt(index, 0);
            String oldIncludeName = valueIncludeName.toString();
            Object valueCppName = table.getValueAt(index, 1);
            String oldCppName = valueCppName.toString();
            Object valueInterfaceName = table.getValueAt(index, 2);
            String oldInterfaceName = valueInterfaceName.toString();
            Object valueServiceCode = table.getValueAt(index, 3);
            String oldServiceCode = valueServiceCode.toString();
            data = new Data(genPath, oldIncludeName, oldCppName, oldInterfaceName, oldServiceCode);
        } else {
            LOG.error("Please select a row of data that you want to modify!");
        }
        return data;
    }

    /**
     * 获得选中行的index
     * @param void 空
     * @return 选中行的index(int)
     * @throws log 输出异常
     */
    public int getSelectedIndex() {
        return table.getSelectedRow();
    }

    private void onCancel() {
        dispose();
    }

    JPanel getContentPanel() {
        return contentPane;
    }
}
