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
package com.sk.utils;

import com.intellij.notification.NotificationType;

import java.util.List;

/**
 * 配置信息列表类，将每一组配置信息放入List中保存
 *
 * @author: goujingjing
 * @see: generator dialog
 * @version: v1.0.3
 * @since 2023-12-14
 */
public class DataList {
    private List<Data> dataList;

    /**
     * 构造函数
     * @param dataList 用户的配置文件信息
     * @throws log 输出异常
     */
    public DataList(List<Data> dataList) {
        this.dataList = dataList;
    }

    /**
     * 返回用户输入的所有配置业务代码的数据
     * @param void 空
     * @return 保存的dataList数据。
     * @throws log 输出异常
     */
    public List<Data> getDataList() {
        return this.dataList;
    }

    /**
     * 将用户输入的Data数据加入List中保存
     * @param  data  用户输入的配置业务代码相关数据
     * @throws log 输出异常
     */
    public void addDataListInfo(Data data) {
        this.dataList.add(data);
        GenNotification.notifyMessage(null, "", "添加成功", NotificationType.INFORMATION);
    }

    /**
     * 修改数据，将用户输入的Data数据加入List中保存
     * @param  index 用户要修改的那一项数据
     * @param  data  用户输入的配置业务代码相关数据
     * @throws log 输出异常
     */
    public void modifyDataListInfo(int index, Data data) {
        this.dataList.set(index, data);
        GenNotification.notifyMessage(null, "", "修改成功", NotificationType.INFORMATION);
    }

    /**
     * 删除数据，删除一项配置数据
     * @param  index  用户要删除的那一项数据的索引
     * @throws log 输出异常
     */
    public void deleteDataListInfo(int index) {
        if (index >= 0 && index < this.dataList.size()) {
            this.dataList.remove(index);
            GenNotification.notifyMessage(null, "", "删除成功", NotificationType.INFORMATION);
        } else {
            GenNotification.notifyMessage(null, "", "删除失败", NotificationType.INFORMATION);
        }
    }

}
