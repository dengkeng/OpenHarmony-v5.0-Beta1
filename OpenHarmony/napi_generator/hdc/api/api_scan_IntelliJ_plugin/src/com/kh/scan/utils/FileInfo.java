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
package com.kh.scan.utils;

import java.io.File;
import java.util.Objects;

/**
 * 文件信息类，提供自定义的文件对象比较方法
 *
 * @author: goujingjing
 * @see: generator dialog
 * @version: v1.0.0
 * @since 2023-01-31
 */
public class FileInfo {
    private String name;
    private String path;
    private long lastModifiedTime;

    public FileInfo(File file) {
        name = file.getName();
        path = file.getPath();
        lastModifiedTime = file.lastModified();
    }

    /**
     * 获取文件路径
     *
     * @return 文件路径
     */
    public String getPath() {
        return path;
    }

    /**
     * 重写比较方法，文件名和最后修改时间都相同才认为相等（被修改覆盖过的文件也认为是新文件）
     *
     * @param obj 待比较的文件对象
     * @return 是否为相同文件
     */
    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        FileInfo fileInfo = (FileInfo) obj;
        return lastModifiedTime == fileInfo.lastModifiedTime && Objects.equals(name, fileInfo.name)
                && Objects.equals(path, fileInfo.path);
    }

    @Override
    public int hashCode() {
        return Objects.hash(name, path, lastModifiedTime);
    }
}
