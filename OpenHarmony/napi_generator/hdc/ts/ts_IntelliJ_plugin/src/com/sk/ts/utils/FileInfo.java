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
package com.sk.ts.utils;

import java.io.File;
import java.util.Objects;

/**
 * 文件信息类，提供自定义的文件对象比较方法
 *
 * @author: zhangzhicheng
 * @see: generator dialog
 * @version: v1.0.0
 * @since 2023-01-18
 */
public class FileInfo {
    private String name;
    private String path;
    private long lastModifiedTime;
    private boolean isTimeEqual = false;
    private boolean isNameEqual = false;
    private boolean isPathEqual = false;

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
     * @param object 待比较的文件对象
     * @return 是否为相同文件
     */
    @Override
    public boolean equals(Object object) {
        FileInfo info = (FileInfo) object;
        if (lastModifiedTime == info.lastModifiedTime) {
            isTimeEqual = true;
        }
        if (Objects.equals(name, info.name)) {
            isNameEqual = true;
        }
        if (Objects.equals(path, info.path)) {
            isPathEqual = true;
        }
        if (object == null || getClass() != object.getClass()) {
            return false;
        }
        if (this == object) {
            return true;
        }
        return isTimeEqual && isNameEqual && isPathEqual;
    }

    @Override
    public int hashCode() {
        return Objects.hash(name, path, lastModifiedTime);
    }
}
