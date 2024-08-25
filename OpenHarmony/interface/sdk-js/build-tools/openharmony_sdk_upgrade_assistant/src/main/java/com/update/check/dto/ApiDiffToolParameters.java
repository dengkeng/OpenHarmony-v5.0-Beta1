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

package com.update.check.dto;

/**
 * ApiDiffToolParameters
 *
 * @since 23-04-07
 */
public class ApiDiffToolParameters {
    private String oldDir;
    private String newDir;
    private String oldVersion;
    private String newVersion;
    private String objectDir;
    private String oldApiDir;
    private String oldComponentDir;

    public String getOldDir() {
        return oldDir;
    }

    public void setOldDir(String oldDir) {
        this.oldDir = oldDir;
    }

    public String getNewDir() {
        return newDir;
    }

    public void setNewDir(String newDir) {
        this.newDir = newDir;
    }

    public String getOldVersion() {
        return oldVersion;
    }

    public void setOldVersion(String oldVersion) {
        this.oldVersion = oldVersion;
    }

    public String getNewVersion() {
        return newVersion;
    }

    public void setNewVersion(String newVersion) {
        this.newVersion = newVersion;
    }

    public String getObjectDir() {
        return objectDir;
    }

    public void setObjectDir(String objectDir) {
        this.objectDir = objectDir;
    }

    public String getOldApiDir() {
        return oldApiDir;
    }

    public void setOldApiDir(String oldApiDir) {
        this.oldApiDir = oldApiDir;
    }

    public String getOldComponentDir() {
        return oldComponentDir;
    }

    public void setOldComponentDir(String oldComponentDir) {
        this.oldComponentDir = oldComponentDir;
    }
}
