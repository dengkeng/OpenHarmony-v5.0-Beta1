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

import java.util.List;

/**
 * ApiDiffResultDto
 *
 * @since 23-04-07
 */
public class ApiDiffResultDto {
    private String packageName;
    private String className;
    private String rawText;
    private String dtsName;
    private Integer statusCode;
    private String oldMessage;
    private String newMessage;
    private String version;
    private String useinstead;
    private String hint;
    private List<Changelog> changelogs;

    /**
     * Changelog
     *
     * @since 23-04-07
     */
    public static class Changelog {
        private String version;
        private String url;

        public String getVersion() {
            return version;
        }

        public void setVersion(String version) {
            this.version = version;
        }

        public String getUrl() {
            return url;
        }

        public void setUrl(String url) {
            this.url = url;
        }
    }

    public String getHint() {
        return hint;
    }

    public void setHint(String hint) {
        this.hint = hint;
    }

    public Integer getStatusCode() {
        return statusCode;
    }

    public void setStatusCode(Integer statusCode) {
        this.statusCode = statusCode;
    }

    public String getUseinstead() {
        return useinstead;
    }

    public void setUseinstead(String useinstead) {
        this.useinstead = useinstead;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public String getDtsName() {
        return dtsName;
    }

    public void setDtsName(String dtsName) {
        this.dtsName = dtsName;
    }

    public String getPackageName() {
        return packageName;
    }

    public void setPackageName(String packageName) {
        this.packageName = packageName;
    }

    public String getClassName() {
        return className;
    }

    public void setClassName(String className) {
        this.className = className;
    }

    public String getRawText() {
        return rawText;
    }

    public void setRawText(String rawText) {
        this.rawText = rawText;
    }

    public String getOldMessage() {
        return oldMessage;
    }

    public void setOldMessage(String oldMessage) {
        this.oldMessage = oldMessage;
    }

    public String getNewMessage() {
        return newMessage;
    }

    public void setNewMessage(String newMessage) {
        this.newMessage = newMessage;
    }

    public List<Changelog> getChangelogs() {
        return changelogs;
    }

    public void setChangelogs(List<Changelog> changelogs) {
        this.changelogs = changelogs;
    }

    @Override
    public String toString() {
        return "ApiDiffResultDto{" +
                "packageName='" + packageName + '\'' +
                ", className='" + className + '\'' +
                ", rawText='" + rawText + '\'' +
                ", dtsName='" + dtsName + '\'' +
                ", statusCode=" + statusCode +
                ", oldMessage='" + oldMessage + '\'' +
                ", newMessage='" + newMessage + '\'' +
                ", version='" + version + '\'' +
                ", useinstead='" + useinstead + '\'' +
                '}';
    }
}
