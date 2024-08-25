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
 * CollectApplicationApiDto
 *
 * @since 23-04-07
 */
public class CollectApplicationApiDto {
    private String packageName;
    private String typeName;
    private String propertyName;
    private String apiText;
    private String deprecated;
    private String applicationFile;
    private String pos;
    private String useinstead;
    private String dtsName;
    private String sourceFileName;

    public String getSourceFileName() {
        return sourceFileName;
    }

    public void setSourceFileName(String sourceFileName) {
        this.sourceFileName = sourceFileName;
    }

    public String getPackageName() {
        return packageName;
    }

    public void setPackageName(String packageName) {
        this.packageName = packageName;
    }

    public String getTypeName() {
        return typeName;
    }

    public void setTypeName(String typeName) {
        this.typeName = typeName;
    }

    public String getPropertyName() {
        return propertyName;
    }

    public void setPropertyName(String propertyName) {
        this.propertyName = propertyName;
    }

    public String getApiText() {
        return apiText;
    }

    public void setApiText(String apiText) {
        this.apiText = apiText;
    }

    public String getDeprecated() {
        return deprecated;
    }

    public void setDeprecated(String deprecated) {
        this.deprecated = deprecated;
    }

    public String getApplicationFile() {
        return applicationFile;
    }

    public void setApplicationFile(String applicationFile) {
        this.applicationFile = applicationFile;
    }

    public String getPos() {
        return pos;
    }

    public void setPos(String pos) {
        this.pos = pos;
    }

    public String getUseinstead() {
        return useinstead;
    }

    public void setUseinstead(String useinstead) {
        this.useinstead = useinstead;
    }

    public String getDtsName() {
        return dtsName;
    }

    public void setDtsName(String dtsName) {
        this.dtsName = dtsName;
    }

    @Override
    public String toString() {
        return "CollectApplicationApiDto{" +
                "packageName='" + packageName + '\'' +
                ", className='" + typeName + '\'' +
                ", methodName='" + propertyName + '\'' +
                ", methodText='" + apiText + '\'' +
                ", deprecated='" + deprecated + '\'' +
                ", applicationFile='" + applicationFile + '\'' +
                ", pos='" + pos + '\'' +
                ", useInstead='" + useinstead + '\'' +
                ", dtsName='" + dtsName + '\'' +
                '}';
    }
}
