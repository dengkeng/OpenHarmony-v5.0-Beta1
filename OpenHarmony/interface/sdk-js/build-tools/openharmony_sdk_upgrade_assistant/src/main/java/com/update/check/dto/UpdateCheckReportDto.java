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
 * UpdateCheckReportDto
 *
 * @since 23-04-07
 */
public class UpdateCheckReportDto {
    private String apiDefinition;
    private String reminderInformation;
    private String sourceFileName;
    private String pos;
    private List<ApiDiffResultDto.Changelog> changelogs;
    private String changeType;

    /**
     * UpdateCheckReportDto
     *
     * @since 23-04-07
     */
    public UpdateCheckReportDto() {
    }

    /**
     * UpdateCheckReportDto
     *
     * @param apiDto              ApiDiffResultDto
     * @param reminderInformation reminderInformation
     * @param collApiDto          collApiDto
     * @param changeType          changeType
     */
    public UpdateCheckReportDto(ApiDiffResultDto apiDto,
                                String reminderInformation,
                                CollectApplicationApiDto collApiDto,
                                String changeType) {
        this.apiDefinition = apiDto.getRawText();
        this.reminderInformation = reminderInformation;
        this.sourceFileName = collApiDto.getSourceFileName();
        this.pos = collApiDto.getPos();
        this.changelogs = apiDto.getChangelogs();
        this.changeType = changeType;
    }

    public String getPos() {
        return pos;
    }

    public void setPos(String pos) {
        this.pos = pos;
    }

    public String getApiDefinition() {
        return apiDefinition;
    }

    public void setApiDefinition(String apiDefinition) {
        this.apiDefinition = apiDefinition;
    }

    public String getReminderInformation() {
        return reminderInformation;
    }

    public void setReminderInformation(String reminderInformation) {
        this.reminderInformation = reminderInformation;
    }

    public String getSourceFileName() {
        return sourceFileName;
    }

    public void setSourceFileName(String sourceFileName) {
        this.sourceFileName = sourceFileName;
    }

    public List<ApiDiffResultDto.Changelog> getChangelogs() {
        return changelogs;
    }

    public void setChangelogs(List<ApiDiffResultDto.Changelog> changelogs) {
        this.changelogs = changelogs;
    }

    public String getChangeType() {
        return changeType;
    }

    public void setChangeType(String changeType) {
        this.changeType = changeType;
    }
}
