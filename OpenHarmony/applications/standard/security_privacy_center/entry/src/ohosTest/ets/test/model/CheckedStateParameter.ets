/**
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

// Check the status parameters. Used to set application permission group check status
// This is the status section of the application permission group, which only includes the selected status and permission group flag
export class CheckedStateParameter {
  //   Permission group check status
  //   Valid permission status：ALLOW,ALLOW_ALL_THE_TIME,ALLOW_ONLY_WHILE_IN_USE,ASK_EACH_TIME,DENY,
  //                MEDIA_ONLY,ALLOW_MANAGEMENT_OF_ALL_FILES
  checkedState: string;
  //   Additional signs
  flagMask: number;
  //   Additional signs
  flagValue: number;

  constructor(checkedState: string, flagMask: number, flagValue: number) {
    this.checkedState = checkedState;
    this.flagMask = flagMask;
    this.flagValue = flagValue;
  }
}
