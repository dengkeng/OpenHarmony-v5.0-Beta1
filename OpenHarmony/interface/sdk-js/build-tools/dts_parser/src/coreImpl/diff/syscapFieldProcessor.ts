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
import { BasicDiffInfo } from '../../typedef/diff/ApiInfoDiff';
import { FunctionUtils } from '../../utils/FunctionUtils';

/**
 * 使用syscap中的关键字段匹配子系统S
 */
export class SyscapProcessorHelper {
  static matchSubsystem(diffInfo: BasicDiffInfo): string | undefined {
    const subsystemMap: Map<string, string> = FunctionUtils.readSubsystemFile().subsystemMap;
    const syscapField: string = SyscapProcessorHelper.getSyscapField(diffInfo);
    if (syscapField) {
      return subsystemMap.get(syscapField);
    }
    return 'NA';
  }

  static getSyscapField(diffInfo: BasicDiffInfo): string {
    const newSyscap: string = diffInfo.getNewSyscapField();
    if (newSyscap) {
      return newSyscap;
    }
    const oldSyscap: string = diffInfo.getOldSyscapField();
    if (oldSyscap) {
      return oldSyscap;
    }
    return '';
  }

  static getSingleKitInfo(data: BasicDiffInfo): string {
    if (data.getNewKitInfo() !== '') {
      return data.getNewKitInfo();
    }
    return data.getOldKitInfo();
  }
}