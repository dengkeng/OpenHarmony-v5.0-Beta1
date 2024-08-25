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

import { StringResourceId } from './constant';

const ZH_STRING_MAP: Map<number, string> = new Map([
  [StringResourceId.INPUT_FILE_NOT_FOUND, '找不到d.ts文件'],
  [StringResourceId.INPUT_FILE_CONTENT_EMPTY, '文件无内容'],
  [StringResourceId.COMMAND_INPUT_DESCRIPTION, 'd.ts文件或包含d.ts的文件夹'],
  [StringResourceId.COMMAND_OUT_DESCRIPTION, '新的d.ts输出文件或目录'],
  [StringResourceId.NOT_DTS_FILE, '输入文件不是d.ts文件'],
  [StringResourceId.COMMAND_LOGLEVEL_DESCRIPTION, '日志输出级别[INFO,WARN,DEBUG,ERR]'],
  [StringResourceId.COMMAND_SPLIT_API, '是否拆分接口'],
  [StringResourceId.COMMAND_RULE, '整改规则文件'],
  [StringResourceId.INVALID_PATH, '不是合法的路径'],
  [StringResourceId.OUTPUT_MUST_FILE, '输出路径需要指向文件'],
  [StringResourceId.OUTPUT_MUST_DIR, '输出路径需要指向目录'],
  [StringResourceId.OUTPUT_SAME_WITH_INPUT, '输出文件路径与输入文件路径相同'],
  [StringResourceId.OUTPUT_SUBDIR_INPUT, '输出目录不能是输入目录的子目录'],
  [StringResourceId.START_MESSAGE, '正在处理, 请稍后 ...'],
  [StringResourceId.COMMAND_BRANCH, 'OpenHarmony 分支名'],
  [StringResourceId.VERSION_HINT, '告警, 需要nodejs $0.$1.$2+'],
  [StringResourceId.COMMAND_TEST, '仅供内部测试使用']
]);

const EN_STRING_MAP: Map<number, string> = new Map([
  [StringResourceId.INPUT_FILE_NOT_FOUND, 'd.ts is not found'],
  [StringResourceId.INPUT_FILE_CONTENT_EMPTY, 'file is empty'],
  [StringResourceId.COMMAND_INPUT_DESCRIPTION, 'absolute path of the file'],
  [StringResourceId.COMMAND_OUT_DESCRIPTION, 'absolute path of the file'],
  [StringResourceId.NOT_DTS_FILE, 'not a d.ts file'],
  [StringResourceId.COMMAND_LOGLEVEL_DESCRIPTION, 'log level [INFO,WARN,DEBUG,ERR]'],
  [StringResourceId.COMMAND_SPLIT_API, 'split event api'],
  [StringResourceId.COMMAND_RULE, 'rule file'],
  [StringResourceId.INVALID_PATH, 'path is invalid'],
  [StringResourceId.OUTPUT_MUST_FILE, 'the output path must be a file'],
  [StringResourceId.OUTPUT_MUST_DIR, 'the output path must be a folder'],
  [StringResourceId.OUTPUT_SAME_WITH_INPUT, 'the output file path is same as the input file path'],
  [StringResourceId.OUTPUT_SUBDIR_INPUT, 'the output directory cannot be a subdirectory of the input directory'],
  [StringResourceId.START_MESSAGE, 'Processing please wait ...'],
  [StringResourceId.COMMAND_BRANCH, 'OpenHarmony branch name'],
  [StringResourceId.VERSION_HINT, 'warning, nodejs version $0.$1.$2+ is required'],
  [StringResourceId.COMMAND_TEST, 'just for internal test']
]);

export class StringResource {
  static stringMap: Map<number, string> = ZH_STRING_MAP;
  static getString(key: number): string {
    return this.stringMap.get(key) || `unknown string resource ${key}`;
  }
}

export class StringUtils {
  static isEmpty(str: string | undefined): boolean {
    return str === undefined || str.length === 0;
  }

  static hasSubstring(str: string, sub: string | RegExp): boolean {
    return str.search(sub) !== -1;
  }

  static replaceAt(src: string, index: number, replacement: string): string {
    return src.substring(0, index) + replacement + src.substring(index + replacement.length);
  }

  static formatString(pattern: string, args: Array<number>): string {
    let newStr = pattern;
    for (let index = 0; index < args.length; index++) {
      newStr = newStr.replace(`$${index}`, `${args[index]}`);
    }
    return newStr;
  }
}

export class LogReportStringUtils {
  static createErrorInfo(errorInfo: string, params: string[]): string {
    params.forEach((param: string) => {
      errorInfo = errorInfo.replace('$$', param);
    });
    return errorInfo;
  }
}