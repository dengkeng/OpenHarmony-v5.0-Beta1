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

/**
 * 错误码
 */
export enum Code {
  OK = 0,
  ERROR = -1
}

/**
 * 字符串资源ID
 */

export enum StringResourceId {
  INPUT_FILE_NOT_FOUND,
  INPUT_FILE_CONTENT_EMPTY,
  COMMAND_INPUT_DESCRIPTION,
  COMMAND_OUT_DESCRIPTION,
  NOT_DTS_FILE,
  COMMAND_LOGLEVEL_DESCRIPTION,
  COMMAND_SPLIT_API,
  COMMAND_RULE,
  INVALID_PATH,
  OUTPUT_MUST_FILE,
  OUTPUT_MUST_DIR,
  OUTPUT_SAME_WITH_INPUT,
  OUTPUT_SUBDIR_INPUT,
  START_MESSAGE,
  COMMAND_BRANCH,
  VERSION_HINT,
  COMMAND_TEST
}

export enum Instruct {

  /**
   * 用于生成单行注释，文本替换成空行
   */
  EMPTY_LINE = 'Instruct_new_line'
}

export class ConstantValue {

  /**
   * d.ts文件后缀名
   */
  static DTS_EXTENSION = '.d.ts';

  /**
   * nodejs 最低主版本号
   */
  static MAJOR_V = 15;

  /**
   * nodejs 最低子版本号
   */
  static MINOR_V = 0;

  /**
   * nodejs 最低修正版本号
   */
  static PATCH_V = 0;
}