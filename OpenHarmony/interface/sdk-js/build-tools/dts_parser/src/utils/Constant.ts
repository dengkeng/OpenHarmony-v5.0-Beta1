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

export enum StringConstant {
  /**
   * 参数类型有callback的function
   */
  ASYNC_CALLBACK_METHOD_KEY = 'AsyncCallback',
  /**
   * 参数类型有AsyncCallback的function，设置sync的值
   */
  ASYNC_CALLBACK_METHOD_KEY_CHANGE = 'AsyncCallback',
  /**
   * 驼峰校验version
   */
  CHECK_API_VERSION = '11',
  CONST_KEY_WORD = 'const',
  /**
   *  class和interface构造函数默认apiName
   */
  CONSTRUCTOR_API_NAME = 'constructor',
  /**
   * exportDefault节点apiName前缀
   */
  EXPORT_DEFAULT = 'export_default_',
  /**
   * export节点apiName前缀
   */
  EXPORT = 'export_',
  /**
   * d.ts文件后缀名
   */
  DTS_EXTENSION = '.d.ts',
  /**
   * d.ets文件后缀名
   */
  DETS_EXTENSION = '.d.ets',
  /**
   * .ets文件后缀名
   */
  ETS_EXTENSION = '.ets',
  FA_MODEL_ONLY = 'famodelonly',
  /**
   * 返回类型是Promise的function
   */
  PROMISE_METHOD_KEY = 'Promise',
  /**
   * 返回类型是Promise的function，设置sync的值
   */
  PROMISE_METHOD_KEY_CHANGE = 'Promise',
  REFERENCE = '_reference',
  /**
   * .ts文件后缀名
   */
  TS_EXTENSION = '.ts',
  /**
   * 在基础解析工具中用于存放当前节点的信息
   */
  SELF = '_self',
  STAGE_MODEL_ONLY = 'stagemodelonly',
  /**
   * 输出文件使用utf-8
   */
  UTF8 = 'utf-8',

  /**
   * 不扫描build-tools目录下的文件
   */
  NOT_SCAN_DIR = 'build-tools',
}

export enum NumberConstant {
  /**
   * 缩进2个空格
   */
  INDENT_SPACE = 2,
  /**
   * API层级关系
   */
  RELATION_LENGTH = 2,
  /**
   * 默认废弃版本为-1
   */
  DEFAULT_DEPRECATED_VERSION = '-1',
  /**
   * 判断字段是否存在
   */
  IS_FIELD_EXIST = 0,
  /**
   * 转成二进制
   */
  BINARY_SYSTEM = 2,
  /**
   * 表格的行数，代表从第二行开始写信息
   */
  LINE_IN_EXCEL = 2,
  /**
   * syscap分隔为数组后，index为2的字段是关键字段
   */
  SYSCAP_KEY_FIELD_INDEX = 2,

  /**
   *当前版本对应的jsdoc
   */
  DELETE_CURRENT_JS_DOC = -2,
}

/**
 * 常用符号存储
 */
export enum PunctuationMark {
  QUERY = '?',
  LEFT_BRACKET = '[',
  RIGHT_BRACKET = ']',
  LEFT_BRACE = '{',
  RIGHT_BRACE = '}',
  LEFT_PARENTHESES = '(',
  RIGHT_PARENTHESES = ')',
}

export class EventConstant {
  static eventNameList: string[] = ['on', 'off', 'emit', 'once'];
  static eventMethodCheckVersion: number = 10;
  static eventFirstParamName: string = 'type';
}
