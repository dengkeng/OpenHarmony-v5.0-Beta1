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

import { LogUtil } from '../../utils/logUtil';
import { NumberConstant } from '../../utils/Constant';
const PATT: { [key: string]: RegExp | string } = {
  GET_NOT_TRANSFERCHAR: /(?<!\\)([\*|\.|\?|\+|\^|\$|\||\/|\[|\]|\(|\)|\{|\}])/g, //获取需要转义的字符
  VARIABLE_START: '(?<=\\b|\\s|\\*|\\.|\\?|\\+|\\^|\\$|\\||\\/|\\[|\\]|\\(|\\)|\\{|\\})', //变量需要是一个完整单词开头,或者以运算相关字符开头
  VARIABLE_END: '(?=\\b|\\s|\\*|\\.|\\?|\\+|\\^|\\$|\\||\\/|\\[|\\]|\\(|\\)|\\{|\\})', //变量需要是一个完整单词结尾,或者以运算相关字符结尾
  SPILT_CHAR_START: '(\\b|\\s)', //替换字符需要是完整字符开头
  SPILT_CHAR_END: '(\\b|\\s)', //替换字符需要是完整字符结尾
};
export class PermissionsProcessorHelper {
  private static NEED_TRANSFER_CHAR: Array<string> = [
    '*',
    '.',
    '?',
    '+',
    '^',
    '$',
    '|',
    '/',
    '[',
    ']',
    '(',
    ')',
    '{',
    '}',
  ]; //需要转义的字符

  /**
   * 转义的规则，可以在new的时候传入相应格式进行修改
   *
   * @type {CharMapType} charMap
   */
  private charMap: CharMapType = new Map([
    ['and', { splitchar: '&', transferchar: '&' }],
    ['or', { splitchar: '\\|', transferchar: '|' }],
    ['eq', { splitchar: '=', transferchar: '==' }],
    ['LE', { splitchar: '->', transferchar: '<=' }],
    ['RE', { splitchar: '<-', transferchar: '>=' }],
    ['not', { splitchar: '-', transferchar: '!' }],
    ['lcurve', { splitchar: '\\(', transferchar: '(' }],
    ['rcurve', { splitchar: '\\)', transferchar: ')' }],
  ]);

  /**
   * 用来记录分割的条件，需要满足可以放入正则，不能存在特殊字符，例如 {@link NEED_TRANSFER_CHAR}
   *
   * @type {Array<string|RegExp>}
   */
  private splitchar: Array<string | RegExp> = ['&', '\\|', '->', '-', '=', '\\(', '\\)'];

  /**
   * 用来记录分割的条件最终需要替换的运算符
   *
   * @type {Array<string>}
   */
  private transferchar: Array<string> = ['&', '|', '<=', '!', '==', '(', ')'];

  private variables: Array<string> = []; //命题集合

  /**
   * 构造方法
   *
   * @param {CharMapType} charMap 如果存在相关字符，需要进行转义 * . ? + ^ $ | / [ ] ( ) { }
   */
  constructor(charMap?: CharMapType) {
    let map: CharMapType = this.charMap;
    if (charMap) {
      map = new Map([...map, ...charMap]);
      this.splitchar = [];
      this.transferchar = [];
      map.forEach((item, key) => {
        let splitchar: string | RegExp = item.splitchar;
        if (!(splitchar instanceof RegExp)) {
          splitchar = splitchar.replace(PATT.GET_NOT_TRANSFERCHAR, '\\$1');
          if (splitchar !== item.splitchar) {
            LogUtil.i(
              'PermissionsProcessorHelper',
              `传入的表达式有问题，已经自行修改! ${key}中的splitchar为${item.splitchar},修改为${splitchar}`
            );
          }
        }
        this.splitchar.push(splitchar);
        this.transferchar.push(item.transferchar);
      });
    }
    return this;
  }

  getvariables(): Array<string> {
    return this.variables;
  }

  /**
   * 比较两个版本Permission的变化
   *
   * @param {string} oldStr
   * @param {string} newStr
   * @returns {CompareReturnObjType}
   */
  comparePermissions(oldStr: string, newStr: string): CompareReturnObjType {
    const calculateResult: CompareReturnObjType = {
      range: RangeChange.NO,
      situationDown: [],
      situationUp: [],
      variables: [],
    };
    const downVal: CompareReturnObjType = this.calculateParadigmDown(oldStr, newStr);
    const upVal: CompareReturnObjType = this.calculateParadigmUp(oldStr, newStr);
    calculateResult.variables = this.variables;
    if (downVal.range !== RangeChange.NO) {
      calculateResult.situationDown = downVal.situationDown;
      calculateResult.range = RangeChange.DOWN;
    }
    if (upVal.range !== RangeChange.NO) {
      calculateResult.situationUp = upVal.situationUp;
      calculateResult.range = calculateResult.range === RangeChange.NO ? RangeChange.UP : RangeChange.CHANGE;
    }
    return calculateResult;
  }

  /**
   * 比较两个版本逻辑关系的变化，返回变小的情况
   *
   * @param {string} oldStr
   * @param {string} newStr
   * @returns {CompareReturnObjType}
   */
  calculateParadigmDown(oldStr: string, newStr: string): CompareReturnObjType {
    const calculateResult: CompareReturnObjType = {
      range: RangeChange.NO,
      situationDown: [],
      situationUp: [],
      variables: [],
    };
    const char: CharMapTypeValue | undefined = this.charMap.get('LE');
    if (!char) {
      return calculateResult;
    }
    const mergeStr: string = `(${oldStr}) ${char.splitchar} (${newStr})`;
    const permissionsDiff: CalculateReturnType = this.calculateParadigm(mergeStr);
    calculateResult.variables = this.variables;
    if (permissionsDiff.fail.length > 0) {
      calculateResult.range = RangeChange.DOWN;
      calculateResult.situationDown = permissionsDiff.fail.map((item: number) => {
        let itemNums: string[] = Number(item)
          .toString(NumberConstant.BINARY_SYSTEM)
          .padStart(this.variables.length, '0')
          .split('');
        return itemNums.map((num: string) => {
          return Boolean(Number(num));
        });
      });
    }
    return calculateResult;
  }

  /**
   * 比较两个版本逻辑关系的变化，返回变大的情况
   *
   * @param {string} oldStr
   * @param {string} newStr
   * @returns {CompareReturnObjType}
   */
  calculateParadigmUp(oldStr: string, newStr: string): CompareReturnObjType {
    const calculateResult: CompareReturnObjType = {
      range: RangeChange.NO,
      situationDown: [],
      situationUp: [],
      variables: [],
    };
    const char = this.charMap.get('RE');
    if (!char) {
      return calculateResult;
    }
    const mergeStr: string = `(${oldStr}) ${char.splitchar} (${newStr})`;
    const permissionsDiff: CalculateReturnType = this.calculateParadigm(mergeStr);

    calculateResult.variables = this.variables;
    if (permissionsDiff.fail.length > 0) {
      calculateResult.range = RangeChange.UP;
      calculateResult.situationUp = permissionsDiff.fail.map((item) => {
        let itemNums: string[] = Number(item)
          .toString(NumberConstant.BINARY_SYSTEM)
          .padStart(this.variables.length, '0')
          .split('');
        return itemNums.map((num: string) => {
          return Boolean(Number(num));
        });
      });
    }
    return calculateResult;
  }

  /**
   * 计算逻辑表达式的析取范式和合取范式
   *
   * @param {string} str
   * @returns {CalculateReturnType}
   */
  calculateParadigm(str: string): CalculateReturnType {
    const variable = this.findVariables(str);
    this.variables = variable;
    str = this.formatten(str);
    const variablesLength: number = this.variables.length;
    const states: string[][] = PermissionsProcessorHelper.getAllState(variablesLength);
    const values: number[] = this.calculate(str, variablesLength, states);
    return this.processValues(values);
  }

  /**
   * 根据传入数据，提取出所有条件，以splitchar中的数据进行分割
   *
   * @param {string} str
   * @returns {Array<string>}
   */
  private findVariables(str: string): Array<string> {
    this.splitchar.forEach((char: string | RegExp) => {
      const reg = new RegExp(char, 'g');
      str = str.replace(reg, ' ');
    });
    const set: Set<string> = new Set(str.split(' '));
    set.delete('');
    const sortSet: string[] = [...set].sort((a, b) => {
      if (a.length === b.length) {
        return a < b ? -1 : 1;
      } else {
        return a.length < b.length ? 1 : -1;
      }
    });
    return sortSet;
  }

  /**
   * 格式化字符串的逻辑条件
   *
   * @param {string} str
   * @returns {string}
   */
  private formatten(str: string): string {
    this.splitchar.forEach((char: string | RegExp, index: number) => {
      if (!(char instanceof RegExp)) {
        char = new RegExp(PATT.SPILT_CHAR_START + char + PATT.SPILT_CHAR_END, 'g');
      }
      str = str.replace(char, this.transferchar[index]);
    });
    return str;
  }

  /**
   * 计算n个长度对应的真值表
   *
   * @param {number} len
   * @returns {Array<Array<string>>}
   */
  private static getAllState(len: number): Array<Array<string>> {
    const states: string[][] = [];
    for (let index = 0; index < NumberConstant.BINARY_SYSTEM ** len; index++) {
      states.push(Number(index).toString(NumberConstant.BINARY_SYSTEM).padStart(len, '0').split(''));
    }
    return states;
  }

  /**
   * 通过真值表计算最终结果
   *
   * @param {string} str
   * @param {number} variablesLen
   * @param {Array<Array<string>>} states
   * @returns {Array<number>}
   */
  private calculate(str: string, variablesLen: number, states: Array<Array<string>>): Array<number> {
    const statesLen = states.length;
    const values: Array<number> = [];
    let outError: boolean = true;
    for (let i = 0; i < statesLen; i++) {
      const state = states[i];
      let modifyStr = str;
      for (let j = 0; j < variablesLen; j++) {
        let variable = this.variables[j];
        variable = variable.replace(PATT.GET_NOT_TRANSFERCHAR, '\\$1');
        const reg = new RegExp(PATT.VARIABLE_START + variable + PATT.VARIABLE_END, 'g');
        modifyStr = modifyStr.replace(reg, state[j]);
      }
      try {
        values.push(eval(modifyStr));
      } catch (error) {
        if (outError) {
          outError = !outError;
          LogUtil.e('PermissionsProcessor.calculate', `error logical expression: ${str}`);
          values.push(0);
        }
      }
    }
    return values;
  }

  /**
   * 最终结果分类处理
   *
   * @param {Array<number>} values
   * @returns {CalculateReturnType}
   */
  private processValues(values: Array<number>): CalculateReturnType {
    const calculate: CalculateReturnType = { pass: [], fail: [] };
    for (let index = 0; index < values.length; index++) {
      const element = values[index];
      if (element) {
        calculate.pass.push(index);
      } else {
        calculate.fail.push(index);
      }
    }
    return calculate;
  }
}

export enum RangeChange {
  DOWN = 'down',
  UP = 'up',
  NO = 'no',
  CHANGE = 'change',
}

/**
 * 转义的规则集合类型
 */
export type CharMapType = Map<string, CharMapTypeValue>;

/**
 * 转义的规则对象
 * @type {object}
 * @property {string | RegExp} splitchar - 逻辑条件的区分字符.
 * @property {string} transferchar - 区分字符转为的逻辑运算符和位运算符
 */
export type CharMapTypeValue = {
  /**
   *
   * 逻辑条件的区分字符
   * @type {(string | RegExp)}
   */
  splitchar: string | RegExp;
  /**
   * 区分字符转为的逻辑运算符和位运算符
   *
   * @type {string}
   */
  transferchar: string;
};

/**
 * 逻辑运算的初步结果
 *
 */
export type CalculateReturnType = {
  /**
   * 逻辑运算通过的真值表对应十进制项 ——析取范式
   *
   * @type {Array<number>}
   */
  pass: Array<number>;
  /**
   * 逻辑运算不通过的真值表对应十进制项 ——合取范式
   *
   * @type {Array<number>}
   */
  fail: Array<number>;
};

/**
 * 比较两个运算的返回值
 *
 */
export type CompareReturnObjType = {
  /**
   * 范围变化
   *
   * @type {RangeChange}
   */
  range: RangeChange;
  /**
   * 权限变小的情况，在对应逻辑条件为当前状态时会有次情况
   *
   * @type {Boolean[][]}
   */
  situationDown: Boolean[][];
  /**
   * 权限变大的情况，在对应逻辑条件为当前状态时会有次情况
   *
   * @type {Boolean[][]}
   */
  situationUp: Boolean[][];
  /**
   * 逻辑条件，提取两个逻辑运算的变量
   *
   * @type {Array<string>}
   */
  variables: Array<string>;
};
