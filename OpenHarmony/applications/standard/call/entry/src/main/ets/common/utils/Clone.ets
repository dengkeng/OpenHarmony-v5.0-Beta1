/**
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
 * @file: Deep copy
 */
import Method from './Method';

const mapType = '[object Map]';
const setType = '[object Set]';
const arrayType = '[object Array]';
const objectType = '[object Object]';
const argsType = '[object Arguments]';
const boolType = '[object Boolean]';
const dateType = '[object Date]';
const numberType = '[object Number]';
const stringType = '[object String]';
const symbolType = '[object Symbol]';
const errorType = '[object Error]';
const regexpType = '[object RegExp]';
const funcType = '[object Function]';
const deepType = [mapType, setType, arrayType, objectType, argsType];

export default class Getclone {
  private static getclone: Getclone = new Getclone();

  public static getInstance(): Getclone {
    return this.getclone;
  }

  /**
   * forEach
   *
   * @param { array } array
   *
   * @param { function } iteratee
   */
  private forEach(array, iteratee) {
    let index = -1;
    const length = array.length;

    while (++index < length) {
      iteratee(array[index], index);
    }
    return array;
  }

  /**
   * is object
   *
   * @param { any } target
   */
  private isObject(target) {
    const type = typeof target;
    return target !== null && (type === 'object' || type === 'function');
  }

  /**
   * get type
   *
   * @param { any } target
   */
  private getType(target) {
    return Object.prototype.toString.call(target);
  }

  /**
   * get init
   *
   * @param { any } target
   */
  private getInit(target) {
    const ctor = target.constructor;
    return new ctor();
  }

  /**
   * clone symbol
   *
   * @param { any } target
   */
  private cloneSymbo(target) {
    return Object(Symbol.prototype.valueOf.call(target));
  }

  /**
   * clone reg
   *
   * @param { any } target
   */
  private cloneRegister(target) {
    const reFlags = /\w*$/;
    const result = new target.constructor(target.source, reFlags.exec(target));
    result.lastIndex = target.lastIndex;
    return result;
  }

  /**
   * clone function
   *
   * @param { function } func
   */
  private cloneFunc(func) {
    const bodyRegister = /(?<={)(.|\n)+(?=})/m;
    const paramRegister = /(?<=\().+(?=\)\s+{)/;
    const funcStr = func.toString();
    if (func.prototype) {
      const param = paramRegister.exec(funcStr);
      const bodys = bodyRegister.exec(funcStr);
      if (bodys) {
        if (param) {
          const paramArray = param[0].split(',');
          return new Function(...paramArray, bodys[0]);
        } else {
          return new Function(bodys[0]);
        }
      } else {
        return null;
      }
    } else {
      return eval(funcStr);
    }
  }

  /**
   * clone other type
   *
   * @param { any } target
   *
   * @param { any } type - data type
   */
  private cloneOtherType(target, type) {
    const ctor = target.constructor;
    switch (type) {
      case boolType:
      case numberType:
      case stringType:
      case errorType:
      case dateType:
        return new ctor(target);
      case regexpType:
        return this.cloneRegister(target);
      case symbolType:
        return this.cloneSymbo(target);
      case funcType:
        return this.cloneFunc(target);
      default:
        return null;
    }
  }

  /**
   * clone
   *
   * @param { any } target
   *
   * @param { map } map
   */
  public clone(target, map = new WeakMap()) {
    if (!this.isObject(target)) {
      return target;
    }

    const type = this.getType(target);
    let cloneTargets;

    if (Method.includes(deepType, type)) {
      cloneTargets = this.getInit(target);
    } else {
      return this.cloneOtherType(target, type);
    }

    if (map.get(target)) {
      return map.get(target);
    }
    map.set(target, cloneTargets);

    if (type === setType) {
      target.forEach((value) => {
        cloneTargets.add(this.clone(value, map));
      });
      return cloneTargets;
    }

    if (type === mapType) {
      target.forEach((value, key) => {
        cloneTargets.set(key, this.clone(value, map));
      });
      return cloneTargets;
    }

    const keys = type === arrayType ? undefined : Object.keys(target);
    this.forEach(keys || target, (value, key) => {
      if (keys) {
        key = value;
      }
      cloneTargets[key] = this.clone(target[key], map);
    });

    return cloneTargets;
  }
}