/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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
import { Log } from './Log';

const TAG: string = 'GlobalObject';
/**
 * 构造单利对象，提供全局变量缓存代替globalThis
 */
export class GlobalObject {
  private static instance: GlobalObject;
  private _objects = new Map<string, Object>();

  private constructor() {
  }

  /**
   * 获取全局单个实例方法
   *
   * @returns instance instance
   */
  public static getInstance(): GlobalObject {
    if (GlobalObject.instance == null) {
      GlobalObject.instance = new GlobalObject();
    }
    return GlobalObject.instance;
  }

  /**
   * 从Map中返回指定的元素
   *
   * @param key key
   * @returns 返回指定key的元素，获取不到返回undefined
   */
  public getObject(key: string): Object | undefined {
    let result = this._objects.get(key);
    Log.info(TAG, 'getValue: ' + key + ' -> ' + (result != null));
    return result;
  }

  /**
   * 将指定键和值添加到Map中。如果已存在相同元素，则更新元素
   *
   * @param key map中映射的唯一标记
   * @param objectClass 需要存储的元素
   */
  public setObject(key: string, objectClass: Object): void {
    this._objects.set(key, objectClass);
    Log.info(TAG, 'setObject: ' + key);
  }

  /**
   * 从Map中移除指定元素
   *
   * @param key map中映射的唯一标记
   * @returns 是否成功移除key对应元素
   */
  public removeObject(key: string): boolean {
    Log.info(TAG, 'delete: ' + key);
    return this._objects.delete(key);
  }

  /**
   * 判断从Map中是否存在指定元素
   *
   * @param key map中映射的唯一标记
   * @returns 存在返回true
   */
  public hasObject(key: string): boolean {
    return this._objects.has(key);
  }
}