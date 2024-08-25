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
import { GlobalObject } from './GlobalObject';
import { Log } from './Log';

const TAG: string = 'SingletonHelper';
/**
 * 获取单例类
 */
export class SingletonHelper {
  static getInstance<T>(clazz: { new(): T }, key: string): T {
    if (!GlobalObject.getInstance().hasObject(key)) {
      GlobalObject.getInstance().setObject(key, new clazz());
      Log.info(TAG, `Create key of ${key}`);
    }
    return GlobalObject.getInstance().getObject(key) as T;
  }
}