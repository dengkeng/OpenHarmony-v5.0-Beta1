/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

const LARGE_SCREEN_GRID_SUM: number = 12;
const SMALL_SCREEN_GRID_SUM: number = 8;
const VP2PX_SUM_IN_LARGE_SCREEN: number = 2;

class Utils {
  isValid(item: unknown): boolean {
    return item !== null && item !== undefined;
  }

  checkObjPropertyValid<T>(obj: T, tree: string): boolean {
    if (!this.isValid(obj) || !this.isValid(tree)) {
      return false;
    }

    let arr = tree.split('.');
    let tempObj = obj;
    for (let i = 0; i < arr.length; i++) {
      if (!this.isValid(tempObj[arr[i]])) {
        return false;
      } else {
        tempObj = tempObj[arr[i]];
      }
    }
    return true;
  }

  isLargeDevice(): number {
    return vp2px(1) === VP2PX_SUM_IN_LARGE_SCREEN ? LARGE_SCREEN_GRID_SUM : SMALL_SCREEN_GRID_SUM;
  }
}

export default new Utils();