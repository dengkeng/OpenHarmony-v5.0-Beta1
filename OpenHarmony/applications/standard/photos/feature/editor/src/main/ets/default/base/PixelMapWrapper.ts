/*
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

import type { Releasable } from '@ohos/common';

export class PixelMapWrapper implements Releasable {
  pixelMap: PixelMap = undefined;
  width: number = 0;
  height: number = 0;

  constructor(pixelMap: PixelMap, width: number, height: number) {
    this.pixelMap = pixelMap;
    this.width = width;
    this.height = height;
  }

  release() {
    if (this.pixelMap != null && this.pixelMap != undefined) {
      this.pixelMap.release();
    }
    this.width = 0;
    this.height = 0;
  }
}