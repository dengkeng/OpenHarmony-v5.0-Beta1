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

import type image from '@ohos.multimedia.image';
import { StringUtil } from '@ohos/common';

/**
 * 文件类
 */
export default class FileModel {
  fd: number; // 文件句柄
  name: string; // 文件名称
  path: string; //路径
  width: number; // 图片宽度
  height: number; // 图片高度
  imageSource: image.ImageSource;


  constructor(fd: number, name: string, path: string, width: number, height: number, imageSource: image.ImageSource) {
    this.fd = fd;
    this.name = name;
    this.path = path;
    this.width = width;
    this.height = height;
    this.imageSource = imageSource;
  }
}
