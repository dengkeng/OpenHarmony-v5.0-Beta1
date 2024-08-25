/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

import fileAccess from '@ohos.file.fileAccess';
import { MILLISECOND } from '../../../base/constants/Constant';
import { FileUtil } from '../../../base/utils/FileUtil';
import ObjectUtil from '../../../base/utils/ObjectUtil';
import Logger from '../../../base/log/Logger';

const TAG: string = 'FileBase';

export class FileBase {
  uri: string;
  relativePath: string;
  fileName: string;
  mode: number;
  isFolder: boolean;
  fileSize: number;
  modifyTime: number;
  mimeType: string;
  childCount: number;
  firstUri: string;
  subList: Array<FileBase>;
  currentDir?: string;

  constructor(fileInfo: fileAccess.FileInfo, needChildCount: boolean = true) {
    if (ObjectUtil.isNullOrUndefined(fileInfo)) {
      return;
    }
    this.uri = fileInfo.uri;
    this.relativePath = fileInfo.relativePath;
    this.fileName = fileInfo.fileName;
    this.fileSize = fileInfo.size;
    this.mode = fileInfo.mode;
    this.isFolder = FileUtil.isFolder(this.mode);
    this.modifyTime = fileInfo.mtime * MILLISECOND.ONE_SECOND;
    if (this.modifyTime <= 0) {
      Logger.w(TAG, "The modification time of " + this.fileName + " is " + this.modifyTime);
    }
    this.mimeType = fileInfo.mimeType;
    if (this.isFolder && needChildCount) {
      this.childCount = FileUtil.getChildCountOfFolder(fileInfo.listFile());
    }
    this.currentDir = FileUtil.getCurrentDir(this.relativePath, this.isFolder);
  }
}