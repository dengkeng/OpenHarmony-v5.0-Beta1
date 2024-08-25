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

import {LogUtil} from '../baseUtil/LogUtil'
import MediaLib from '@ohos.multimedia.mediaLibrary';

const TAG = "MediaLibraryAccess"
export class MediaLibraryAccess {

  static async getFirstObject(fetchOpt, context) {
    let album = {
      count: 0,
      obj: null,
    }
    try {
      // 通过Uri拷贝图片到指定指定的包路径下
      // 1、获取本地路径

      let fileResult = await MediaLib.getMediaLibrary(context).getFileAssets(fetchOpt)
      if (fileResult != undefined) {
        album.count = fileResult.getCount();
        if (album.count <= 0) {
          return album;
        }

        let file = await fileResult.getFirstObject();
        if (file) {
          album.obj = file;
          return album;
        } else {
          LogUtil.warn(TAG, 'Failed getFirstObject')
        }
      }
      return album;
    }
    catch (error) {
      LogUtil.error(TAG, `getFirstObject loadData error: ${error}`)
      return album;
    }
  }

  static async openAsset(mode: string, fileAsset: any) {
    LogUtil.info(TAG, 'openAsset start')
    let fd = await fileAsset.open(mode);
    LogUtil.info(TAG, `openAsset end. fd: ${fd}`)

    if (fd <= 0) {
      LogUtil.warn(TAG, 'openAsset Fail')
      return;
    }

    return fd;
  }

  static async closeAsset(fd: number, fileAsset: any) {
    LogUtil.info(TAG, 'closeAsset start')

    if (fd <= 0) {
      LogUtil.warn(TAG, 'closeAsset fd is invalid')
      return;
    }

    try {
      await fileAsset.close(fd)
      LogUtil.info(TAG, 'closeAsset end')

    } catch (error) {
      LogUtil.warn(TAG, 'closeAsset fail')
    }
  }
}