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

import Fileio from '@ohos.file.fs';
import image from '@ohos.multimedia.image';
import type common from '@ohos.app.ability.common';
import { Log, PageDirection } from '@ohos/common';
import CheckEmptyUtils from '@ohos/common';
import FileModel from '../../Model/FileModel';
import { Constants } from '@ohos/common';
import { GlobalThisHelper, GlobalThisStorageKey} from '@ohos/common';


const FILE_SEPARATOR = '/';
const TAG = 'FileUtil';
const READ_DATA_SIZE = 4096;

export default class FileUtil {
  /**
   * Read Json file from disk by file path.
   *
   * @param {string} path - path of the target file.
   * @return {any} - read object from file
   */
  static readJsonFile(path: string): string {
    Log.info(TAG, 'readJsonFile start execution');
    let readStreamSync = null;
    let content: string = undefined;
    try {
      readStreamSync = Fileio.createStreamSync(path, 'r');
      content = this.getContent(readStreamSync);
      Log.info(TAG, `readJsonFile finish execution content: ${content}`);
      return <string> JSON.parse(content);
    } catch (e) {
      Log.error(TAG, `readJsonFile error: ${JSON.stringify(e)}`);
    } finally {
      if (readStreamSync !== undefined) {
        readStreamSync.closeSync();
      }
    }
    return content;
  }

  /**
   * Read String from disk by bundleName.
   *
   * @param {string} bundleName - bundleName as target file name
   * @return {string} - read string from file
   */
  static readStringFromFile(bundleName: string, abilityContext: common.Context): string {
    Log.info(TAG, 'readStringFromFile start execution');
    const filePath = abilityContext.filesDir + FILE_SEPARATOR + bundleName + '.json';
    let readStreamSync = null;
    let content: string = undefined;
    try {
      readStreamSync = Fileio.createStreamSync(filePath, 'r');
      content = this.getContent(readStreamSync);
      Log.info(TAG, 'readStringFromFile finish execution');
    } catch (e) {
      Log.error(TAG, `readStringFromFile error: ${JSON.stringify(e)}`);
    } finally {
      if (readStreamSync !== null) {
        readStreamSync.closeSync();
      }
    }
    return content;
  }

  /**
   * Write string to a file.
   *
   * @param {string} string - target string will be written to file
   * @param {string} bundleName - bundleName as target file name
   */
  static writeStringToFile(string: string, bundleName: string, abilityContext: common.Context): void {
    Log.info(TAG, 'writeStringToFile start execution');
    const filePath = abilityContext.filesDir + FILE_SEPARATOR + bundleName + '.json';
    let writeStreamSync = null;
    try {
      writeStreamSync = Fileio.createStreamSync(filePath, 'w+');
      writeStreamSync.writeSync(string);
    } catch (e) {
      Log.error(TAG, `writeStringToFile error: ${JSON.stringify(e)}`);
    } finally {
      if (writeStreamSync !== null) {
        writeStreamSync.closeSync();
        Log.info(TAG, 'writeStringToFile close sync');
      }
    }
  }

  /**
   * Read JSON object from a file.
   *
   * @param {object} readStreamSync - stream of target file
   * @return {object} - object read from file stream
   */
  static getContent(readStreamSync): string {
    Log.info(TAG, 'getContent start');
    const bufArray = [];
    let totalLength = 0;
    let buf = new ArrayBuffer(READ_DATA_SIZE);
    let len: number = readStreamSync.readSync(buf);
    while (len !== 0) {
      Log.debug(TAG, `getContent FileIO reading ${len}`);
      totalLength += len;
      if (len < READ_DATA_SIZE) {
        buf = buf.slice(0, len);
        bufArray.push(buf);
        break;
      }
      bufArray.push(buf);
      buf = new ArrayBuffer(READ_DATA_SIZE);
      len = readStreamSync.readSync(buf);
    }
    Log.info(TAG, `getContent read finished: ${totalLength}`);
    const contentBuf = new Uint8Array(totalLength);
    let offset = 0;
    for (const bufArr of bufArray) {
      Log.debug(TAG, `getContent collecting: ${offset}`);
      const uInt8Arr = new Uint8Array(bufArr);
      contentBuf.set(uInt8Arr, offset);
      offset += uInt8Arr.byteLength;
    }
    const content: string = String.fromCharCode.apply(null, new Uint8Array(contentBuf));
    return content;
  }

  /**
   * 初始化ImageData, 将want传过来的uri解析
   */
  public static async initImageData(fileList: Array<string>): Promise<Array<FileModel>> {
    Log.info(TAG, 'initImageData');
    let errorCount: number = 0;
    let errorFileName: string = 'file';
    let imageArray: FileModel[] = new Array<FileModel>();
    if (CheckEmptyUtils.isEmptyArr(fileList)) {
      Log.error(TAG, 'fileList is empty');
      return imageArray;
    }
    for (let uri of fileList) {
      let uriArr = uri.split(FILE_SEPARATOR);
      let fileName = uriArr[uriArr.length-1];
      let file = undefined;
      try {
        file = Fileio.openSync(uri, Constants.READ_WRITE);
      } catch (error) {
        Log.error(TAG, 'open fail: ' + JSON.stringify(error));
        errorFileName = fileName;
        errorCount++;
        continue;
      }
      if (file === undefined || file.fd < 0) {
        Log.error(TAG, 'open fail, file is undefined');
        errorFileName = fileName;
        errorCount++;
        continue;
      }
      Log.info(TAG, 'fd is ' + file.fd);
      let imageSource = image.createImageSource(file.fd);
      Log.info(TAG, 'image.createImageSource: ', JSON.stringify(imageSource));
      if (CheckEmptyUtils.isEmpty(imageSource)) {
        Log.error(TAG, 'imageSource is error');
        errorFileName = fileName;
        errorCount++;
        continue;
      }
      let imageInfo = await Promise.resolve(this.getImageInfo(imageSource));
      Log.info(TAG, 'imageSource.getImageInfo: ', JSON.stringify(imageInfo));
      if (CheckEmptyUtils.isEmpty(imageInfo)) {
        Log.error(TAG, 'imageInfo is error');
        errorFileName = fileName;
        errorCount++;
        continue;
      }
      imageArray.push(new FileModel(<number> file.fd, fileName, <string> uri,
        <number> imageInfo.size.width, <number> imageInfo.size.height, imageSource));
      Log.debug(TAG, 'initImageData imageArray: ', JSON.stringify(imageArray));
    }

    GlobalThisHelper.createValue<number>(errorCount, GlobalThisStorageKey.KEY_IMAGE_ERROR_COUNT, true);
    GlobalThisHelper.createValue<string>(errorFileName, GlobalThisStorageKey.KEY_IMAGE_ERROR_NAME);
    // @ts-ignore
    return <object[]> imageArray;
  }

  /**
   * 初始化ImageData, 将want传过来的fd解析
   */
  public static async initFdImageData(fdList: Array<number>): Promise<Array<FileModel>> {
    Log.info(TAG, 'initFdImageData');
    let imageArray: FileModel[] = new Array<FileModel>();
    if (CheckEmptyUtils.isEmptyArr(fdList)) {
      Log.error(TAG, 'fdList is empty');
      // @ts-ignore
      return <object[]> imageArray;
    }
    for (let fd of fdList) {
      Log.info(TAG, 'fd is ' + fd);
      let imageSource = image.createImageSource(fd);
      if (CheckEmptyUtils.isEmpty(imageSource)) {
        Log.error(TAG, 'imageSource is error');
        break;
      }
      let imageInfo = await imageSource.getImageInfo();
      if (CheckEmptyUtils.isEmpty(imageInfo)) {
        Log.error(TAG, 'imageInfo is error');
        break;
      }
      imageArray.push(new FileModel(<number> fd, fd.toString(), fd.toString(), <number> imageInfo.size.width, <number> imageInfo.size.height, imageSource));
    }
    // @ts-ignore
    return <object[]> imageArray;
  }

  /**
   * 转存图片
   *
   * @param pixelMap
   * @param imagePath
   * @param orientation
   */
  static async saveImageToJpeg(pixelMap: image.PixelMap, imagePath: string, orientation: number): Promise<void> {
    let imagePacker = image.createImagePacker();
    let rotation = orientation == PageDirection.LANDSCAPE ? Constants.NUMBER_90 : Constants.NUMBER_0;
    Log.info(TAG, `rotation: ${rotation}`);
    await pixelMap.rotate(rotation);
    Log.info(TAG, 'rotation end');
    let arrayBuffer = await imagePacker.packing(pixelMap, {
      format: 'image/jpeg', quality: 100
    });
    Log.info(TAG, 'packing end');
    let file = Fileio.openSync(imagePath, Constants.READ_WRITE | Constants.CREATE);
    if (file === undefined || file.fd < 0) {
      Log.error(TAG, 'open fail');
      return;
    }
    Log.info(TAG, 'open end');
    let bytesWritten = await Fileio.write(file.fd, arrayBuffer);
    if (bytesWritten) {
      Log.debug('save success');
      Fileio.closeSync(file);
    }
    if (imagePacker !== undefined) {
      imagePacker.release();
    }
  }

  static createJobsDir(filesDir: string): void {
    let jobsDir = filesDir + Constants.FILE_SEPARATOR + Constants.TEMP_JOB_FOLDER;
    try {
      let result = Fileio.accessSync(jobsDir);
      if (result) {
        Log.info(TAG, 'jobs dir exist');
      } else {
        Fileio.mkdirSync(jobsDir);
        Log.info(TAG, 'jobs dir is not exist');
      }
    } catch (err) {
      Log.error(TAG, 'create dir error: ' + JSON.stringify(err));
    }
  }

  static deleteSource(jobFiles: string[]): void {
    if (CheckEmptyUtils.isEmptyArr(jobFiles)) {
      Log.error(TAG, 'jobFiles is empty');
      return;
    }
    let context = GlobalThisHelper.getValue(GlobalThisStorageKey.KEY_MAIN_ABILITY_CONTEXT);
    if (CheckEmptyUtils.isEmpty(context)) {
      Log.error(TAG, 'context is empty');
      return;
    }
    for (let jobFile of jobFiles) {
      try {
        let result = Fileio.accessSync(jobFile);
        if (result) {
          Fileio.unlinkSync(jobFile);
          Log.info(TAG, 'delete success');
        } else {
          Log.info(TAG, 'file is not exist');
        }
      } catch (error) {
        Log.info(TAG, 'delete error: ' + JSON.stringify(error));
      }
    }
  }

  /**
   * 获取所有待打印文件的fd
   *
   * @param jobFiles 待打印文件的uri list
   */
  static getFdList(jobFiles: string[]): Array<number> {
    try {
      let fdList = new Array<number>();
      if (CheckEmptyUtils.isEmptyArr(jobFiles)) {
        Log.error(TAG, 'jobFiles is empty');
        return fdList;
      }
      jobFiles.forEach((uri) => fdList.push(<number> Fileio.openSync(uri).fd));
      Log.info(TAG, 'fd list : ' + JSON.stringify(fdList));
      return fdList;
    } catch (error) {
      Log.error(TAG, 'getFdList error: ' + JSON.stringify(error));
    }
    return new Array<number>();
  }

  static getImageInfo(imageSource: image.ImageSource): Promise<image.ImageInfo> {
    Log.info(TAG, 'getImageInfo: ', JSON.stringify(imageSource));
    return new Promise((returnResult) => {
      imageSource.getImageInfo()
        .then((info) => {
          Log.info(TAG, 'getImageInfo info: ', JSON.stringify(info));
          returnResult(info);
        })
        .catch((error) => {
          Log.info(TAG, 'getImageInfo err: ', JSON.stringify(error));
          returnResult(undefined);
        });
    });
  }
}
