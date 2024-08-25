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

import fileExtensionInfo from '@ohos.file.fileExtensionInfo';
import fileAccess from '@ohos.file.fileAccess';
import ObjectUtil from './ObjectUtil';
import Logger from '../log/Logger';
import StringUtil from './StringUtil';
import { FILENAME_MAX_LENGTH,
  RENAME_CONNECT_CHARACTER } from '../constants/Constant';
import MediaLibrary from '@ohos.multimedia.mediaLibrary';

const TAG = 'FileUtil';

export class FileUtil {

  /**
   * uri 格式开头
   */
  static readonly URI_START = 'file://';

  /**
   * 根据fileAccess.FileInfo中的mode匹配是否是文件夹
   * @param mode number
   * @returns boolean
   */
  public static isFolder(mode: number): boolean {
    return (mode & fileExtensionInfo.DocumentFlag.REPRESENTS_DIR) === fileExtensionInfo.DocumentFlag.REPRESENTS_DIR;
  }

  /**
   * 计算文件夹子文件个数
   * @param fileIterator fileAccess.FileIterator
   * @returns number
   */
  public static getChildCountOfFolder(fileIterator: fileAccess.FileIterator): number {
    let count = 0;
    if (ObjectUtil.isNullOrUndefined(fileIterator)) {
      return count;
    }
    let isDone: boolean = false;
    while (!isDone) {
      let currItem = fileIterator.next();
      isDone = currItem.done;
      if (isDone) {
        break;
      }
      count++;
    }
    return count;
  }

  /**
   * 获取文件信息
   * @param uri 文件uri
   * @param fileAccessHelper fileAccess.FileAccessHelper
   * @returns fileAccess.FileInfo
   */
  public static async getFileInfoByUri(uri: string, fileAccessHelper: fileAccess.FileAccessHelper): Promise<fileAccess.FileInfo> {
    try {
      return await fileAccessHelper.getFileInfoFromUri(uri);
    } catch (err) {
      Logger.e(TAG, 'getFileInfoByUri err: ' + JSON.stringify(err));
    }
    return null;
  }

  /**
   * 获取文件信息
   * @param relativePath 文件relativePath
   * @param fileAccessHelper fileAccess.FileAccessHelper
   * @returns fileAccess.FileInfo
   */
  public static async getFileInfoByRelativePath(relativePath: string, fileAccessHelper: fileAccess.FileAccessHelper): Promise<fileAccess.FileInfo> {
    try {
      return await fileAccessHelper.getFileInfoFromRelativePath(relativePath);
    } catch (err) {
      Logger.e(TAG, 'getFileInfoByRelativePath err: ' + JSON.stringify(err));
    }
    return null;
  }

  /**
   * 根据uri获取文件夹子文件列表Iterator
   * @param uri
   * @param fileAccessHelper
   * @returns FileIterator
   */
  public static async getFileIteratorByUri(uri: string, fileAccessHelper: fileAccess.FileAccessHelper): Promise<fileAccess.FileIterator> {
    try {
      let fileInfo = await fileAccessHelper.getFileInfoFromUri(uri);
      return fileInfo.listFile();
    } catch (err) {
      Logger.e(TAG, 'getFileIteratorByUri err: ' + JSON.stringify(err));
    }
    return null;
  }

  public static getFileAccessHelper(context, wants): fileAccess.FileAccessHelper {
    try {
      return fileAccess.createFileAccessHelper(context, wants);
    } catch (err) {
      Logger.i(TAG, 'getFileAccessHelper err: ' + JSON.stringify(err));
    }
    return null;
  }

  public static async getFileAccessHelperAsync(context): Promise<fileAccess.FileAccessHelper> {
    try {
      let wants = await fileAccess.getFileAccessAbilityInfo();
      return fileAccess.createFileAccessHelper(context, wants);
    } catch (err) {
      Logger.i(TAG, 'getFileAccessHelperAsync err: ' + JSON.stringify(err));
    }
    return null;
  }

  public static getParentRelativePath(relativePath: string): string {
    let curPath = relativePath;
    if (StringUtil.isEmpty(relativePath)) {
      return '';
    }

    let index: number = curPath.lastIndexOf('/');
    // 去掉最后一个'/'
    if (index === curPath.length - 1) {
      curPath = curPath.substr(0, index);
    }
    index = curPath.lastIndexOf('/');
    if (index <= 0) {
      return '';
    }
    return curPath.substr(0, index + 1);
  }

  public static getUsageHabitsKey(prefix: string, suffix: string): string {
    return prefix + suffix.charAt(0).toLocaleUpperCase() + suffix.substring(1);
  }

  /**
   * 是否是uri路径
   * @param path 路径
   * @returns 结果
   */
  public static isUriPath(path: string): boolean {
    if (ObjectUtil.isNullOrUndefined(path)) {
      return false;
    }
    return path.startsWith(this.URI_START);
  }

  /**
   * 从目录下获取某个文件名的文件
   * @param foldrUri 目录uri
   * @param fileName 文件名
   * return 结果
   */
  public static async getFileFromFolder(foldrUri: string, fileName, fileAccessHelper: fileAccess.FileAccessHelper): Promise<fileAccess.FileInfo> {
    // 先将目录的信息查询出来
    let fileInfo: fileAccess.FileInfo = await this.getFileInfoByUri(foldrUri, fileAccessHelper);
    if (ObjectUtil.isNullOrUndefined(fileInfo)) {
      return null;
    }
    // 构建目标目录下的同名文件的相对路径
    const destFileRelativePath = fileInfo.relativePath + fileInfo.fileName + '/' + fileName;
    // 根据相对路径查询相应的文件
    return await this.getFileInfoByRelativePath(destFileRelativePath, fileAccessHelper);
  }

  /**
   * 根据FileInfo获取当前文件的文件夹
   *
   * @param fileInfo 文件对象
   * @returns 返回当前文件的文件夹
   */
  public static getCurrentFolderByFileInfo(fileInfo: fileAccess.FileInfo): string {
    if (fileInfo !== null) {
      let path = fileInfo.relativePath;
      return FileUtil.getCurrentDir(path, FileUtil.isFolder(fileInfo.mode));
    }
    return "";
  }

  public static async createFolder(fileAccessHelper: fileAccess.FileAccessHelper, parentUri: string, name: string): Promise<{code, uri}> {
    let uri: string = '';
    let code: any;
    try {
      uri = await fileAccessHelper.mkDir(parentUri, name);
    } catch (error) {
      code = error.code;
      Logger.e(TAG, 'createFolder error occurred:' + error.code + ', ' + error.message);
    }
    return {code: code, uri: uri};
  }

  public static async hardDelete(uri: string, mediaLibrary: MediaLibrary.MediaLibrary): Promise<boolean> {
    if (ObjectUtil.isNullOrUndefined(mediaLibrary)) {
      return false;
    }
    try {
      await mediaLibrary.deleteAsset(uri);
      return true;
    } catch (e) {
      Logger.e(TAG, 'hardDelete error: ' + JSON.stringify(e));
    }
    return false;
  }

  /**
   * 重命名
   * @param fileAccessHelper FileAccessHelper
   * @param oldUri oldUri
   * @param newName newName
   * @returns {err, uri}
   */
  public static async rename(fileAccessHelper: fileAccess.FileAccessHelper, oldUri: string, newName: string): Promise<{err, uri}> {
    let uri: string = '';
    let err: any;
    try {
      uri = await fileAccessHelper.rename(oldUri, newName);
    } catch (error) {
      err = {code: error.code, message: error.message};
      Logger.e(TAG, 'rename error occurred:' + error.code + ', ' + error.message);
    }
    return {err: err, uri: uri};
  }

  public static async createFile(fileAccessHelper: fileAccess.FileAccessHelper, parentUri: string, fileName: string): Promise<{err, uri}> {
    let retUri: string = '';
    let err: any;
    try {
      Logger.i(TAG, 'createFile ' + fileAccessHelper + '; ' + parentUri + " ; " + fileName);
      retUri = await fileAccessHelper.createFile(parentUri, fileName);
    } catch (e) {
      Logger.e(TAG, 'createFile error: ' + e.code + ', ' + e.message);
      err = {code: e.code, message: e.message};
    }
    return {err: err, uri: retUri};
  }

  public static hasSubFolder(loadPath: string, curFolderPath: string): boolean {
    if (!StringUtil.isEmpty(loadPath)) {
      if (!StringUtil.isEmpty(curFolderPath)) {
        loadPath = FileUtil.getPathWithFileSplit(loadPath);
        curFolderPath = FileUtil.getPathWithFileSplit(curFolderPath);
        if (loadPath.startsWith(curFolderPath)) {
          return true;
        }
      }
    }
    return false;
  }

  public static getPathWithFileSplit(path: string): string {
    let fileSplit: string = '/';
    if (path && !path.endsWith(fileSplit)) {
      path = path + fileSplit;
    }
    return path;
  }

  public static loadSubFinish(loadPath: string, curFolderPath: string, maxLevel: number): boolean {
    let fileSplit: string = '/';
    if (!StringUtil.isEmpty(loadPath)) {
      if (!loadPath.endsWith(fileSplit)) {
        loadPath = loadPath + fileSplit;
      }

      let folders = curFolderPath.split(fileSplit);

      if ((curFolderPath + fileSplit) === loadPath || folders.length >= maxLevel) {
        return true;
      }
    }
    return false;
  }

  public static renameFile(fileName: string, renameCount: number, suffix: string): string {
    if (ObjectUtil.isNullOrUndefined(fileName)) {
      return fileName;
    }
    let newName = fileName;
    if (renameCount > 0) {
      newName = fileName + RENAME_CONNECT_CHARACTER + renameCount;
      let strLen = newName.length + suffix.length;
      // 字符长度大于最大长度
      if (strLen > FILENAME_MAX_LENGTH) {
        // 计算需要裁剪的长度
        let subLen = strLen - FILENAME_MAX_LENGTH + 1;
        newName = fileName.substring(0, fileName.length - subLen) + RENAME_CONNECT_CHARACTER + renameCount;
      }
    }
    return newName + suffix;
  }

  public static getFileNameReName(fileName: string): string[] {
    if (StringUtil.isEmpty(fileName)) {
      return null;
    }
    let index = fileName.lastIndexOf(RENAME_CONNECT_CHARACTER);
    if (index === -1) {
      return null;
    }
    let str = fileName.substring(index + 1, fileName.length);
    let name = fileName.substring(0, index);
    return [name, str];
  }

  public static getCurrentDir(path: string, isFolder: boolean): string {
    if (isFolder) {
      return path;
    }
    if (path) {
      let index: number = path.lastIndexOf('/');
      let len: number = path.length;
      if (len > 1 && index > 1) {
        return path.substring(0, index);
      }
    }
    return path;
  }

  public static getUriPath(path: string): string {
    if (path && FileUtil.isUriPath(path)) {
      return path;
    }
    return null;
  }
}