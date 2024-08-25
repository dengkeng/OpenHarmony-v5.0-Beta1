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

/**
 * FileAccessManager删除、复制、移动、重命名等操作
 */
import Logger from '../log/Logger';
import { FilesData } from '../../databases/model/FileData';
import { FOLDER_LEVEL, DESKTOP_FOLDER } from '../constants/Constant';
import { sortDataByTime, randomId, sortBaseDataByOrderTime } from './Tools';
import fileAccess from '@ohos.file.fileAccess';
import fileExtensionInfo from '@ohos.file.fileExtensionInfo';
import { FileBase } from '../../databases/model/base/FileBase';
import ObjectUtil from './ObjectUtil';
import { FileUtil } from './FileUtil';

const TAG = 'FileAccessExec';

namespace FileAccessExec {

  // 创建文件夹
  export function createFolder(sourceUri: string, folderName: string): any {
    return new Promise((resolve, reject) => {
      try {
        globalThis.fileAcsHelper.mkDir(sourceUri, folderName, (ret, data) => {
          if (ret && ret.code !== '0') {
            reject(ret);
            Logger.e(TAG, 'createFolder fail:' + JSON.stringify(ret));
          } else {
            resolve(data);
          }
        })
      } catch (error) {
        reject(error);
        Logger.e(TAG, 'createFolder error occurred:' + error);
      }
    })
  }

  // 创建文件
  export function createFile(sourceUri: string, fileName: string): any {
    return new Promise((resolve, reject) => {
      try {
        globalThis.fileAcsHelper.createFile(sourceUri, fileName, (ret, data) => {
          if (ret && ret.code !== '0') {
            reject(ret);
            Logger.e(TAG, 'createFile fail:' + JSON.stringify(ret));
          } else {
            resolve(data);
          }
        })
      } catch (error) {
        reject(error);
        Logger.e(TAG, 'createFile error occurred:' + error);
      }
    })
  }

  export function getFileData(): any {
    let folderList: FilesData[] = [];
    let fileList: FilesData[] = [];
    const allData = getRootFolder();
    allData.forEach((item) => {
      if (item.isFolder) {
        folderList.push(new FilesData({
          ...item
        }));
      } else {
        fileList.push(new FilesData({
          ...item
        }));
      }
    })

    return { folderList, fileList };
  }

  export function getFileByCurIterator(fileInfo: fileAccess.FileInfo | fileAccess.RootInfo): FilesData[] {
    let fileList: FilesData[] = [];
    try {
      let fileIterator = fileInfo.listFile();
      if (!fileIterator) {
        Logger.w(TAG, 'getFileByCurIterator fail, fileIterator is null');
        return fileList;
      }
      let result = fileIterator.next();
      let isDone = result.done;
      while (!isDone) {
        const {fileName, relativePath,uri, mode, size, mtime, mimeType} = result.value;
        let tempFile = new FilesData({
          id: randomId(),
          fileName,
          relativePath,
          uri,
          mode,
          size,
          mtime,
          mimeType,
          fileIterator: result.value
        });
        fileList.push(tempFile);
        result = fileIterator.next();
        isDone = result.done;
      }
      fileList = sortDataByTime(fileList);
    } catch (error) {
      fileList = [];
      Logger.e(TAG, 'getFileByCurIterator fail, error:' + JSON.stringify(error) + error);
    }
    return fileList;
  }

  export function getPathPickSubFiles(fileInfo: fileAccess.FileInfo,
                                      defaultPathPick: string, level: number): FileBase[] {
    let fileArr: FileBase[] = [];
    let fileIterator = fileInfo.listFile();
    if (!fileIterator) {
      return fileArr;
    }
    let result = fileIterator.next();
    let isDone = result.done;
    while (!isDone) {
      try {
        let fileInfo: fileAccess.FileInfo = result.value;
        if (!ObjectUtil.isNullOrUndefined(fileInfo)) {
          let tempFile = new FileBase(result.value, false);
          if (tempFile.isFolder) {
            if (FileUtil.hasSubFolder(defaultPathPick, tempFile.currentDir) && level <= FOLDER_LEVEL.MAX_LEVEL) {
              tempFile.subList = getPathPickSubFiles(fileInfo, defaultPathPick, level + 1);
            }
          }
          // 根目录下不显示Documents文件夹
          fileArr.push(tempFile);
        }
        result = fileIterator.next();
        isDone = result.done;
      } catch (e) {
        Logger.e(TAG, 'getSubFileByIterator error: ' + e.toString());
        isDone = true;
      }
    }
    fileArr = sortBaseDataByOrderTime(fileArr, true);
    return fileArr;
  }


  export function getRootFolder(): FilesData[] {
    let fileList: FilesData[] = [];
    if (!globalThis.rootInfoArr) {
      Logger.e(TAG, 'getRootFolder fail, rootInfoArr is null');
      return fileList;
    }
    try {
      const rootFolder: fileAccess.RootInfo = globalThis.rootInfoArr.find(
        (item: fileAccess.RootInfo) => item.deviceType === fileExtensionInfo.DeviceType.DEVICE_LOCAL_DISK);
      if (rootFolder) {
        globalThis.documentInfo = rootFolder;
        fileList = getFileByCurIterator(rootFolder);
        fileList = fileList.filter(item => item.fileName !== DESKTOP_FOLDER);
      } else {
        Logger.e(TAG, 'rootFolder is null');
      }
    } catch (error) {
      fileList = [];
      Logger.e(TAG, 'getRootFolder fail, error:' + JSON.stringify(error) + error);
    }
    return fileList;
  }
}

export default FileAccessExec;