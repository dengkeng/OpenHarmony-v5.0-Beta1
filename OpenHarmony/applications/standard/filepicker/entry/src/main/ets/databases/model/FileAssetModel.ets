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

import MediaLibrary from '@ohos.multimedia.mediaLibrary';
import { MILLISECOND } from '../../base/constants/Constant';
import { formatSuffix, getResourceString } from '../../base/utils/Tools';
import DateTimeUtil from '../../base/utils/DateTimeUtil';
import { FileMimeTypeUtil } from '../../base/utils/FileMimeTypeUtil';
import LanguageUtil from '../../base/utils/LanguageUtil';
import ErrorCodeConst from '../../base/constants/ErrorCodeConst';
import { MimeType } from './MimeType';
import { THUMBNAIL_SIZE } from '../../base/constants/UiConstant';
import { BasicDataSource } from './BasicDataSource';
import Logger from '../../base/log/Logger';
import AbilityCommonUtil from '../../base/utils/AbilityCommonUtil';

const TAG = 'FileAssetModel';

export class FileAssetLazyModel extends BasicDataSource {
  private dataArray: FileAssetModel[] = [];
  public dataCount: number = 0;

  public totalCount(): number {
    return this.dataArray.length;
  }

  public getDataArray(): FileAssetModel[] {
    return this.dataArray;
  }

  public setData(data: FileAssetModel[]): void {
    this.dataArray = [...data];
    this.dataCount = this.dataArray.length;
    this.notifyDataReload();
  }

  public getData(index: number): FileAssetModel {
    return this.dataArray[index];
  }

  public selectAll(isSelected: boolean): void {
    this.dataArray.forEach(item => {
      item.isChecked = isSelected;
    });
  }

  public getIndex(uri): number {
    return this.dataArray.findIndex(item => item.uri === uri);
  }

  public getSelectedFileList(): FileAssetModel[] {
    return this.dataArray.filter(item => item.isChecked);
  }

  public replaceData(index, data: FileAssetModel): void {
    this.dataArray.splice(index, 1, data);
    this.notifyDataChange(index);
  }

  public addData(index: number, data: FileAssetModel): void {
    this.dataArray.splice(index, 0, data);
    this.dataCount = this.dataArray.length;
    this.notifyDataAdd(index);
  }

  public pushData(data: FileAssetModel): void {
    this.dataArray.push(data);
    this.dataCount = this.dataArray.length;
    this.notifyDataAdd(this.dataArray.length - 1);
  }

  public deleteData(index: number): void {
    this.dataArray.splice(index, 1);
    this.dataCount = this.dataArray.length;
    this.notifyDataDelete(index);
  }
}

/**
 * 媒体文件信息类
 */
export class FileAssetModel {
  public id: number;
  public uri: string;
  public mimeType: string;
  public mediaType: number;
  public displayName: string;
  public title: string;
  public relativePath: string;
  public parent: number;
  public size: number;
  public dateAdded: number;
  public dateModified: number;
  public dateTaken: number;
  public artist: string;
  public audioAlbum: string;
  public width: number;
  public height: number;
  public orientation: number;
  public duration: number;
  public albumId: number;
  public albumUri: string;
  public albumName: string;
  // MediaLibrary.FileAsset对象外的属性
  public fileName: string;
  public fullPath: string;
  public isChecked: boolean = false;
  public suffix: string;
  public icon: Resource | PixelMap;
  public gridIcon: Resource | PixelMap;
  public localGridIcon: Resource | PixelMap;
  public lastModifiedDate: string | Resource;
  public thumbUri: string;
  public sortLabel: string = '';
  public mimeTypeObj: MimeType;

  constructor(file) {
    this.id = file.id;
    this.uri = file.uri;
    this.mimeType = file.mimeType;
    this.mediaType = file.mediaType;
    this.displayName = file.displayName;
    this.title = file.title;
    this.relativePath = file.relativePath;
    this.parent = file.parent;
    this.size = file.size;
    this.dateAdded = file.dateAdded;
    this.dateModified = file.dateModified * MILLISECOND.ONE_SECOND;
    this.dateTaken = file.dateTaken;
    this.artist = file.artist;
    this.audioAlbum = file.audioAlbum;
    this.width = file.width;
    this.height = file.height;
    this.orientation = file.orientation;
    this.duration = file.duration;
    this.albumId = file.albumId;
    this.albumUri = file.albumUri;
    this.albumName = file.albumName;

    this.fileName = file.displayName;
    this.mimeTypeObj = FileMimeTypeUtil.getFileMimeType(this.fileName);
    this.fullPath = getFullPath(this);
    this.suffix = formatSuffix(file.fileName);
    this.icon = this.mimeTypeObj.getResID();
    this.gridIcon = this.mimeTypeObj.getGridResID();
    this.localGridIcon = this.mimeTypeObj.getLocalGridResID();
    this.lastModifiedDate = DateTimeUtil.getDateStringForCategory(this.dateModified);
    this.sortLabel = file.sortLabel;
    if (this.mimeTypeObj.isMedia()) {
      this.thumbUri = `${this.uri}/thumbnail/${THUMBNAIL_SIZE.WIDTH}/${THUMBNAIL_SIZE.HEIGHT}`;
    }
  }

  setFileName(fileName: string): void {
    this.fileName = fileName;
    this.mimeTypeObj = FileMimeTypeUtil.getFileMimeType(this.fileName);
    this.fullPath = getFullPath(this);
    this.icon = this.mimeTypeObj.getResID();
    this.gridIcon = this.mimeTypeObj.getGridResID();
    this.localGridIcon = this.mimeTypeObj.getLocalGridResID();
    if (this.mimeTypeObj.isMedia()) {
      this.thumbUri = `${this.uri}/thumbnail/${THUMBNAIL_SIZE.WIDTH}/${THUMBNAIL_SIZE.HEIGHT}`;
    }
  }

  pickFile(): void {
    AbilityCommonUtil.terminateFilePicker([this.uri], [this.fileName]);
  }
}

/**
 * 对媒体文件进行排序
 * @param dataList 待排序数组
 * @param order 排序规则
 * @param isDesc 是否倒序
 * @return 排序后的数组
 */
function sortFileAssetList(dataList) {
  const language = LanguageUtil.getSystemLanguage();
  return dataList.sort((a, b) => {
    if (b.dateModified !== a.dateModified) {
      return b.dateModified - a.dateModified;
    } else {
      return b.displayName.localeCompare(a.displayName, language);
    }
  })
}

/**
 * 媒体库查询条件类
 */
export class MediaFetchOptions {
  public selections: string = MediaLibrary.FileKey.MEDIA_TYPE + '=?';
  public selectionArgs: string[] = [];
  public order: string = MediaLibrary.FileKey.DATE_MODIFIED + ' DESC';
  public uri: string;
  public networkId: string;
  public extendArgs: string;

  constructor(mediaTypeArg: string = '') {
    if (!mediaTypeArg) {
      this.selections = '';
    } else {
      this.selectionArgs.push(mediaTypeArg);
    }
  }

  /**
   * 设置要查询文件的uri
   */
  setUri(uri: string): void {
    this.uri = uri;
  }

  /**
   * 追加其他查询条件
   * @param selection 要查询的关键字
   * @param selectionArg 要查询的值
   */
  addSelection(selection: MediaLibrary.FileKey, selectionArg: string) {
    if (this.selections.length) {
      this.selections += ` AND ${selection} = ? `;
    } else {
      this.selections = `${selection} = ?`;
    }
    this.selectionArgs.push(selectionArg);
  }
}

/**
 * 查询媒体库内指定类型的文件
 * @param mediaFetchOptions 媒体库查询条件
 * @return 文件列表
 */
export function getMediaFileAssets(mediaFetchOptions: MediaFetchOptions): Promise<FileAssetModel[]> {
  const mediaLibrary = AbilityCommonUtil.getMediaLibrary();
  if (!mediaLibrary) {
    return Promise.resolve([]);
  }
  return mediaLibrary.getFileAssets(mediaFetchOptions).then((fetchFileResult: MediaLibrary.FetchFileResult) => {
    return fetchFileResult.getAllObject().then((fileAssetList: MediaLibrary.FileAsset[]) => {
      let newFileAssetList = [];
      fileAssetList.forEach(fileAsset => {
        newFileAssetList.push(new FileAssetModel(fileAsset));
      });
      newFileAssetList = addSortLabel(newFileAssetList);
      newFileAssetList = sortFileAssetList(newFileAssetList);
      return newFileAssetList;
    }).catch((err) => {
      // 媒体库查询为空code返回3
      if (err.code === ErrorCodeConst.FILE_ACCESS.GET_MEDIAFILE_NULL) {
        Logger.e(TAG, 'no media file');
        return [];
      }
      return Promise.reject(err);
    }).finally(() => {
      fetchFileResult.close();
    })
  }).catch((err) => {
    return Promise.reject(err);
  })
}

/**
 * 根据文件名（后缀）判断媒体类型
 * @param fileName 文件名
 * @return 媒体类型MediaLibrary.MediaType
 */
export function getMediaType(fileName: string): MediaLibrary.MediaType {
  const mimeType = FileMimeTypeUtil.getFileMimeType(fileName);
  if (mimeType.isImage()) {
    return MediaLibrary.MediaType.IMAGE;
  } else if (mimeType.isVideo()) {
    return MediaLibrary.MediaType.VIDEO;
  } else if (mimeType.isAudio()) {
    return MediaLibrary.MediaType.AUDIO;
  } else {
    return MediaLibrary.MediaType.FILE;
  }
}

export function getDurationByUri(mediaType: MediaLibrary.MediaType, uri: string): Promise<number> {
  const option = new MediaFetchOptions(mediaType.toString());
  option.setUri(uri);
  return getMediaFileAssets(option).then((res) => {
    if (res && res.length) {
      return res[0].duration;
    } else {
      return 0;
    }
  }).catch(() => {
    return 0;
  })
}

/**
 * 获取文件的完整路径
 * @param file 文件信息
 * @return 完整路径
 */
export function getFullPath(file: FileAssetModel): string {
  return getResourceString($r('app.string.myPhone')) + '/' + file.relativePath + file.fileName;
}

/**
 * 设置文件列表排序后需要显示的label
 * @param fileAssetList 文件列表
 * @param order 排序规则
 * @return 设置了label的文件数组
 */
export function addSortLabel(fileAssetList): FileAssetModel[] {
  fileAssetList.forEach((fileAsset: FileAssetModel) => {
    fileAsset.sortLabel = DateTimeUtil.getDateStringForCategory(fileAsset.dateModified);
  });
  return fileAssetList;
}


