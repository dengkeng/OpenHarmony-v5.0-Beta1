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

import {folderIconMap, folderTextMap} from '../model/NoteBaseData'
import FolderData from '../model/databaseModel/FolderData'
import NoteData from '../model/databaseModel/NoteData'
import {SysDefFolderUuid, FolderType, Favorite, Delete} from '../model/databaseModel/EnumData'
import GlobalResourceManager from './GlobalResourceManager'
import {LogUtil} from './LogUtil'

const TAG = "FolderUtil"

export class FolderUtil {
  /**
  * Get Folder Data
  *
  * @param folderDataArray - Folder data list
  * @param folderUuid - fold uuid
  * @return FolderData
  */
  getFolderData(folderDataArray: FolderData[], folderUuid: string): FolderData {
    LogUtil.info(TAG, "get folder uuid " + folderUuid)
    let folderData = folderDataArray.find((folder) => {
      return folder.uuid == folderUuid
    })
    if (folderData == undefined) {
      LogUtil.info(TAG, "no folder get " + folderUuid)
      folderData = new FolderData(0, "", new Date().getTime() + "", "", FolderType.CusDef, Delete.No, new Date().getTime(), new Date().getTime())
    }
    return folderData
  }

  /**
  * Get Folder Icon
  *
  * @param folderUuid - folder Uuid
  * @return Resource - Folder Icon Resource
  */
  getFolderIcon(folderUuid: string): Resource {
    LogUtil.info(TAG, "folderUuid " + folderUuid)
    if (folderIconMap[folderUuid] != undefined) {
      return folderIconMap[folderUuid]
    }
    return $r("app.media.folder")
  }

  /**
  * Get folder Icon color
  *
  * @param folderDataArray - Folder data list
  * @param selectFolderUuid - Selected fold uuid
  * @param isSelected - is selected or not
  * @return Resource | string - color value
  */
  getFolderIconColor(folderDataArray: FolderData[], selectFolderUuid: string, isSelected: boolean): Resource | string {
    let folderData: FolderData = this.getFolderData(folderDataArray, selectFolderUuid)
    if (folderData == undefined) {
      LogUtil.info(TAG, "FolderIconColor is 182431")
      return $r("app.color.folder_color_182431")
    }
    LogUtil.info(TAG, "folderData uuid " + folderData.uuid + " isSelected " + isSelected)
    if (folderData.folder_type == FolderType.SysDef || folderData.folder_type == FolderType.FeatureDef) {
      if (folderData.uuid ==SysDefFolderUuid.UnClassified) {
        return "#FF9516"
      }
      return isSelected ? $r("app.color.folder_color_f86d05") : $r("app.color.folder_color_99182431")
    }
    return folderData.color
  }

  /**
  * Get folder Text color
  *
  * @param isSelected - is selected or not
  * @return Resource | string - color value
  */
  getFolderTextColor(isSelected: boolean): Resource | string {
    LogUtil.info(TAG, "isSelected " + isSelected)
    return isSelected ? $r("app.color.folder_color_f86d05") : $r("app.color.folder_color_182431")
  }

  /**
  * Is folder bottom fixed
  *
  * @param folderData - Folder
  * @return boolean - fottom fixed folder: deleted or favorite return true. else return false
  */
  isBottomFixedFolder(folderData: FolderData): boolean {
    if (folderData === undefined || folderData === null) {
      LogUtil.info(TAG, "isBottomFixedFolder folderData undefined")
    }
    if (folderData.uuid === undefined || folderData.uuid === null) {
      LogUtil.info(TAG, "isBottomFixedFolder folderData uuid undefined")
      folderData.uuid = 'sys_def_unClassified_uuid';
    }
    LogUtil.info(TAG, "isBottomFixedFolder folderDataUuid " + folderData.uuid)
    return (folderData.folder_type == FolderType.FeatureDef)
  }

  /**
  * Is the folder can be moved into notes
  *
  * @param folderDataUuid - Folder uuid
  * @return boolean - can be moved into notes return true. else return false
  */
  isFolderMoveIn(folderData: FolderData): boolean {
    if (folderData === undefined || folderData === null) {
      LogUtil.info(TAG, "isFolderMoveIn folderData undefined")
    }
    if (folderData.uuid === undefined || folderData.uuid === null) {
      LogUtil.info(TAG, "isFolderMoveIn folderData uuid undefined")
      folderData.uuid = 'sys_def_unClassified_uuid';
    }
    LogUtil.info(TAG, "isFolderMoveIn folderDataUuid " + folderData.uuid)
    return (folderData.uuid == SysDefFolderUuid.UnClassified || folderData.folder_type == FolderType.CusDef)
  }

  /**
  * Get folder text
  *
  * @param folderData
  * @return string | Resource - folder text
  */
  getFolderText(folderData: FolderData): string | Resource {
    if (folderData === undefined || folderData === null) {
      LogUtil.info(TAG, "folderData undefined")
      return ''
    }
    if (folderData.uuid === undefined || folderData.uuid === null) {
      LogUtil.info(TAG, "folderData uuid undefined")
      folderData.uuid = 'sys_def_unClassified_uuid';
    }
    LogUtil.info(TAG, "folderData.uuid " + folderData.uuid + " folderData.folder_type " + folderData.folder_type)
    return folderData.folder_type == FolderType.CusDef ? folderData.name : folderTextMap[folderData.uuid]
  }

  /**
  * Get Note Count
  *
  * @param noteDataArray
  * @param folderUuid
  * @return number - Note Count
  */
  getNoteCount(noteDataArray: NoteData[], folderUuid: string): number {
    let count = 0;
    const folderTextMap = {
      "sys_def_allNotes_uuid": (noteData) => {
          noteData.is_deleted == Delete.No ? ++count : count
      },
      "sys_def_recentDeletes_uuid": (noteData) => {
          noteData.is_deleted == Delete.Yes ? ++count : count
      },
      "sys_def_myFavorites_uuid": (noteData) => {
          noteData.is_favorite == Favorite.Yes && noteData.is_deleted == Delete.No ? ++count : count
      },
      "sys_def_other_uuid": (noteData) => {
          noteData.folder_uuid == folderUuid && noteData.is_deleted == Delete.No ? ++count : count
      },
    }
    if (folderUuid == SysDefFolderUuid.AllNotes || folderUuid == SysDefFolderUuid.RecentDeletes || folderUuid == SysDefFolderUuid.MyFavorites) {
      noteDataArray.forEach(folderTextMap[folderUuid])
    } else {
      noteDataArray.forEach(folderTextMap["sys_def_other_uuid"])
    }
    LogUtil.info(TAG, "folderUuid " + folderUuid + " count " + count.toString())
    return count;
  }

  /**
  * Get common FolderData
  *
  * @param folderDataArray - Folder data list
  * @param selectedNoteArray - Selected note data list
  * @return FolderData - return folder when note data list belong to the same folder, else return null
  */
  getCommonFolder(folderDataArray: FolderData[], selectedNoteArray: NoteData[]): FolderData {
    if (selectedNoteArray.length == 0) {
      return null
    }
    let folderData: FolderData = this.getFolderData(folderDataArray, selectedNoteArray[0].folder_uuid)
    let currentFolderData = null
    selectedNoteArray.forEach((noteItem) => {
      if (folderData != this.getFolderData(folderDataArray, noteItem.folder_uuid)) {
        currentFolderData = this.getFolderData(folderDataArray, noteItem.folder_uuid).name
      }
    })
    return (currentFolderData == null) ? folderData : null
  }

  /**
  * folder name duplicate detection
  *
  * @param inputStr - Folder name input
  * @param folderDataArray - folder already exist
  * @return Promise<boolean> - if input name exist, return true, else return false
  */
  async duplicateDetection(inputStr: string, folderDataArray: FolderData[]): Promise<boolean> {
    for (let index = 0; index < folderDataArray.length; index++) {
      if (folderDataArray[index].folder_type == FolderType.CusDef && folderDataArray[index].name == inputStr) {
        return true
      } else {
        let temp = GlobalResourceManager.getStringByResource(this.getFolderText(folderDataArray[index]))
        temp.then(result => {
          if (result == inputStr) {
            return true
          }
        })
      }
    }
    return false
  }
}

let folderUtil = new FolderUtil()

export default folderUtil as FolderUtil