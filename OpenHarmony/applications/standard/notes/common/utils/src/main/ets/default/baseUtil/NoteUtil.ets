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

import {unSelectedNoteBgColorMap, selectedNoteBgColorMap} from '../model/NoteBaseData'
import FolderData from '../model/databaseModel/FolderData'
import NoteData from '../model/databaseModel/NoteData'
import {SysDefFolderUuid, FolderType, Favorite, Delete, TableName, NoteTableColumn,
} from '../model/databaseModel/EnumData'
import StyleConstants from '../constants/StyleConstants'
import {LogUtil} from './LogUtil'
import FolderUtil from './FolderUtil'
import RdbStoreUtil from './RdbStoreUtil'

const TAG = "NoteUtil"

export class NoteUtil {
  /**
  * Set Note Checked status
  *
  * @param checkedNoteArray - Checked status Note list
  * @param noteItem - note
  */
  setNoteChecked(checkedNoteArray: NoteData[], noteItem: NoteData) {
    LogUtil.info(TAG, "setNoteChecked")
    checkedNoteArray.push(noteItem)
    AppStorage.Set('CheckedNoteArray',checkedNoteArray)
  }

  /**
  * unset Note with Checked status
  *
  * @param checkedNoteArray - Checked status Note list
  * @param noteItem - note
  */
  unsetNoteChecked(checkedNoteArray: NoteData[], noteItem: NoteData) {
    let index = checkedNoteArray.findIndex((note) => {
      return note == noteItem
    })
    LogUtil.info(TAG, "index " + index.toString() + noteItem.uuid)
    index == -1 ? null : checkedNoteArray.splice(index, 1)
    AppStorage.Set('CheckedNoteArray',checkedNoteArray)
  }

  /**
  * Is Note Checked status
  *
  * @param checkedNoteArray - Checked status Note list
  * @param noteItem - note
  * @return boolean - Checked: true, unchecked: false
  */
  isNoteChecked(checkedNoteArray: NoteData[], noteItem: NoteData): boolean {
    for (let i = 0; i < checkedNoteArray.length; i++) {
      LogUtil.info(TAG, "index " + checkedNoteArray[i].uuid + " noteItem uuid: " + noteItem.uuid)
    }
    let index = checkedNoteArray.findIndex((note) => {
      return note.uuid == noteItem.uuid
    })
    LogUtil.info(TAG, "index " + index.toString() + " noteItem uuid: " + noteItem.uuid)
    return index != -1
  }

  /**
  * Set all notes Checked status
  *
  * @param checkedNoteArray - Checked status Note list
  * @param selectedNoteArray - note array
  */
  setAllNotesChecked(checkedNoteArray: NoteData[], noteArray: NoteData[]) {
    LogUtil.info(TAG, "setAllNotesChecked")
    this.unsetAllNotesChecked(checkedNoteArray)
    checkedNoteArray.push(...noteArray)
    AppStorage.Set('CheckedNoteArray', checkedNoteArray)
  }

  /**
  * unset all Notes with Checked status
  *
  * @param CheckedNoteArray - Checked status Note list
  */
  unsetAllNotesChecked(checkedNoteArray: NoteData[]) {
    LogUtil.info(TAG, "unsetAllNotesChecked")
    checkedNoteArray.splice(0, checkedNoteArray.length)
    AppStorage.Set('CheckedNoteArray', checkedNoteArray)
  }

  /**
  * Get Note Count in folder
  *
  * @param noteDataArray
  * @param folderData
  * @return number - Note Count
  */
  getNoteCount(noteDataArray: NoteData[], folderData: FolderData): number {
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
          noteData.folder_uuid == folderData.uuid && noteData.is_deleted == Delete.No ? ++count : count
      }
    }
    if (folderData.uuid == SysDefFolderUuid.AllNotes || folderData.folder_type == FolderType.FeatureDef) {
      noteDataArray.forEach(folderTextMap[folderData.uuid])
    } else {
      noteDataArray.forEach(folderTextMap["sys_def_other_uuid"])
    }
    LogUtil.info(TAG, "folderUuid " + folderData.uuid + " count " + count.toString())
    return count;
  }

  /**
  * Get note background color
  *
  * @param folderDataArray - Folder data list
  * @param uuid - note's folder_uuid
  * @param selectFolderUuid - selected folder's uuid
  * @param isSelected - is selected or not
  * @return Resource | string - color value
  */
  getNoteBgColor(folderDataArray: FolderData[], uuid: string, selectFolderUuid: string, isSelected: boolean): Resource | string {
    let folderData: FolderData = FolderUtil.getFolderData(folderDataArray, uuid)
    if (folderData == undefined || (selectFolderUuid != SysDefFolderUuid.AllNotes && !isSelected)) {
      LogUtil.info(TAG, "NoteBgColor is ffffff")
      return $r("app.color.color_ffffff")
    }
    if (folderData.color == "#ffffff") {
      return "#FFEBE1"
    }
    if (folderData.color == "#e84026") {
      return "#ffe0b2ac"
    }
    LogUtil.info(TAG, "isSelected " + isSelected.toString() + ", folderData.color: " + folderData.color.toString())
    return isSelected ? selectedNoteBgColorMap[folderData.color] : unSelectedNoteBgColorMap[folderData.color]
  }

  /**
  * Get verticalBar background color
  *
  * @param folderDataArray - Folder data list
  * @param uuid - note's folder_uuid
  * @return Resource | string - color value
  */
  getVerticalBarBgColor(folderDataArray: FolderData[], uuid: string): Resource | string {
    let folderData: FolderData = FolderUtil.getFolderData(folderDataArray, uuid)
    if (folderData == undefined) {
      LogUtil.info(TAG, "NoteBgColor is ffffff")
      return $r("app.color.color_ffffff")
    }
    LogUtil.info(TAG, "isSelected " + folderData.color.toString() + ", folderData.color: " + folderData.color.toString())
    if (folderData.color == "#ffffff") {
      return "#ff9516"
    }
    return folderData.color
  }

  /**
  * Automatically delete notes in the deleted folder more than 30 days
  *
  * @param allNoteDataArray
  */
  autoDeleteNote(allNoteDataArray: NoteData[]) {
    for (let index = 0; index < allNoteDataArray.length; ) {
      if (allNoteDataArray[index].is_deleted == Delete.Yes && new Date().getTime() - allNoteDataArray[index].deleted_time > StyleConstants.DELETE_DEADLINE) {
        LogUtil.info(TAG, "Delete Note, uuid " + allNoteDataArray[index].uuid + " delete time " + allNoteDataArray[index].deleted_time)
        // delete note from db
        let predicates_note = RdbStoreUtil.getRdbPredicates(TableName.NoteTable)
        predicates_note.equalTo(NoteTableColumn.Uuid, allNoteDataArray[index].uuid)
        RdbStoreUtil.delete(predicates_note, null)
        allNoteDataArray.splice(index, 1);
      }
      index++
    }
  }

  /**
  * Get Note Count
  *
  * @param allNoteDataArray
  * @param folderUuid
  * @return NoteData[] - return Note in folder
  */
  getNoteDataArray(allNoteDataArray: NoteData[], folderUuid: string): NoteData[] {
    LogUtil.info(TAG, "folderUuid " + folderUuid)
    this.autoDeleteNote(allNoteDataArray)
    let noteDataArray: NoteData[] = [];
    let func = (noteData) => noteDataArray.push(noteData)
    const folderTextMap = {
      "sys_def_allNotes_uuid": (noteData) => {
          noteData.is_deleted == Delete.No ? func(noteData) : null
      },
      "sys_def_recentDeletes_uuid": (noteData) => {
          noteData.is_deleted == Delete.Yes ? func(noteData) : null
      },
      "sys_def_myFavorites_uuid": (noteData) => {
          noteData.is_favorite == Favorite.Yes && noteData.is_deleted == Delete.No ? func(noteData) : null
      },
      "sys_def_other_uuid": (noteData) => {
          noteData.folder_uuid == folderUuid && noteData.is_deleted == Delete.No ? func(noteData) : null
      },
    }
    if (folderUuid == SysDefFolderUuid.AllNotes || folderUuid == SysDefFolderUuid.RecentDeletes || folderUuid == SysDefFolderUuid.MyFavorites) {
      allNoteDataArray.forEach(folderTextMap[folderUuid])
    } else {
      allNoteDataArray.forEach(folderTextMap["sys_def_other_uuid"])
    }
    // Sort priority: 1、Top or not 2、created time
    noteDataArray.sort((noteItemLeft: NoteData, noteItemRight: NoteData) => {
      if (noteItemRight.is_top != noteItemLeft.is_top) {
        return noteItemRight.is_top - noteItemLeft.is_top
      }
      return noteItemRight.modified_time - noteItemLeft.modified_time
    })
    LogUtil.info(TAG, "noteDataArray size " + noteDataArray.length.toString())
    return noteDataArray
  }

  /**
  * Get First Note in note array
  *
  * @param allNoteDataArray
  * @param folderUuid
  * @return NoteData
  */
  getFirstNoteData(allNoteDataArray: NoteData[], folderUuid: string): NoteData {
    let noteDataArray: NoteData[] = this.getNoteDataArray(allNoteDataArray, folderUuid);
    LogUtil.info(TAG, "get noteDataArray size " + noteDataArray.length.toString())
    if (noteDataArray.length == 0) {
      LogUtil.info(TAG, "get noteDataArray empty")
      return undefined;
    }
    return noteDataArray == undefined ? null : noteDataArray[0]
  }

  /**
  * Remove NoteData
  *
  * @param allNoteDataArray
  * @param noteUuid
  */
  removeNoteData(allNoteDataArray: NoteData[], noteUuid: string) {
    let index = allNoteDataArray.findIndex((note) => {
      return note.uuid == noteUuid
    })
    LogUtil.info(TAG, "index " + index.toString() + " uuid " + noteUuid)
    index == -1 ? null : allNoteDataArray.splice(index, 1)
  }

  deleteEmptyNote(selectedNoteData: NoteData, AllNoteArray: NoteData[], controllerShow: WebController): boolean {
    if (selectedNoteData.title == "标题" && selectedNoteData.content_text == "") {
      // delete note from db
      noteUtil.removeNoteData(AllNoteArray, selectedNoteData.uuid)
      LogUtil.info(TAG, "delete note:" + selectedNoteData.uuid)
      let predicates_note = RdbStoreUtil.getRdbPredicates(TableName.NoteTable)
      predicates_note.equalTo(NoteTableColumn.Uuid, selectedNoteData.uuid)
      RdbStoreUtil.delete(predicates_note, null)
      LogUtil.info(TAG, "delete note success:" + selectedNoteData.uuid)
      return true
    }
    return false
  }

  refreshAll() {
    let isRefresh = AppStorage.Get('isUpdate')
    AppStorage.Set('isUpdate',!isRefresh)
  }
}

let noteUtil = new NoteUtil()

export default noteUtil as NoteUtil