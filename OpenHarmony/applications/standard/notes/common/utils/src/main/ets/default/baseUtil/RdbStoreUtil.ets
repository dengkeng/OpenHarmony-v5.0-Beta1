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

import fileio from '@ohos.fileio'
import { LogUtil } from './LogUtil'
import FolderUtil from './FolderUtil'
import NoteUtil from './NoteUtil'
import SysDefData from '../model/databaseModel/SysDefData'
import FolderData from '../model/databaseModel/FolderData'
import NoteData from '../model/databaseModel/NoteData'
import {
  TableSql,
  TableName,
  FolderTableColumn,
  NoteTableColumn,
  SysDefFolderUuid
} from '../model/databaseModel/EnumData'
import relationalStore from '@ohos.data.relationalStore'
import util from '@ohos.util';

const TAG = "RdbStoreUtil"

const FileMaxSize: number = 20 * 1024 * 1024

/**
 * db instance
 */

export default {
  /**
   * create db and table
   */
  createRdbStore(context) {
    try {
      relationalStore.getRdbStore(context, SysDefData.dbInfo.db_name)
        .then(async (store) => {
          // add sys-def folder and note to AppStorage
          let folderDataArray = []
          let sysDefFolderArray = [SysDefData.sys_def_allNotes, SysDefData.sys_def_unClassified,
          SysDefData.sys_def_myFavorites, SysDefData.sys_def_recentDeletes,
          SysDefData.sys_def_personal, SysDefData.sys_def_life, SysDefData.sys_def_work]
          sysDefFolderArray.forEach((sysDefFolder) => {
            let folderData = new FolderData(sysDefFolder.id, sysDefFolder.name, sysDefFolder.uuid, sysDefFolder.color,
              sysDefFolder.folder_type, sysDefFolder.is_deleted, sysDefFolder.created_time,
              sysDefFolder.modified_time)
            folderDataArray.push(folderData)
          })
          LogUtil.info(TAG, "folderDataArray[sysdef] : " + folderDataArray.length)

          let noteDataArray = []
          let sysDefNoteArray = [SysDefData.sys_def_note1, SysDefData.sys_def_note2,
          SysDefData.sys_def_note3, SysDefData.sys_def_note4]
          sysDefNoteArray.forEach((sysDefNote) => {
            let noteData = new NoteData(sysDefNote.id, sysDefNote.title, sysDefNote.uuid, sysDefNote.folder_uuid, sysDefNote.content_text,
              sysDefNote.content_img, sysDefNote.note_type, sysDefNote.is_top, sysDefNote.is_favorite,
              sysDefNote.is_deleted, sysDefNote.created_time, sysDefNote.modified_time, sysDefNote.deleted_time, sysDefNote.slider_value)
            noteDataArray.push(noteData)
          })
          LogUtil.info(TAG, "noteDataArray[sysdef] : " + noteDataArray.length)

          AppStorage.SetOrCreate('AllFolderArray', folderDataArray)
          AppStorage.SetOrCreate('AllNoteArray', noteDataArray)
          LogUtil.info(TAG, "AppStorage[sysdef] set AllFolderArray and AllNoteArray success")

          // save continue data
          let isContinue = AppStorage.Get<boolean>('IsContinue');
          LogUtil.info(TAG, "createRdbStore, isContinue is " + isContinue)
          if (isContinue) {
            let continueNote: string = AppStorage.Get('ContinueNote')
            let continueSection = AppStorage.Get('ContinueSection')
            let noteObj = JSON.parse(continueNote)
            let noteData = new NoteData(noteObj.uuid, noteObj.title, noteObj.uuid, noteObj.folder_uuid,
              noteObj.content_text, noteObj.content_img, noteObj.note_type, noteObj.is_top, noteObj.is_favorite,
              noteObj.is_deleted, noteObj.created_time, noteObj.modified_time, noteObj.deleted_time, noteObj.slider_value)

            // save img to FileDir
            LogUtil.info(TAG, "createRdbStore, save img to FileDir")
            let imgNameArray = this.getImgNameFromHtml(noteData)
            imgNameArray.forEach((imgName: string) => {
              this.writeToFileDir(imgName)
            })

            // if not exit this note
            let exist = false
            let folderUuid = ""
            for (let note of noteDataArray) {
              if (noteData.created_time == note.created_time) {
                exist = true
                folderUuid = note.folder_uuid
                break
              }
            }
            LogUtil.info(TAG, "createRdbStore, exist : " + exist)
            if (!exist) {
              // 迁移过来的笔记在本地不存在，则保存在未分类文件夹
              noteData.folder_uuid = SysDefFolderUuid.UnClassified
              noteDataArray.push(noteData)
              AppStorage.SetOrCreate('AllNoteArray', noteDataArray)
              this.insert(TableName.NoteTable, noteData.toNoteObject(), null)
              AppStorage.SetOrCreate('Folder', FolderUtil.getFolderData(folderDataArray, SysDefFolderUuid.UnClassified))
            } else {
              // 迁移过来的笔记在本地存在，则进行修改
              for (let i = 0; i < noteDataArray.length; i++) {
                if (noteData.created_time == noteDataArray[i].created_time) {
                  noteDataArray[i] = noteData
                  LogUtil.info(TAG, "createRdbStore, update noteData in noteDataArray success")
                  break
                }
              }
              let predicates_note = this.getRdbPredicates(TableName.NoteTable)
              predicates_note.equalTo(NoteTableColumn.CreatedTime, noteData.created_time)
              this.update(noteData.toNoteObject(), predicates_note, null)
              AppStorage.SetOrCreate('Folder', FolderUtil.getFolderData(folderDataArray, folderUuid))
            }
            AppStorage.SetOrCreate('Note', noteData)
            AppStorage.SetOrCreate<string>('ContinueNote', JSON.stringify(noteData.toNoteObject()))
            AppStorage.SetOrCreate('Section', continueSection)
            AppStorage.SetOrCreate<NoteData>('NewNote', noteData)
          } else {
            LogUtil.info(TAG, "createRdbStore, IsContinue false")
            AppStorage.SetOrCreate('Folder', AppStorage.Get('AllFolderArray')[0])
            let note = NoteUtil.getFirstNoteData(AppStorage.Get('AllNoteArray'), SysDefFolderUuid.AllNotes)
            AppStorage.SetOrCreate('Note', note)
            if (note) {
              AppStorage.SetOrCreate<string>('ContinueNote', JSON.stringify(note.toNoteObject()))
            }
            AppStorage.SetOrCreate('Section', 3)
          }
          AppStorage.SetOrCreate('DBQueryFinished', 1)
          LogUtil.info(TAG, "createRdbStore, set DBQueryFinished 1")
          LogUtil.info(TAG, "createRdbStore, store is " + store)
          globalThis.rdbStore = store
          // create table
          await globalThis.rdbStore.executeSql(TableSql.FolderTableSQL, null)
          await globalThis.rdbStore.executeSql(TableSql.NoteTableSQL, null)
          await globalThis.rdbStore.executeSql(TableSql.AttachmentTableSQL, null)
          await globalThis.rdbStore.executeSql(TableSql.FormTableSQL, null)
          LogUtil.info(TAG, "create table success")
          // insert system defined folder
          await globalThis.rdbStore.insert(TableName.FolderTable, SysDefData.sys_def_allNotes)
          await globalThis.rdbStore.insert(TableName.FolderTable, SysDefData.sys_def_unClassified)
          await globalThis.rdbStore.insert(TableName.FolderTable, SysDefData.sys_def_myFavorites)
          await globalThis.rdbStore.insert(TableName.FolderTable, SysDefData.sys_def_recentDeletes)
          await globalThis.rdbStore.insert(TableName.FolderTable, SysDefData.sys_def_personal)
          await globalThis.rdbStore.insert(TableName.FolderTable, SysDefData.sys_def_life)
          await globalThis.rdbStore.insert(TableName.FolderTable, SysDefData.sys_def_work)
          LogUtil.info(TAG, "insert system defined folder success")
          // insert system defined note and attachment
          await globalThis.rdbStore.insert(TableName.NoteTable, SysDefData.sys_def_note1)
          await globalThis.rdbStore.insert(TableName.NoteTable, SysDefData.sys_def_note2)
          await globalThis.rdbStore.insert(TableName.NoteTable, SysDefData.sys_def_note3)
          await globalThis.rdbStore.insert(TableName.NoteTable, SysDefData.sys_def_note4)
          LogUtil.info(TAG, "insert system defined note and attachment success")
        })
    } catch (err) {
      LogUtil.warn(TAG, "createRdbStore, error : " + err)
    }
  },

  /**
   * query folders and notes from the database, then save them to the AppStorage.
   */
  initAppStorage(context) {
    let folderDataArray = []
    let noteDataArray = []
    try {
      relationalStore.getRdbStore(context, SysDefData.dbInfo.db_name)
        .then(async (store) => {
          LogUtil.info(TAG, "initAppStorage, store is " + store)
          globalThis.rdbStore = store
          // query folder
          let columns_folder = []
          let predicates_folder = new relationalStore.RdbPredicates(TableName.FolderTable)
          let resultSet_folder = await globalThis.rdbStore.query(predicates_folder, columns_folder)
          while (resultSet_folder.goToNextRow()) {
            let id = resultSet_folder.getLong(resultSet_folder.getColumnIndex(FolderTableColumn.Id))
            let name = resultSet_folder.getString(resultSet_folder.getColumnIndex(FolderTableColumn.Name))
            let uuid = resultSet_folder.getString(resultSet_folder.getColumnIndex(FolderTableColumn.Uuid))
            let color = resultSet_folder.getString(resultSet_folder.getColumnIndex(FolderTableColumn.Color))
            let folder_type = resultSet_folder.getLong(resultSet_folder.getColumnIndex(FolderTableColumn.FolderType))
            let is_deleted = resultSet_folder.getLong(resultSet_folder.getColumnIndex(FolderTableColumn.IsDeleted))
            let created_time = resultSet_folder.getLong(resultSet_folder.getColumnIndex(FolderTableColumn.CreatedTime))
            let modified_time = resultSet_folder.getLong(resultSet_folder.getColumnIndex(FolderTableColumn.ModifiedTime))
            let folderData = new FolderData(id, name, uuid, color, folder_type, is_deleted, created_time, modified_time)
            folderDataArray.push(folderData)
          }
          resultSet_folder.close();
          LogUtil.info(TAG, "folderDataArray[query] : " + folderDataArray.length)
          // query note
          let columns_note = []
          let predicates_note = new relationalStore.RdbPredicates(TableName.NoteTable)
          let resultSet_note = await globalThis.rdbStore.query(predicates_note, columns_note)
          while (resultSet_note.goToNextRow()) {
            let id = resultSet_note.getLong(resultSet_note.getColumnIndex(NoteTableColumn.Id))
            let title = resultSet_note.getString(resultSet_note.getColumnIndex(NoteTableColumn.Title))
            let uuid = resultSet_note.getString(resultSet_note.getColumnIndex(NoteTableColumn.Uuid))
            let folder_uuid = resultSet_note.getString(resultSet_note.getColumnIndex(NoteTableColumn.FolderUuid))
            // 暂时规避备忘录二次打开白屏问题，后续数据库解决
            let content_text = '';
            let content_img = '';
            try {
              content_text = resultSet_note.getString(resultSet_note.getColumnIndex(NoteTableColumn.ContentText))
              content_img = resultSet_note.getString(resultSet_note.getColumnIndex(NoteTableColumn.ContentImg))
            } catch (err) {
              LogUtil.error(TAG, "initAppStorage, content_img = error : " + err)
            }
            let noteType = resultSet_note.getLong(resultSet_note.getColumnIndex(NoteTableColumn.NoteType))
            let is_top = resultSet_note.getLong(resultSet_note.getColumnIndex(NoteTableColumn.IsTop))
            let is_favorite = resultSet_note.getLong(resultSet_note.getColumnIndex(NoteTableColumn.IsFavorite))
            let is_deleted = resultSet_note.getLong(resultSet_note.getColumnIndex(NoteTableColumn.IsDeleted))
            let created_time = resultSet_note.getLong(resultSet_note.getColumnIndex(NoteTableColumn.CreatedTime))
            let modified_time = resultSet_note.getLong(resultSet_note.getColumnIndex(NoteTableColumn.ModifiedTime))
            let deleted_time = resultSet_note.getLong(resultSet_note.getColumnIndex(NoteTableColumn.DeletedTime))
            let slider_value = resultSet_note.getLong(resultSet_note.getColumnIndex(NoteTableColumn.SliderValue))
            let noteData = new NoteData(id, title, uuid, folder_uuid, content_text, content_img, noteType, is_top, is_favorite, is_deleted, created_time, modified_time, deleted_time, slider_value)
            noteDataArray.push(noteData)
          }
          resultSet_note.close();
          LogUtil.info(TAG, "noteDataArray[query] : " + noteDataArray.length)
          if (folderDataArray === null || folderDataArray === undefined || folderDataArray.length === 0) {
            LogUtil.info(TAG, "folderDataArray is null")
            let sysDefFolderArray = [SysDefData.sys_def_allNotes, SysDefData.sys_def_unClassified,
            SysDefData.sys_def_myFavorites, SysDefData.sys_def_recentDeletes,
            SysDefData.sys_def_personal, SysDefData.sys_def_life, SysDefData.sys_def_work]
            sysDefFolderArray.forEach((sysDefFolder) => {
              let folderData = new FolderData(sysDefFolder.id, sysDefFolder.name, sysDefFolder.uuid, sysDefFolder.color,
                sysDefFolder.folder_type, sysDefFolder.is_deleted, sysDefFolder.created_time,
                sysDefFolder.modified_time)
              folderDataArray.push(folderData)
            })
            LogUtil.info(TAG, "folderDataArray[query] : " + folderDataArray.length)
          }
          AppStorage.SetOrCreate('AllFolderArray', folderDataArray)
          AppStorage.SetOrCreate('AllNoteArray', noteDataArray)
          LogUtil.info(TAG, "AppStorage[query] set AllFolderArray and AllNoteArray success")

          // save continue data
          let isContinue = AppStorage.Get<boolean>('IsContinue');
          LogUtil.info(TAG, "initAppStorage, isContinue is " + isContinue)
          if (isContinue) {
            let continueNote: string = AppStorage.Get('ContinueNote')
            let continueSection = AppStorage.Get('ContinueSection')

            let noteObj = JSON.parse(continueNote)
            let noteData = new NoteData(noteObj.uuid, noteObj.title, noteObj.uuid, noteObj.folder_uuid,
              noteObj.content_text, noteObj.content_img, noteObj.note_type, noteObj.is_top, noteObj.is_favorite,
              noteObj.is_deleted, noteObj.created_time, noteObj.modified_time, noteObj.deleted_time, noteObj.slider_value)

            // save img to FileDir
            LogUtil.info(TAG, "initAppStorage, save img to FileDir")
            let imgNameArray = this.getImgNameFromHtml(noteData)
            imgNameArray.forEach((imgName: string) => {
              this.writeToFileDir(imgName)
            })

            // if not exit this note
            let exist = false
            let folderUuid = ""
            for (let note of noteDataArray) {
              if (noteData.created_time == note.created_time) {
                exist = true
                folderUuid = note.folder_uuid
                break
              }
            }
            LogUtil.info(TAG, "initAppStorage, exist : " + exist)
            if (!exist) {
              // 迁移过来的笔记在本地不存在，则保存在未分类文件夹
              noteData.folder_uuid = SysDefFolderUuid.UnClassified
              noteDataArray.push(noteData)
              AppStorage.SetOrCreate('AllNoteArray', noteDataArray)
              this.insert(TableName.NoteTable, noteData.toNoteObject(), null)
              AppStorage.SetOrCreate('Folder', FolderUtil.getFolderData(folderDataArray, SysDefFolderUuid.UnClassified))
            } else {
              // 迁移过来的笔记在本地存在，则进行修改
              for (let i = 0; i < noteDataArray.length; i++) {
                if (noteData.created_time == noteDataArray[i].created_time) {
                  noteDataArray[i] = noteData
                  LogUtil.info(TAG, "initAppStorage, update noteData in noteDataArray success")
                  break
                }
              }
              let predicates_note = this.getRdbPredicates(TableName.NoteTable)
              predicates_note.equalTo(NoteTableColumn.CreatedTime, noteData.created_time)
              this.update(noteData.toNoteObject(), predicates_note, null)
              AppStorage.SetOrCreate('Folder', FolderUtil.getFolderData(folderDataArray, folderUuid))
            }
            AppStorage.SetOrCreate('Note', noteData)
            AppStorage.SetOrCreate<string>('ContinueNote', JSON.stringify(noteData.toNoteObject()))
            AppStorage.SetOrCreate('Section', continueSection)
            AppStorage.SetOrCreate<NoteData>('NewNote', noteData)
          } else {
            LogUtil.info(TAG, "initAppStorage, IsContinue false")
            AppStorage.SetOrCreate('Folder', AppStorage.Get('AllFolderArray')[0])
            let note = NoteUtil.getFirstNoteData(AppStorage.Get('AllNoteArray'), SysDefFolderUuid.AllNotes)
            AppStorage.SetOrCreate('Note', note)
            if (note) {
              AppStorage.SetOrCreate<string>('ContinueNote', JSON.stringify(note.toNoteObject()))
            }
            AppStorage.SetOrCreate('Section', 3)
          }
          AppStorage.SetOrCreate('DBQueryFinished', 1)
          LogUtil.info(TAG, "initAppStorage, set DBQueryFinished 1")
        })
    } catch (err) {
      LogUtil.error(TAG, "initAppStorage, error : " + err)
    }
  },

  getImgNameFromHtml(noteData: NoteData): any {
    let newModuleName = "file://" + globalThis.noteContext.filesDir
    let imgNameArray = []
    if (noteData.content_text == undefined || noteData.content_text == null || noteData.content_text == "") {
      LogUtil.info(TAG, "noteData.content_text is null or undefined")
      return imgNameArray
    }
    let base64regex = /^([0-9a-zA-Z+/]{4})*(([0-9a-zA-Z+/]{2}==)|([0-9a-zA-Z+/]{3}=))?$/
    let html
    if (base64regex.test(noteData.content_text)) {
      let base64 = new util.Base64Helper
      html = base64.decodeSync(noteData.content_text).toString()
    } else {
      html = noteData.content_text
    }
    if (html == undefined || html == null || html == "") {
      return imgNameArray
    }
    let imgReg = /<img[^>]+>/g
    let srcReg = /src=[\'\"]?([^\'\"]*)[\'\"]?/i
    let imgArray = html.match(imgReg)
    if (imgArray != null) {
      let hasFirstImg: boolean = false
      for (let i = 0; i < imgArray.length; i++) {
        let src = imgArray[i].match(srcReg)
        if (src != null && src.length > 1) {
          LogUtil.info(TAG, "getImgNameFromHtml, src[1] : " + src[1])
          let lastIndex = src[1].lastIndexOf('/')
          if (lastIndex != -1) {
            let oldModuleName = src[1].substring(0, lastIndex)
            let imgName = src[1].substring(lastIndex + 1)
            noteData.content_text = noteData.content_text.replace(oldModuleName, newModuleName)
            if (!hasFirstImg) {
              noteData.content_img = newModuleName + "/" + imgName
              hasFirstImg = true
            }
            imgNameArray.push(imgName)
          }
        }
      }
    }
    return imgNameArray
  },

  writeToFileDir(fileName: string) {
    LogUtil.info(TAG, "writeToFileDir fileName : " + fileName)

    let desPath = globalThis.noteContext.filesDir + "/" + fileName
    LogUtil.info(TAG, "desPath : " + desPath)
    try {
      fileio.accessSync(desPath)
      LogUtil.info(TAG, "desPath has existed, return")
      return
    } catch (err) {
      LogUtil.warn(TAG, "desPath has not existed, need to write")
    }
    let srcPath
    let size
    try {
      srcPath = globalThis.noteContext.distributedFilesDir + "/" + fileName
      LogUtil.info(TAG, "srcPath : " + srcPath)
      size = fileio.statSync(srcPath).size
      LogUtil.info(TAG, "srcPath size : " + size)
      if (size > FileMaxSize) {
        LogUtil.warn(TAG, "srcPath size more then FileMaxSize, return")
        return
      }
    }
    catch (err) {
      LogUtil.warn(TAG, "desPath has not existed, need to write two")
      return
    }


    let srcFd
    try {
      srcFd = fileio.openSync(srcPath, 0o0)
      LogUtil.info(TAG, "open srcPath success : " + srcFd)
    } catch (err) {
      LogUtil.warn(TAG, "open srcPath failed : " + err)
      return
    }

    let desFd
    try {
      desFd = fileio.openSync(desPath, 0o2 | 0o100, 0o400 | 0o200 | 0o040 | 0o020)
      LogUtil.info(TAG, "open desPath success : " + srcFd)
    } catch (err) {
      LogUtil.warn(TAG, "open desPath failed : " + err)
      return
    }

    let buf = new ArrayBuffer(size)
    try {
      let readNum = fileio.readSync(srcFd, buf)
      LogUtil.info(TAG, "readNum : " + readNum)
      let writeNum = fileio.writeSync(desFd, buf)
      LogUtil.info(TAG, "writeNum : " + writeNum)
    } catch (err) {
      LogUtil.warn(TAG, "read or write error : " + err)
    }
  },

  /**
   * insert
   * @param tableName
   * @param valueBucket
   * @param callback
   */
  insert(tableName, valueBucket, callback) {
    globalThis.rdbStore.insert(tableName, valueBucket).then((rowId) => {
      LogUtil.info(TAG, "insert success, rowId is " + rowId)
      if (callback != null) {
        callback(rowId)
      }
    }).catch((err) => {
      LogUtil.warn(TAG, "insert error : " + err)
    })
  },

  /**
   * delete
   * @param predicates
   * @param callback
   */
  delete(predicates, callback) {
    globalThis.rdbStore.delete(predicates).then((affectedRowCount) => {
      LogUtil.info(TAG, "delete success, affectedRowCount is " + affectedRowCount)
      if (callback != null) {
        callback(affectedRowCount)
      }
    }).catch((err) => {
      LogUtil.warn(TAG, "delete error : " + err)
    })
  },

  /**
   * update
   * @param valueBucket
   * @param predicates
   * @param callback
   */
  update(valueBucket, predicates, callback) {
    if (!globalThis.rdbStore) {
      return;
    }
    globalThis.rdbStore.update(valueBucket, predicates).then((affectedRowCount) => {
      LogUtil.info(TAG, "update success, affectedRowCount is " + affectedRowCount)
      if (callback != null) {
        callback(affectedRowCount)
      }
    }).catch((err) => {
      LogUtil.warn(TAG, "update error : " + err)
    })
  },

  /**
   * query
   * @param columns
   * @param predicates
   * @param callback
   */
  query(columns, predicates, callback) {
    globalThis.rdbStore.query(predicates, columns).then((resultSet) => {
      LogUtil.info(TAG, "query success, row count : " + resultSet.rowCount)
      if (callback != null) {
        callback(resultSet)
      }
    }).catch((err) => {
      LogUtil.warn(TAG, "query error : " + err)
    })
  },

  /**
   * get RdbPredicates by table name
   * @param tableName
   */
  getRdbPredicates(tableName) {
    return new relationalStore.RdbPredicates(tableName)
  },

  updataNoteImage(noteData: NoteData): string {
    let content_img = ""
    let imgNameArray = this.getImgNameFromHtml(noteData)
    if (imgNameArray.length == 0) {
      return content_img
    }
    if (imgNameArray[0] == 'shuxue.png' || imgNameArray[0] == 'cake.png') {
      content_img = "/res/" + imgNameArray[0]
    } else {
      content_img = noteData.content_img
    }
    LogUtil.info(TAG, "updataNoteImage, content_img : " + content_img)
    return content_img
  }
}