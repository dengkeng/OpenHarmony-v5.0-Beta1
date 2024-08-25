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

import FolderData from '@ohos/utils/src/main/ets/default/model/databaseModel/FolderData'
import NoteData from '@ohos/utils/src/main/ets/default/model/databaseModel/NoteData'
import {
  SysDefFolderUuid,
  TableName,
  FolderType,
  FolderTableColumn,
  NoteTableColumn,
  Delete,
  DeleteFileType
} from '@ohos/utils/src/main/ets/default/model/databaseModel/EnumData'
import { NewOrEditFolderDialog, DeleteDialog } from './CusDialogComp'
import RdbStoreUtil from '@ohos/utils/src/main/ets/default/baseUtil/RdbStoreUtil'
import FolderUtil from '@ohos/utils/src/main/ets/default/baseUtil/FolderUtil'
import NoteUtil from '@ohos/utils/src/main/ets/default/baseUtil/NoteUtil'
import { LogUtil } from '@ohos/utils/src/main/ets/default/baseUtil/LogUtil'

// Folder list component
@Component
export struct FolderListComp {
  @StorageLink('AllFolderArray') AllFolderArray: FolderData[] = AppStorage.Link('AllFolderArray')
  @Consume('SectionStatus') sectionStatus: number
  @Consume('ExpandStatus') expandStatus: boolean // 笔记本折叠展开状态
  @StorageLink('breakPoint') breakPoints: string = 'lg'
  controllerShow: WebviewController
  TAG = "FolderListComp"
  @Consume('AsideWidth') asideWidth: number

  build() {
    Flex({ direction: FlexDirection.Column, justifyContent: FlexAlign.SpaceBetween }) {
      Column() {
        Column() {
          Image($r("app.media.suojin"))
            .height(24)
            .width(24)
            .responseRegion({ x: -15.0, y: -15.0, width: 54, height: 54 })
            .onClick(() => {
              if (this.breakPoints == 'sm' || this.breakPoints == 'md') {
                animateTo({ duration: 200 }, () => {
                  this.expandStatus = !this.expandStatus
                })
              } else {
                this.asideWidth = 0
                this.sectionStatus = (this.sectionStatus == 3 ? 2 : 3)
                // save continue data
                AppStorage.SetOrCreate<number>('ContinueSection', this.sectionStatus)
                LogUtil.info(this.TAG, "FolderListComp, set continue section success")
              }
            })
        }
        .alignItems(HorizontalAlign.Start)
        .width("100%")
        .margin({ top: 28 })
        .padding({ left: 24 })
        .flexGrow(1)

        NoteAndCreateComp()
        // center
        List() {
          ForEach(this.AllFolderArray, (folderItem: FolderData) => {
            ListItem() {
              if (!FolderUtil.isBottomFixedFolder(folderItem)) {
                FolderItemComp({ folderItem: folderItem, controllerShow: this.controllerShow })
              }
            }
          }, folderItem => folderItem.name.toString())
        }
        .width('100%')
        .height(500)
        .margin({ bottom: 120 })
        .padding({ left: 12, right: 12 })
        .flexGrow(1)
      }


      Column() {
        FolderItemComp({
          folderItem: FolderUtil.getFolderData(AppStorage.Get('AllFolderArray'), SysDefFolderUuid.MyFavorites),
          controllerShow: this.controllerShow
        })
        FolderItemComp({
          folderItem: FolderUtil.getFolderData(AppStorage.Get('AllFolderArray'), SysDefFolderUuid.RecentDeletes),
          controllerShow: this.controllerShow
        })
      }
      .backgroundColor($r("app.color.folderlist_bgcolor_f1f3f5"))
      .flexGrow(0)
      .width("100%")
      .padding({ left: 12, right: 12, bottom: 24 })
    }
    .height("100%")
    .backgroundColor($r('app.color.folder_color_d6d6d6'))
    .backgroundBlurStyle(BlurStyle.Thick)
  }

  aboutToAppear(): void {
    LogUtil.info(this.TAG, "aboutToAppear")
  }

  aboutToDisappear(): void {
    LogUtil.info(this.TAG, "aboutToDisappear")
  }
}

@Component
export struct NoteAndCreateComp {
  @StorageLink('AllFolderArray') AllFolderArray: FolderData[] = AppStorage.Link('AllFolderArray')
  @Consume('SelectedColor') selectedColor: string
  @Consume('PortraitModel') portraitModel: boolean
  folderCreateDialogCtl: CustomDialogController = new CustomDialogController({
    builder: NewOrEditFolderDialog({ confirm: this.onCreateConfirm.bind(this), dialogType: 0 }),
    alignment: DialogAlignment.Center,
    autoCancel: false,
    customStyle: true,
  })
  folderCreateDialogCtlBottom: CustomDialogController = new CustomDialogController({
    builder: NewOrEditFolderDialog({ confirm: this.onCreateConfirm.bind(this), dialogType: 0 }),
    alignment: DialogAlignment.Bottom,
    autoCancel: false,
    customStyle: true,
  })

  aboutToDisappear() {
    this.folderCreateDialogCtl = null
    this.folderCreateDialogCtlBottom = null
  }

  onCreateConfirm(color: string, name: string) {
    let folderData = new FolderData(0, name, new Date().getTime() + "", color, FolderType.CusDef, Delete.No, new Date().getTime(), new Date().getTime()) // 新的的笔记本都是自定义类型 type为1
    this.AllFolderArray.push(folderData)
    // insert folder to db
    RdbStoreUtil.insert(TableName.FolderTable, folderData.toFolderObject(), null)
    AppStorage.SetOrCreate('isUpdate', true)
  }

  build() {
    Flex({ alignItems: ItemAlign.Center, justifyContent: FlexAlign.SpaceBetween }) {
      Row() {
        Text($r("app.string.note"))
          .fontSize(20)
          .fontWeight(FontWeight.Bold)
      }.width(102)

      Row() {
        Text($r("app.string.create"))
          .fontSize(14)
          .fontColor($r("app.color.text_color_f86d05"))
          .onClick(() => {
            this.selectedColor = "#e84026" // 新建的时候选中第一个颜色
            if (this.portraitModel) {
              this.folderCreateDialogCtlBottom.open()
            } else {
              this.folderCreateDialogCtl.open()
            }
          }).padding({ right: 0 })
      }.width(50)
    }.width("100%")
    .margin({ top: 8 })
    .padding({ left: 24 })
    .height(56)
  }
}

@Component
struct FolderItemComp {
  @State folderItem: FolderData = new FolderData(0, "", new Date().getTime() + "", "", FolderType.CusDef, Delete.No, new Date().getTime(), new Date().getTime())
  @StorageLink('AllNoteArray') AllNoteArray: NoteData[] = []
  @StorageLink('AllFolderArray') AllFolderArray: FolderData[] = []
  @StorageLink('CheckedNoteArray') CheckedNoteArray: NoteData[] = []
  @Consume('SelectedFolderData') selectedFolderData: FolderData
  @Consume('SelectedNoteData') selectedNoteData: NoteData
  @Consume('RefreshFlag') refreshFlag: number
  @Consume('Longpress') longpress: boolean
  @Consume('SelectedColor') selectedColor: string
  @Consume('PortraitModel') portraitModel: boolean
  controllerShow: WebviewController
  @State isLongPress: boolean = false
  TAG = "FolderItemComp"
  @StorageLink('isUpdate') isUpdate: boolean = false
  // Folder Edit Dialog
  folderEditDialogCtl: CustomDialogController = new CustomDialogController({
    builder: NewOrEditFolderDialog({
      editFolderUuid: this.folderItem.uuid,
      confirm: this.onEditConfirm.bind(this),
      dialogType: 1
    }),
    alignment: DialogAlignment.Center,
    autoCancel: false,
    customStyle: true,
  })
  // Folder Edit Dialog for portrait model
  folderEditDialogCtlBottom: CustomDialogController = new CustomDialogController({
    builder: NewOrEditFolderDialog({
      editFolderUuid: this.folderItem.uuid,
      confirm: this.onEditConfirm.bind(this),
      dialogType: 1
    }),
    alignment: DialogAlignment.Bottom,
    autoCancel: false,
    customStyle: true,
  })

  aboutToDisappear() {
    this.folderEditDialogCtl = null
    this.folderEditDialogCtlBottom = null
    this.folderDeleteDialogCtl = null
    this.folderDeleteDialogCtlBottom = null
    this.folderCreateDialogCtl = null
    this.folderCreateDialogCtlBottom = null
  }

  // Folder Edit Callback
  onEditConfirm(color: string, name: string) {
    this.folderItem.color = color
    this.folderItem.name = name
    this.folderItem.folder_type = FolderType.CusDef
    // update folder to db
    let predicates_folder = RdbStoreUtil.getRdbPredicates(TableName.FolderTable)
    predicates_folder.equalTo(FolderTableColumn.Uuid, this.folderItem.uuid)
    RdbStoreUtil.update(this.folderItem.toFolderObject(), predicates_folder, null)
    this.isUpdate = true
  }
  // Folder Delete Dialog
  folderDeleteDialogCtl: CustomDialogController = new CustomDialogController({
    builder: DeleteDialog({ onConfirm: this.onDeleteConfirm.bind(this), deleteFileType: DeleteFileType.FolderData }),
    alignment: DialogAlignment.Center,
    autoCancel: false,
    customStyle: true,
  })
  // Folder Delete Dialog for portrait model
  folderDeleteDialogCtlBottom: CustomDialogController = new CustomDialogController({
    builder: DeleteDialog({ onConfirm: this.onDeleteConfirm.bind(this), deleteFileType: DeleteFileType.FolderData }),
    alignment: DialogAlignment.Bottom,
    autoCancel: false,
    customStyle: true,
  })
  // Folder Delete Callback
  onDeleteConfirm() {
    let currentFolder = FolderUtil.getFolderData(this.AllFolderArray, this.folderItem.uuid)
    let index = this.AllFolderArray.indexOf(currentFolder)
    let currentNoteDataArray = NoteUtil.getNoteDataArray(AppStorage.Get('AllNoteArray'), this.folderItem.uuid)
    let deleteNoteDataArray = NoteUtil.getNoteDataArray(AppStorage.Get('AllNoteArray'), 'sys_def_recentDeletes_uuid')
    if (index > -1) {
      this.AllFolderArray.splice(index, 1)
      if (deleteNoteDataArray.length != 0) {
        deleteNoteDataArray.forEach((noteItem: NoteData) => {
          let folderData: FolderData = FolderUtil.getFolderData(this.AllFolderArray, noteItem.folder_uuid)
          if (folderData == undefined) {
            noteItem.folder_uuid = SysDefFolderUuid.UnClassified
            // update note to db
            let predicates_note = RdbStoreUtil.getRdbPredicates(TableName.NoteTable)
            predicates_note.equalTo(NoteTableColumn.Uuid, noteItem.uuid)
            RdbStoreUtil.update(noteItem.toNoteObject(), predicates_note, null)
          }
        })
      }
      if (currentNoteDataArray.length != 0) {
        currentNoteDataArray.forEach((noteItem: NoteData) => {
          noteItem.is_deleted = Delete.Yes
          noteItem.folder_uuid = SysDefFolderUuid.UnClassified
          noteItem.deleted_time = new Date().getTime()
          // update note to db
          let predicates_note = RdbStoreUtil.getRdbPredicates(TableName.NoteTable)
          predicates_note.equalTo(NoteTableColumn.Uuid, noteItem.uuid)
          RdbStoreUtil.update(noteItem.toNoteObject(), predicates_note, null)
        })
      }
      // delete folder from db
      let predicates_folder = RdbStoreUtil.getRdbPredicates(TableName.FolderTable)
      predicates_folder.equalTo(FolderTableColumn.Uuid, this.folderItem.uuid)
      RdbStoreUtil.delete(predicates_folder, null)
      // update selectedFolderData and selectedNoteData
      this.selectedFolderData = FolderUtil.getFolderData(this.AllFolderArray, SysDefFolderUuid.AllNotes)
      this.selectedNoteData = NoteUtil.getFirstNoteData(this.AllNoteArray, SysDefFolderUuid.AllNotes)
      if (!this.selectedNoteData) {
        return
      }
      // 刷新web界面
      if (this.portraitModel == false) {
        try {
          this.controllerShow.runJavaScript(
            "RICH_EDITOR.setHtml('" + this.selectedNoteData.content_text + "')"
          )
          LogUtil.info(this.TAG, `runJavaScript success.`);
        } catch (error) {
          LogUtil.error(this.TAG, `runJavaScript failed.code:${JSON.stringify(error.code)},message:${JSON.stringify(error.message)}`);
        }
      }
      // save continue data
      let continueNote: string = JSON.stringify(this.selectedNoteData.toNoteObject())
      AppStorage.SetOrCreate<string>('ContinueNote', continueNote)
      LogUtil.info(this.TAG, "onDeleteConfirm, set continue note success")
    }
    this.isUpdate = true
  }
  // Folder Create Dialog
  folderCreateDialogCtl: CustomDialogController = new CustomDialogController({
    builder: NewOrEditFolderDialog({ confirm: this.onCreateConfirm.bind(this), dialogType: 0 }),
    alignment: DialogAlignment.Center,
    autoCancel: false,
    customStyle: true,
  })
  // Folder Create Dialog for portrait model
  folderCreateDialogCtlBottom: CustomDialogController = new CustomDialogController({
    builder: NewOrEditFolderDialog({ confirm: this.onCreateConfirm.bind(this), dialogType: 0 }),
    alignment: DialogAlignment.Bottom,
    autoCancel: false,
    customStyle: true,
  })
  // Folder Create Callback
  onCreateConfirm(color: string, name: string) {
    let folderData = new FolderData(0, name, new Date().getTime() + "", color, FolderType.CusDef, Delete.No, new Date().getTime(), new Date().getTime()) // 新的的笔记本都是自定义类型 type为1
    this.AllFolderArray.push(folderData)
    // insert folder to db
    RdbStoreUtil.insert(TableName.FolderTable, folderData.toFolderObject(), null)
    this.isUpdate = true
  }

  @Builder menuBuilder() {
    Column({ space: 1 }) {
      Text($r("app.string.editFolder"))
        .width(124)
        .height(48)
        .padding({ top: 13, bottom: 13 })
        .fontSize(16)
        .fontColor($r("app.color.folder_color_182431"))
        .onClick(() => {
          this.selectedColor = this.folderItem.color
          if (this.portraitModel) {
            this.folderEditDialogCtlBottom.open()
          } else {
            this.folderEditDialogCtl.open()
          }
          ContextMenu.close()
        })
      Divider()
        .color($r("app.color.divider_color_e4e4e4"))
        .strokeWidth(1)
      Text($r("app.string.deleteFolder"))
        .width(124)
        .height(48)
        .padding({ top: 13, bottom: 14 })
        .fontSize(16)
        .fontColor($r("app.color.folder_color_182431"))
        .onClick(() => {
          if (this.portraitModel) {
            this.folderDeleteDialogCtlBottom.open()
          } else {
            this.folderDeleteDialogCtl.open()
          }
          ContextMenu.close()
        })
      Divider()
        .color($r("app.color.divider_color_e4e4e4"))
        .strokeWidth(1)
      Text($r("app.string.createFolder"))
        .width(124)
        .height(48)
        .padding({ top: 13, bottom: 15 })
        .fontSize(16)
        .fontColor($r("app.color.folder_color_182431"))
        .onClick(() => {
          this.selectedColor = "#e84026" // 新建的时候选中第一个颜色
          if (this.portraitModel) {
            this.folderCreateDialogCtlBottom.open()
          } else {
            this.folderCreateDialogCtl.open()
          }
          ContextMenu.close()
        })
    }
    .width(156)
    .height(154)
    .padding({ top: 4, bottom: 4, left: 16, right: 16 })
    .borderRadius(16)
    .backgroundColor($r("app.color.press_folder_bg_color"))
  }

  build() {
    Flex() {
      if (this.folderItem?.folder_type == FolderType.CusDef) {
        Flex({ alignItems: ItemAlign.Center, wrap: FlexWrap.NoWrap, justifyContent: FlexAlign.SpaceBetween }) {
          Row() {
            Image(FolderUtil.getFolderIcon(this.folderItem.uuid))
              .id(this.isUpdate + '')
              .objectFit(ImageFit.Fill)
              .width(24)
              .height(24)
              .fillColor(FolderUtil.getFolderIconColor(this.AllFolderArray, this.folderItem.uuid, this.selectedFolderData.uuid == this.folderItem.uuid))
              .margin({ right: 16 })
            Text(FolderUtil.getFolderText(this.folderItem))
              .id(this.isUpdate + '')
              .fontWeight(FontWeight.Medium)
              .fontSize(16)
              .textAlign(TextAlign.Center)
              .maxLines(1)
              .textOverflow({ overflow: TextOverflow.Ellipsis })
              .flexShrink(1)
              .fontColor(FolderUtil.getFolderTextColor(this.selectedFolderData.uuid == this.folderItem.uuid))
            Text(JSON.stringify(this.refreshFlag))
              .visibility(Visibility.None) // 用于强制刷新使用
          }.width(118)

          Text(FolderUtil.getNoteCount(AppStorage.Get('AllNoteArray'), this.folderItem.uuid).toString())
            .id(this.isUpdate + '')
            .fontWeight(FontWeight.Regular)
            .fontSize(14)
            .textAlign(TextAlign.Center)
        }
        .width('100%')
        .borderRadius(12)
        .height(56)
        .padding({ left: 12, right: 12 })
        .backgroundColor(this.isLongPress ? $r("app.color.folder_color_19182431") : this.selectedFolderData.uuid == this.folderItem.uuid
                                                                                      ? $r("app.color.folder_color_ffffff") : "#00FFFFFF")
        .bindContextMenu(this.menuBuilder, ResponseType.LongPress)
        .bindContextMenu(this.menuBuilder, ResponseType.RightClick)
        .onClick(() => {
          if (this.longpress) {
            this.longpress = false
            NoteUtil.unsetAllNotesChecked(this.CheckedNoteArray)
          } else {
            this.selectedFolderData = this.folderItem
            this.selectedNoteData = NoteUtil.getFirstNoteData(AppStorage.Get('AllNoteArray'), this.folderItem.uuid)
            if (!this.selectedNoteData) {
              return
            }
            // 刷新web界面
            if (this.portraitModel == false) {
              this.controllerShow.runJavaScript(
                "RICH_EDITOR.setHtml('" + this.selectedNoteData.content_text + "')"
              )
            }
            // save continue data
            let continueNote: string = JSON.stringify(this.selectedNoteData.toNoteObject())
            AppStorage.SetOrCreate<string>('ContinueNote', continueNote)
            AppStorage.SetOrCreate('ContinueSection', 3)
            LogUtil.info(this.TAG, "FolderItemComp, set continue note success")
          }
          NoteUtil.refreshAll()
        })
      } else {
        Flex({ alignItems: ItemAlign.Center, wrap: FlexWrap.NoWrap, justifyContent: FlexAlign.SpaceBetween }) {
          Row() {
            Image(FolderUtil.getFolderIcon(this.folderItem.uuid))
              .id(this.isUpdate + '')
              .objectFit(ImageFit.Fill)
              .width(24)
              .height(24)
              .fillColor(this.isUpdate ? FolderUtil.getFolderIconColor(this.AllFolderArray, this.folderItem.uuid, this.selectedFolderData.uuid == this.folderItem.uuid) : FolderUtil.getFolderIconColor(this.AllFolderArray, this.folderItem.uuid, this.selectedFolderData.uuid == this.folderItem.uuid))
              .margin({ right: 16 })
            Text(FolderUtil.getFolderText(this.folderItem))
              .id(this.isUpdate + '')
              .fontWeight(FontWeight.Medium)
              .fontSize(16)
              .textAlign(TextAlign.Center)
              .maxLines(1)
              .textOverflow({ overflow: TextOverflow.Ellipsis })
              .flexShrink(1)
              .fontColor(FolderUtil.getFolderTextColor(this.selectedFolderData.uuid == this.folderItem.uuid))
            Text(JSON.stringify(this.refreshFlag))
              .visibility(Visibility.None) // 用于强制刷新使用
          }.width(118)

          Text(FolderUtil.getNoteCount(AppStorage.Get('AllNoteArray'), this.folderItem.uuid).toString())
            .id(this.isUpdate + '')
            .fontWeight(FontWeight.Regular)
            .fontSize(14)
            .textAlign(TextAlign.Center)
        }
        .width('100%')
        .borderRadius(12)
        .height(56)
        .padding({ left: 12, right: 12 })
        .backgroundColor(this.isLongPress ? $r("app.color.folder_color_19182431") : this.selectedFolderData.uuid == this.folderItem.uuid
                                                                                      ? $r("app.color.folder_color_ffffff") : "#00FFFFFF")
        .onClick(() => {
          if (this.longpress) {
            this.longpress = false
            NoteUtil.unsetAllNotesChecked(this.CheckedNoteArray)
          } else {
            this.selectedFolderData = this.folderItem
            this.selectedNoteData = NoteUtil.getFirstNoteData(AppStorage.Get('AllNoteArray'), this.folderItem.uuid)
            if (!this.selectedNoteData) {
              return
            }
            // 刷新web界面
            if (this.portraitModel == false) {
              this.controllerShow.runJavaScript(
                "RICH_EDITOR.setHtml('" + this.selectedNoteData.content_text + "')"
              )
            }
            // save continue data
            let continueNote: string = JSON.stringify(this.selectedNoteData.toNoteObject())
            AppStorage.SetOrCreate<string>('ContinueNote', continueNote)
            AppStorage.SetOrCreate('ContinueSection', 3)
            LogUtil.info(this.TAG, "FolderItemComp, set continue note success")
          }
          NoteUtil.refreshAll()
        })
      }
    }
    .width('100%')
    .height(56)
    .parallelGesture(
    GestureGroup(GestureMode.Exclusive,
    LongPressGesture()
      .onAction(() => {
        this.isLongPress = true
        this.refreshFlag = (this.refreshFlag == 0 ? 1 : 0)
      })
      .onActionEnd(() => {
        this.isLongPress = false
        this.refreshFlag = (this.refreshFlag == 0 ? 1 : 0)
      })
    )
    )
  }
}