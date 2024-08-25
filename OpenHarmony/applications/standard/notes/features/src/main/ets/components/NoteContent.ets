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

import DateUtil from '@ohos/utils/src/main/ets/default/baseUtil/DateUtil'
import RdbStoreUtil from '@ohos/utils/src/main/ets/default/baseUtil/RdbStoreUtil'
import FolderData from '@ohos/utils/src/main/ets/default/model/databaseModel/FolderData'
import NoteData from '@ohos/utils/src/main/ets/default/model/databaseModel/NoteData'
import util from '@ohos.util'
import {
  TableName,
  NoteTableColumn,
  SysDefFolderUuid,
  Favorite,
  Delete
} from '@ohos/utils/src/main/ets/default/model/databaseModel/EnumData'
import StyleConstants from '@ohos/utils/src/main/ets/default/constants/StyleConstants'
import { EditContentDialog, EditTitleDialog } from './CusDialogComp'
import FolderUtil from '@ohos/utils/src/main/ets/default/baseUtil/FolderUtil'
import NoteUtil from '@ohos/utils/src/main/ets/default/baseUtil/NoteUtil'
import { LogUtil } from '@ohos/utils/src/main/ets/default/baseUtil/LogUtil'
import OperationUtils from '@ohos/utils/src/main/ets/default/baseUtil/OperationUtils'
import router from '@system.router';
import inputMethod from '@ohos.inputMethod';
import { folderTextMap } from '@ohos/utils/src/main/ets/default/model/NoteBaseData'

const TAG = "NoteContent"

var timeID: number

@Component
export struct NoteContent {
  @Provide('SelectedNoteData') selectedNoteData: NoteData = AppStorage.Get('NewNote')
  @StorageLink('AllNoteArray') AllNoteArray: NoteData[] = AppStorage.Link('AllNoteArray')
  @Provide('Issave') issave: number = 0
  @Provide('EditModel') editModel: boolean = false
  @StorageLink('dpi') dpi: number = 240
  controllerShow: WebviewController
  private editContentFlag = false
  @StorageLink('ScrollTopPercent') scrollTopPercent: number = 0.0

  storeScrollTop(scrollTop: number) {
    if (scrollTop < 0) {
      return
    }
    AppStorage.SetOrCreate<number>('ScrollTopPercent', scrollTop / this.controllerShow.getPageHeight())
  }

  restoreScrollTop() {
    if (!AppStorage.Has('remoteScrollTopPercent')) {
      return
    }
    var scrollTopPercent = AppStorage.Get<number>('remoteScrollTopPercent')
    if (scrollTopPercent < 0) {
      return
    }
    this.controllerShow.runJavaScript(
      'document.documentElement.scrollTop = ' + this.controllerShow.getPageHeight() * scrollTopPercent
    )
    AppStorage.Delete('remoteScrollTopPercent')
  }

  restoreFocus() {
    if (!AppStorage.Has('isRemoteFocusOnSearch')) {
      return
    }
    let isRemoteFocusOnSearch = AppStorage.Get<boolean>('isRemoteFocusOnSearch')
    if (isRemoteFocusOnSearch) {
      focusControl.requestFocus('searchInput')
    }
    AppStorage.Delete('isRemoteFocusOnSearch')
  }

  noteContent = {
    callbackhtml: (html) => {
      LogUtil.info(TAG, 'note uuid is:' + this.selectedNoteData.uuid)
      this.selectedNoteData.content_text = html
      this.selectedNoteData.modified_time = new Date().getTime()
      let predicates_note = RdbStoreUtil.getRdbPredicates(TableName.NoteTable)
      predicates_note.equalTo(NoteTableColumn.Uuid, this.selectedNoteData.uuid)
      RdbStoreUtil.update(this.selectedNoteData.toNoteObject(), predicates_note, null)
      LogUtil.info(TAG, 'update note success:' + this.selectedNoteData.uuid)
      AppStorage.SetOrCreate<NoteData>('NewNote', this.selectedNoteData)
      AppStorage.SetOrCreate<boolean>('needRefresh', true)
      // save continue data
      let continueNote: string = JSON.stringify(this.selectedNoteData.toNoteObject())
      AppStorage.SetOrCreate<string>('ContinueNote', continueNote)
      LogUtil.info(TAG, "callbackhtml, set continue note success")
    },
    callbackImagePath: (imgName) => {
      // updata note image
      LogUtil.info(TAG, 'note imgPath is:' + imgName)
      this.selectedNoteData.content_img = imgName
    },

    callbackScheduledSave: (html) => {
      LogUtil.info(TAG, 'callbackScheduledSave')
      if (this.selectedNoteData.content_text == html) {
        LogUtil.info(TAG, 'callbackScheduledSave the same value return')
        return;
      }
      this.selectedNoteData.content_text = html
      this.selectedNoteData.modified_time = new Date().getTime()
      let predicates_note = RdbStoreUtil.getRdbPredicates(TableName.NoteTable)
      predicates_note.equalTo(NoteTableColumn.Uuid, this.selectedNoteData.uuid)
      RdbStoreUtil.update(this.selectedNoteData.toNoteObject(), predicates_note, null)
      LogUtil.info(TAG, 'callbackScheduledSave, update note success:' + this.selectedNoteData.uuid)
      // save continue data
      let continueNote: string = JSON.stringify(this.selectedNoteData.toNoteObject())
      LogUtil.info(TAG, 'continueNote content', continueNote)
      AppStorage.SetOrCreate<string>('ContinueNote', continueNote)
      LogUtil.info(TAG, 'callbackScheduledSave, set continue note success')
    },
    callbackPasteImage: (html) => {
      if (html) {
        LogUtil.info(TAG, 'paste info' + html)
        let realHtml = ""
        let base64regex = /^([0-9a-zA-Z+/]{4})*(([0-9a-zA-Z+/]{2}==)|([0-9a-zA-Z+/]{3}=))?$/
        if (html && html.indexOf("base64") > 0) {
          LogUtil.info(TAG, " getSrcFromHtml, src[1] : " + html)
          let imgData = html.split(',')[1];
          let imgType = 'png'
          if (html.indexOf("jpeg") > 0) {
            imgType = 'jpg'
          } else if (html.indexOf("gif") > 0) {
            imgType = 'gif'
          }
          let filePath = ""
          if (base64regex.test(imgData)) {
            let base64 = new util.Base64()
            let decodeArr = base64.decodeSync(imgData)
            filePath = OperationUtils.saveImageData(decodeArr, imgType)
          } else {
            filePath = OperationUtils.saveImage(imgData, imgType)
          }
          realHtml = "file://" + filePath
        }
        LogUtil.info(TAG, 'paste info11' + realHtml)
        this.controllerShow.runJavaScript("javascript:RICH_EDITOR.insertImageHtml('" + realHtml + "')")
      } else {
        LogUtil.info(TAG, 'paste info22223')
      }
    },
    callbackGetSize: (fontSize) => {
      if (fontSize === 16) {
        this.selectedNoteData.slider_value = 0
      } else if (fontSize === 18) {
        this.selectedNoteData.slider_value = 4
      } else if (fontSize === 24) {
        this.selectedNoteData.slider_value = 8
      } else if (fontSize === 32) {
        this.selectedNoteData.slider_value = 12
      } else if (fontSize === 48) {
        this.selectedNoteData.slider_value = 16
      }
    }
  }

  build() {
    Stack({ alignContent: Alignment.Bottom }) {
      Flex({ direction: FlexDirection.Column, wrap: FlexWrap.NoWrap,
        alignItems: ItemAlign.Start, alignContent: FlexAlign.SpaceAround }) {
        Column() {
          ToolBarComp({ controllerShow: this.controllerShow })
        }.margin({ left: 24, right: 24 })

        Column() {
          NoteContentOverViewComp()

          Web({ src: $rawfile('editor.html'), controller: this.controllerShow })
            .javaScriptAccess(true)
            .javaScriptProxy({
              object: this.noteContent,
              name: "callBackToApp", // html-->  name.method
              methodList: ["callbackhtml", "callbackScheduledSave", "callbackPasteImage", "callbackImagePath", "callbackGetSize"],
              controller: this.controllerShow
            })
            .onPageEnd((e) => {
              if (this.dpi <= 240) {
                this.controllerShow.runJavaScript("changeSizeToRk()")
              } else if (this.dpi <= 320 && this.dpi > 240) {
                this.controllerShow.runJavaScript("changeSizeToPhone()")
              } else {
                this.controllerShow.runJavaScript("changeSizeToTablet()")
              }
              if (AppStorage.Get('breakPoint') !== 'sm') {
                this.controllerShow.runJavaScript("hiddenButton()")
              }
              LogUtil.info(TAG, "finish loadurl")
              if (this.selectedNoteData) {
                let self = this
                this.controllerShow.runJavaScript(
                  "RICH_EDITOR.setHtml('" + this.selectedNoteData.content_text + "')",
                  () => {
                    // wait for the image in the note to load
                    setTimeout(function () {
                      self.restoreScrollTop()
                      self.restoreFocus()
                    }, 100)
                  }
                )
              }
            })
            .zoomAccess(false)
            .imageAccess(true)
            .onlineImageAccess(true)
            .fileAccess(true)
            .domStorageAccess(true)
            .height('88%')
            .width('100%')
            .onScroll((event) => {
              this.storeScrollTop(event.yOffset)
            })
            .onClick(() => {
              // 添加定时器：3s自动保存
              if (timeID) {
                clearInterval(timeID)
              }
              timeID = setInterval(() => {
                this.controllerShow.runJavaScript("scheduledSaveContent()")
              }, 3000)
              LogUtil.info(TAG, "setInterval timeID : " + timeID)
              this.issave = 0
              this.editModel = true
            })
        }
        .margin({ left: 12, right: 24, top: 16 })
      }
      .height(StyleConstants.PERCENTAGE_100)
    }
    .height(StyleConstants.PERCENTAGE_100)
    .width(StyleConstants.PERCENTAGE_100)
  }

  aboutToAppear(): void {
    LogUtil.info(TAG, "aboutToAppear")
  }

  aboutToDisappear(): void {
    AppStorage.Set("refreshCurrentNote", true)
    NoteUtil.refreshAll()
    clearInterval(timeID)
    LogUtil.info(TAG, "aboutToDisappear")
  }
}

@Component
export struct ToolBarComp {
  @Consume('SelectedNoteData') selectedNoteData: NoteData
  @StorageLink('AllNoteArray') AllNoteArray: NoteData[] = AppStorage.Link('AllNoteArray')
  @Consume('Issave') issave: number
  @Consume('EditModel') editModel: boolean
  controllerShow: WebviewController
  editContentDialogCtl: CustomDialogController = new CustomDialogController({
    builder: EditContentDialog({ confirm: this.confirm.bind(this) }),
    alignment: DialogAlignment.Bottom,
    autoCancel: true,
    customStyle: true,
  })

  aboutToDisappear() {
    this.editContentDialogCtl = null
  }

  confirm(excuteJs: string) {
    this.controllerShow.runJavaScript(excuteJs)
  }

  build() {
    Flex({ direction: FlexDirection.Row, wrap: FlexWrap.NoWrap,
      justifyContent: FlexAlign.SpaceBetween, alignItems: ItemAlign.Center }) {
      Image($r('app.media.narrow'))
        .height(24)
        .width(24)
        .onClick(() => {
          this.controllerShow.runJavaScript("RICH_EDITOR.setInputEnabled(false)")
          this.controllerShow.runJavaScript("getHtmlContent()")
          // 清除定时器
          if (timeID != undefined) {
            LogUtil.info(TAG, "zoom, clearInterval timeID : " + timeID)
            clearInterval(timeID)
          }
          AppStorage.Set("refreshCurrentNote", true)
          router.back()
          NoteUtil.refreshAll()
        })
        .visibility(this.selectedNoteData.is_deleted == Delete.Yes ? Visibility.None : Visibility.Visible)

      if (this.editModel == false) {
        Row({ space: StyleConstants.SPACE_24 }) {
          Image(this.selectedNoteData.is_favorite == Favorite.Yes ? $r('app.media.favorite') : $r('app.media.favorite_cancel'))
            .height(24).width(24)
            .onClick(() => {
              try {
                this.selectedNoteData.is_favorite = (this.selectedNoteData.is_favorite == Favorite.Yes ? Favorite.No : Favorite.Yes)
                // update note to db
                let predicates_note = RdbStoreUtil.getRdbPredicates(TableName.NoteTable)
                predicates_note.equalTo(NoteTableColumn.Uuid, this.selectedNoteData.uuid)
                RdbStoreUtil.update(this.selectedNoteData.toNoteObject(), predicates_note, null)
                // save continue data
                let continueNote: string = JSON.stringify(this.selectedNoteData.toNoteObject())
                AppStorage.SetOrCreate<string>('ContinueNote', continueNote)
                LogUtil.info(TAG, 'ToolBarComp, set continue note success')
                NoteUtil.refreshAll()
              } catch (error) {
                LogUtil.error(TAG, 'favorite error: ' + JSON.stringify(error));
              }
            })
        }.width(36)
        .visibility(this.selectedNoteData.is_deleted == Delete.Yes ? Visibility.None : Visibility.Visible)
      } else {
        Row({ space: StyleConstants.SPACE_6 }) {
          Button({ type: ButtonType.Normal, stateEffect: true }) {
            Image($r('app.media.circle_tick1'))
              .height(24)
              .width(24)
              .onClick(() => {
                // 退出键盘
                // @ts-ignore
                inputMethod.getController().stopInputSession();
                // 清单
                this.controllerShow.runJavaScript("javascript:RICH_EDITOR.setTodo()")
              })
          }.width(42)
          .height(42)
          .borderRadius(8)
          .backgroundColor($r('app.color.color_fffffB'))

          Button({ type: ButtonType.Normal, stateEffect: true }) {
            Image($r('app.media.font_style'))
              .height(24)
              .width(24)
              .onClick(() => {
                // 退出键盘
                // @ts-ignore
                inputMethod.getController().stopInputSession();
                LogUtil.info(TAG, 'editContentDialogCtl start')
                this.editContentDialogCtl.open()
              })
          }.width(42)
          .height(42)
          .borderRadius(8)
          .backgroundColor($r('app.color.color_fffffB'))

          Button({ type: ButtonType.Normal, stateEffect: true }) {
            Image($r('app.media.picture_white')).height(24).width(24)
              .onClick(async () => {
                // 退出键盘
                // @ts-ignore
                inputMethod.getController().stopInputSession();
                LogUtil.info(TAG, 'startAbility start')
                await globalThis.noteContext.startAbilityForResult({
                  parameters: { uri: "singleselect" },
                  bundleName: "com.ohos.photos",
                  abilityName: "com.ohos.photos.MainAbility",
                })
                  .then(v => {
                    let want = v['want'];
                    if (want != null && want != undefined) {
                      let param = want['parameters'];
                      let imageUri = ""
                      if (param != null && param != undefined) {
                        let uri = param['select-item-list'];
                        imageUri = uri[0];
                      }
                      // 拷贝
                      if (imageUri != null && imageUri != "") {
                        OperationUtils.copy(imageUri).then((uriPath) => {
                          var path = "file://" + uriPath
                          LogUtil.info(TAG, 'image uri is:' + path)
                          this.controllerShow.runJavaScript(
                            "javascript:RICH_EDITOR.insertImage('" + path + "')"
                          )
                          this.issave = 1
                          // 保存笔记信息到数据库
                          this.controllerShow.runJavaScript("getHtmlContent()")
                        })
                      }
                    }
                  });
              })
          }.width(42)
          .height(42)
          .borderRadius(8)
          .backgroundColor($r('app.color.color_fffffB'))

          Button({ type: ButtonType.Normal, stateEffect: true }) {
            Image($r('app.media.undo'))
              .height(24)
              .width(24)
              .onClick(() => {
                // 退出键盘
                // @ts-ignore
                inputMethod.getController().stopInputSession();
                this.controllerShow.runJavaScript("RICH_EDITOR.undo()")
              })
          }.width(42)
          .height(42)
          .borderRadius(8)
          .backgroundColor($r('app.color.color_fffffB'))

          Button({ type: ButtonType.Normal, stateEffect: true }) {
            Image($r('app.media.todo'))
              .height(24)
              .width(24)
              .onClick(() => {
                // 退出键盘
                // @ts-ignore
                inputMethod.getController().stopInputSession();
                this.controllerShow.runJavaScript("RICH_EDITOR.redo()")
              })
          }.width(42)
          .height(42)
          .borderRadius(8)
          .backgroundColor($r('app.color.color_fffffB'))


          Button({ type: ButtonType.Normal, stateEffect: true }) {
            Image($r('app.media.tick_thick'))
              .height(24)
              .width(24)
              .fillColor(this.issave == 0 ? Color.Black : Color.Grey)
              .onClick(() => {
                this.issave = 1
                // 保存笔记信息到数据库
                this.controllerShow.runJavaScript("getHtmlContent()")
              })
          }.width(42)
          .height(42)
          .borderRadius(8)
          .backgroundColor($r('app.color.color_fffffB'))
        }.width(274)
      }
    }
    .width(StyleConstants.PERCENTAGE_100)
    .height(80)
  }
}

@Component
export struct NoteContentOverViewComp {
  @Consume('SelectedNoteData') selectedNoteData: NoteData
  @StorageLink('AllFolderArray') AllFolderArray: FolderData[] = []
  @StorageLink('CheckedNoteArray') CheckedNoteArray: NoteData[] = []
  @StorageLink('isUpdate') isUpdate: boolean = false
  editTitleDialogCtl: CustomDialogController = new CustomDialogController({
    builder: EditTitleDialog({ confirm: this.confirm.bind(this) }),
    alignment: DialogAlignment.Center,
    autoCancel: false,
    customStyle: true,
  })

  aboutToDisappear() {
    this.editTitleDialogCtl = null
  }

  confirm(newTitle: string) {
    this.selectedNoteData.title = newTitle
    this.selectedNoteData.modified_time = new Date().getTime()
    let predicates_note = RdbStoreUtil.getRdbPredicates(TableName.NoteTable)
    predicates_note.equalTo(NoteTableColumn.Uuid, this.selectedNoteData.uuid)
    RdbStoreUtil.update(this.selectedNoteData.toNoteObject(), predicates_note, null)
    // save continue data
    let continueNote: string = JSON.stringify(this.selectedNoteData.toNoteObject())
    AppStorage.SetOrCreate<string>('ContinueNote', continueNote)
    LogUtil.info(TAG, "NoteContentOverViewComp confirm, set continue note success")
    NoteUtil.refreshAll()
  }

  @Builder MenuBuilder() {
    Flex({ direction: FlexDirection.Column, justifyContent: FlexAlign.Center, alignItems: ItemAlign.Center }) {
      List() {
        ForEach(this.AllFolderArray, (item) => {
          ListItem() {
            NoteDataMoveItemComp({ folderItem: item })
          }
          .onClick(() => {
            this.selectedNoteData.folder_uuid = item.uuid
            let predicates_note = RdbStoreUtil.getRdbPredicates(TableName.NoteTable)
            predicates_note.equalTo(NoteTableColumn.Uuid, this.selectedNoteData.uuid)
            RdbStoreUtil.update(this.selectedNoteData.toNoteObject(), predicates_note, null)
            // save continue data
            let continueNote: string = JSON.stringify(this.selectedNoteData.toNoteObject())
            AppStorage.SetOrCreate<string>('ContinueNote', continueNote)
            LogUtil.info(TAG, "NoteContentOverViewComp MenuBuilder, set continue note success")
            NoteUtil.refreshAll()
          })
        }, noteItem => JSON.stringify(noteItem))
      }.listDirection(Axis.Vertical)
      .edgeEffect(EdgeEffect.Spring)
      .height(this.AllFolderArray.length > 12 ? 504 : (this.AllFolderArray.length - 3) * 56)
    }
    .width(148)
    .backgroundColor($r("app.color.color_fffffB"))
    .padding({ left: 24, right: 24 })
  }

  build() {
    if (this.selectedNoteData) {
      Flex({ direction: FlexDirection.Column, wrap: FlexWrap.NoWrap,
        justifyContent: FlexAlign.SpaceBetween, alignItems: ItemAlign.Center }) {
        Row() {
          Text(this.selectedNoteData.title)
            .id(this.isUpdate + '')
            .fontSize(30)
            .margin({ left: 12, right: 24 })
            .onClick(() => {
              clearInterval(timeID)
              this.editTitleDialogCtl.open()
            })
        }.height(40)
        .width(StyleConstants.PERCENTAGE_100)

        Row() {
          Text(DateUtil.formateDateForNoteContent(new Date(this.selectedNoteData.modified_time)))
            .id(this.isUpdate + '')
            .fontSize(12)
            .padding({ top: 4, bottom: 4 })
            .fontColor($r("app.color.modified_time_font_color"))
            .margin({ left: 12 })
          Row() {
            Text(FolderUtil.getFolderText(FolderUtil.getFolderData(AppStorage.Get('AllFolderArray'), this.selectedNoteData.folder_uuid)) ==
                 folderTextMap["sys_def_myFavorites_uuid"] ? folderTextMap["sys_def_unClassified_uuid"] :
            FolderUtil.getFolderText(FolderUtil.getFolderData(AppStorage.Get('AllFolderArray'), this.selectedNoteData.folder_uuid)))
              .id(this.isUpdate + '')
              .fontSize(12)
              .fontColor($r("app.color.list_modified_time_font_color"))
            Image($r('app.media.triangle'))
              .width(6)
              .height(12)
              .margin({ left: 4 })
          }
          .padding({ left: 8, right: 8, top: 4, bottom: 4 })
          .margin({ left: 8 })
          .borderRadius(16)
          .backgroundColor(NoteUtil.getNoteBgColor(AppStorage.Get('AllFolderArray'), this.selectedNoteData.folder_uuid, SysDefFolderUuid.AllNotes, false))
          .bindMenu(this.MenuBuilder)
        }.alignItems(VerticalAlign.Top).height(40).width(StyleConstants.PERCENTAGE_100)
      }
      .opacity(this.selectedNoteData.is_deleted == Delete.Yes ? 0.4 : 1)
      .width(StyleConstants.PERCENTAGE_100)
      .height(80)
    }
  }
}

@Component
struct NoteDataMoveItemComp {
  @StorageLink('CheckedNoteArray') CheckedNoteArray: NoteData[] = []
  @StorageLink('AllFolderArray') AllFolderArray: FolderData[] = []
  private folderItem: FolderData

  build() {
    Flex({ alignItems: ItemAlign.Center, wrap: FlexWrap.NoWrap, justifyContent: FlexAlign.Center }) {
      Flex({ alignItems: ItemAlign.Center, wrap: FlexWrap.NoWrap }) {
        Image(FolderUtil.getFolderIcon(this.folderItem.uuid))
          .objectFit(ImageFit.Fill)
          .width(24)
          .height(24)
          .flexShrink(0)
          .fillColor(FolderUtil.getFolderIconColor(this.AllFolderArray, this.folderItem.uuid, false))
      }
      .width(24)

      Column() {
        Flex({ alignItems: ItemAlign.Center, wrap: FlexWrap.NoWrap, justifyContent: FlexAlign.SpaceBetween }) {
          Text(FolderUtil.getFolderText(this.folderItem))
            .fontSize(16)
            .fontColor(FolderUtil.getFolderIconColor(this.AllFolderArray, this.folderItem.uuid, false))
            .textAlign(TextAlign.Center)
            .maxLines(1)
            .textOverflow({ overflow: TextOverflow.Ellipsis })
            .flexShrink(1)
        }
        .width('100%')
        .height(55)

        Divider()
          .color($r("app.color.divider_color_e4e4e4"))
          .strokeWidth(1)
      }
      .padding({ left: 16 })
    }
    .width('100%')
    .height(56)
    .visibility(FolderUtil.isFolderMoveIn(this.folderItem) ? Visibility.Visible : Visibility.None)
  }
}