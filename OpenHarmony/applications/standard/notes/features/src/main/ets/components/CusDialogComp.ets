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

import GlobalResourceManager from '@ohos/utils/src/main/ets/default/baseUtil/GlobalResourceManager'
import FolderData from '@ohos/utils/src/main/ets/default/model/databaseModel/FolderData'
import FolderUtil from '@ohos/utils/src/main/ets/default/baseUtil/FolderUtil'
import NoteData from '@ohos/utils/src/main/ets/default/model/databaseModel/NoteData'
import NoteUtil from '@ohos/utils/src/main/ets/default/baseUtil/NoteUtil'
import { circleColorArray, fontColorArray, SysDefFolderUuid, DeleteFileType, FolderType, LogUtil } from '@ohos/utils'
import inputMethod from '@ohos.inputMethod'

const TAG = "CusDialogComp"

@CustomDialog
export struct NewOrEditFolderDialog {
  newOrEditFolderDialogCtl: CustomDialogController
  confirm: (color: string, name: string) => void
  @State inputName: string = ""
  private oriInputName: string = ""
  private oriSelectedColor: string = ""
  private editFolderUuid: string = ""
  private dialogType: number = 0 // 0表示新建文件夹  1表示修改文件夹
  @State isExisted: boolean = false
  @StorageLink('AllFolderArray') AllFolderArray: FolderData[] = AppStorage.Link('AllFolderArray')
  @Consume('SelectedColor') selectedColor: string

  build() {
    Column() {
      Text(this.dialogType == 0 ? $r("app.string.createFolder") : $r("app.string.editFolder"))
        .fontSize(20)
        .height(56)
        .margin({ left: 24 })
        .fontWeight(FontWeight.Medium)
      // folder color choose
      Flex({ wrap: FlexWrap.NoWrap, justifyContent: FlexAlign.SpaceBetween }) {
        ForEach(circleColorArray, (colorStr: string) => {
          ColorCircleComp({ circleColor: colorStr })
        }, colorStr => colorStr)
      }.margin({ bottom: 12, left: 24, right: 24 })
      // folder name input
      Flex({ wrap: FlexWrap.NoWrap, justifyContent: FlexAlign.SpaceBetween }) {
        Image($r("app.media.folder"))
          .objectFit(ImageFit.Fill)
          .width(24)
          .height(24)
          .flexShrink(0)
          .fillColor(this.selectedColor)
        TextInput({ text: this.inputName, placeholder: $r("app.string.input_placeholder") })
          .placeholderFont({ size: 18 })
          .maxLength(20)
          .borderRadius(15)
          .backgroundColor($r("app.color.New_folder_input_box_color"))
          .width('100%')
          .padding({ left: 12, bottom: -12 })
          .onChange((value: string) => {
            this.inputName = value
            FolderUtil.duplicateDetection(this.inputName, this.AllFolderArray).then(result => {
              this.isExisted = result
            })
          })
          .restoreId(1)
      }.margin({ bottom: 4, left: 24, right: 24 })

      Divider()
        .height(1)
        .margin({ left: 64, right: 24 })
        .color((this.isExisted && this.inputName != this.oriInputName) ? $r("app.color.category_already_exist_divider_color") : $r("app.color.divider_color_182431"))
      if (this.isExisted && this.inputName != this.oriInputName) {
        Text($r("app.string.category_already_exist"))
          .fontSize(10)
          .margin({ left: 64, top: 4 })
          .fontColor($r("app.color.category_already_exist_font_color"))
          .visibility((this.isExisted && this.inputName != this.oriInputName) ? Visibility.Visible : Visibility.None)
      } else {
        Column() {
        }
        .height(16)
        .width("100%")
      }

      // button group
      Flex({ wrap: FlexWrap.Wrap, justifyContent: FlexAlign.SpaceBetween }) {
        Text($r("app.string.cancel"))
          .fontSize(18)
          .textAlign(TextAlign.Center)
          .fontColor($r("app.color.button_color_f86d05"))
          .width('48%')
          .onClick(() => {
            this.newOrEditFolderDialogCtl.close()
            inputMethod.getController().stopInputSession();
          })
        Divider()
          .vertical(true)
          .height(15)
          .strokeWidth(1)
          .color($r("app.color.divider_color_e4e4e4"))
        Text($r("app.string.save"))
          .opacity(this.inputName == ""
                   || (this.oriSelectedColor == this.selectedColor && this.inputName == this.oriInputName && this.dialogType == 1)
                   || (this.isExisted && this.dialogType == 0)
                   || (this.isExisted && this.dialogType == 1 && this.inputName != this.oriInputName) ? 0.4 : 1)
          .enabled(this.inputName == ""
                   || (this.oriSelectedColor == this.selectedColor && this.inputName == this.oriInputName && this.dialogType == 1)
                   || (this.isExisted && this.dialogType == 0)
                   || (this.isExisted && this.dialogType == 1 && this.inputName != this.oriInputName) ? false : true)
          .fontSize(18)
          .textAlign(TextAlign.Center)
          .fontColor($r("app.color.button_color_f86d05"))
          .width('48%')
          .onClick(() => {
            this.newOrEditFolderDialogCtl.close()
            if (this.inputName.replace(/\s+/g, '') == '') {
              return
            } else {
              this.confirm(this.selectedColor, this.inputName)
            }
            inputMethod.getController().stopInputSession();
          })
      }.width('100%')
      .margin({ top: 21, bottom: 25 })
    }
    .width(336)
    .borderRadius(36)
    .backgroundColor($r("app.color.create_folder_bg_color"))
    .alignItems(HorizontalAlign.Start)
    .margin({ bottom: 16, left: 12, right: 12 })
  }

  aboutToAppear(): void {
    var currentFolder: FolderData = FolderUtil.getFolderData(this.AllFolderArray, this.editFolderUuid) // 获取当前选中的文件夹
    if (currentFolder == null) {
      return
    }
    if (currentFolder.folder_type == FolderType.CusDef) {
      this.inputName = currentFolder.name
      this.oriInputName = this.inputName
      this.oriSelectedColor = currentFolder.color
    } else {
      GlobalResourceManager.getStringByResource(FolderUtil.getFolderText(currentFolder)).then(result => {
        this.inputName = result
        this.oriInputName = this.inputName
        this.oriSelectedColor = currentFolder.color
      })
    }
  }
}

@Component
struct ColorCircleComp {
  private circleColor: string
  @Consume('SelectedColor') selectedColor: string

  build() {
    Stack({ alignContent: Alignment.Center }) {
      Circle({ width: 24, height: 24 })
        .fill(this.circleColor)
      Circle({ width: 12, height: 12 })
        .fill($r("app.color.color_ffffff"))
        .visibility(this.circleColor == this.selectedColor ? Visibility.Visible : Visibility.None)
    }.onClick(() => {
      try {
        this.selectedColor = this.circleColor
      } catch (error) {
        LogUtil.error(TAG, "selectedColor error: ", error.toString());
      }
    })
  }
}

@CustomDialog
export struct DeleteDialog {
  @StorageLink('CheckedNoteArray') CheckedNoteArray: NoteData[] = []
  @StorageLink('AllNoteArray') AllNoteArray: NoteData[] = AppStorage.Link('AllNoteArray')
  @StorageLink('AllFolderArray') AllFolderArray: FolderData[] = AppStorage.Link('AllFolderArray')
  @Consume('SelectedNoteData') selectedNoteData: NoteData
  @Consume('SelectedFolderData') selectedFolderData: FolderData
  private multiSelect: boolean = false
  private deleteFileType = DeleteFileType.NoteData
  noteDataDeleteDialogCtl: CustomDialogController
  onConfirm: () => void

  build() {
    Flex({ direction: FlexDirection.Column, justifyContent: FlexAlign.SpaceBetween }) {
      Flex({ justifyContent: FlexAlign.Center, alignItems: ItemAlign.Center }) {
        if (this.deleteFileType == DeleteFileType.FolderData) {
          Text($r("app.string.delete_tips"))
            .fontSize(14)
            .textAlign(TextAlign.Center)
            .maxLines(1)
        } else {
          Text(this.selectedFolderData.uuid == SysDefFolderUuid.RecentDeletes ? $r("app.string.deleteNoteComplete") : $r("app.string.deleteNote"))
            .fontSize(14)
            .textAlign(TextAlign.Center)
            .maxLines(1)
            .visibility(this.multiSelect == false || this.selectedFolderData.uuid == SysDefFolderUuid.RecentDeletes ? Visibility.Visible : Visibility.None)
          if (this.CheckedNoteArray.length ==
          NoteUtil.getNoteDataArray(this.AllNoteArray, this.selectedFolderData.uuid).length) {
            Text($r("app.string.deleteAllNote"))
              .fontSize(14)
              .textAlign(TextAlign.Center)
              .maxLines(1)
              .visibility(this.multiSelect == false || this.selectedFolderData.uuid == SysDefFolderUuid.RecentDeletes ? Visibility.None : Visibility.Visible)
          } else if (this.CheckedNoteArray.length > 1) {
            Text($r("app.string.deletePartNote", this.CheckedNoteArray.length))
              .fontSize(14)
              .textAlign(TextAlign.Center)
              .maxLines(1)
              .visibility(this.multiSelect == false || this.selectedFolderData.uuid == SysDefFolderUuid.RecentDeletes ? Visibility.None : Visibility.Visible)
          } else {
            Text($r("app.string.deleteNote"))
              .fontSize(14)
              .textAlign(TextAlign.Center)
              .maxLines(1)
              .visibility(this.multiSelect == false || this.selectedFolderData.uuid == SysDefFolderUuid.RecentDeletes ? Visibility.None : Visibility.Visible)
          }
        }
      }
      .width(288)
      .height(28.5)

      Flex({ justifyContent: FlexAlign.Center, alignItems: ItemAlign.Center }) {
        Text($r("app.string.cancel"))
          .fontSize(16)
          .fontColor($r("app.color.button_color_f86d05"))
          .textAlign(TextAlign.Center)
          .maxLines(1)
          .width('50%')
          .height('100%')
          .onClick(() => {
            this.noteDataDeleteDialogCtl.close()
          })
        Divider()
          .vertical(true)
          .strokeWidth(1)
          .color($r("app.color.divider_color_e4e4e4"))
          .height(40)
        Text($r("app.string.delete"))
          .fontSize(16)
          .fontColor($r("app.color.delete_color_fa2a2d"))
          .textAlign(TextAlign.Center)
          .maxLines(1)
          .width('50%')
          .height('100%')
          .onClick(() => {
            this.noteDataDeleteDialogCtl.close()
            this.onConfirm()
          })
      }
      .width('100%')
      .height('50%')
    }
    .width(336)
    .height(117)
    .borderRadius(36)
    .padding({ top: 24, bottom: 16, left: 16, right: 16 })
    .backgroundColor($r("app.color.delete_note_bg_color"))
    .margin({ bottom: 16, left: 12, right: 12 })
  }
}

@Component
struct NoteDataMoveItemComp {
  @StorageLink('CheckedNoteArray') CheckedNoteArray: NoteData[] = []
  @StorageLink('AllFolderArray') AllFolderArray: FolderData[] = []
  private folderItem: FolderData
  dividerShow: boolean = true

  build() {
    Flex({ alignItems: ItemAlign.Center, wrap: FlexWrap.NoWrap }) {
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
            .textAlign(TextAlign.Center)
            .maxLines(1)
            .textOverflow({ overflow: TextOverflow.Ellipsis })
            .flexShrink(1)
            .fontWeight(FontWeight.Medium)
          Image((FolderUtil.getCommonFolder(this.AllFolderArray, this.CheckedNoteArray) == null
          || FolderUtil.getCommonFolder(this.AllFolderArray, this.CheckedNoteArray) != this.folderItem) ? $r("app.media.foldMove_unselect") : $r("app.media.foldMove_select"))
            .objectFit(ImageFit.Fill)
            .width(24)
            .height(24)
            .flexShrink(0)
        }
        .width(248)
        .height(55)

        if (this.dividerShow) {
          Divider()
            .color($r("app.color.divider_color_e4e4e4"))
            .strokeWidth(1)
        }

      }
      .padding({ left: 16 })
    }
    .width(288)
    .height(56)
    .visibility(FolderUtil.isFolderMoveIn(this.folderItem) ? Visibility.Visible : Visibility.None)
  }
}

@CustomDialog
export struct NoteDataMoveDialog {
  noteDataMoveDialogCtl: CustomDialogController
  onConfirm: (folderUuid: string) => void
  NoteDataMoveArray: FolderData[]
  @StorageLink('AllFolderArray') AllFolderArray: FolderData[] = []

  aboutToAppear() {
    this.NoteDataMoveArray = this.AllFolderArray.slice(2, this.AllFolderArray.length);
    if (this.AllFolderArray[1] === undefined || this.AllFolderArray[1] === null) {
      LogUtil.info(TAG, "this AllFolderArray[1] undefined")
      return
    }
    this.NoteDataMoveArray.push(this.AllFolderArray[1]);
  }

  build() {
    Flex({ direction: FlexDirection.Column, alignItems: ItemAlign.Center, wrap: FlexWrap.NoWrap }) {
      Flex({ alignItems: ItemAlign.Center }) {
        Text($r("app.string.chooseFolder"))
          .fontSize(20)
          .fontWeight(600)
          .fontWeight(FontWeight.Medium)
      }.height(56)
      .width(288)

      List() {
        if (this.NoteDataMoveArray !== undefined && this.NoteDataMoveArray !== null && this.NoteDataMoveArray !== []) {
          ForEach(this.NoteDataMoveArray.slice(0, this.NoteDataMoveArray.length - 1), (item) => {
            ListItem() {
              NoteDataMoveItemComp({ folderItem: item })
            }
            .onClick(() => {
              this.noteDataMoveDialogCtl.close()
              this.onConfirm(item.uuid)
            })
          }, noteItem => noteItem.uuid)
        }
        ListItem() {
          NoteDataMoveItemComp({
            folderItem: this.NoteDataMoveArray[this.NoteDataMoveArray.length - 1],
            dividerShow: false
          })
        }
        .onClick(() => {
          this.noteDataMoveDialogCtl.close()
          this.onConfirm(this.NoteDataMoveArray[this.NoteDataMoveArray.length - 1].uuid)
        })
      }.listDirection(Axis.Vertical)
      .edgeEffect(EdgeEffect.Spring)
      .height(this.AllFolderArray.length > 12 ? 504 : (this.AllFolderArray.length - 3) * 56)

      Flex({ alignItems: ItemAlign.Center, justifyContent: FlexAlign.Center }) {
        Text($r("app.string.cancel"))
          .fontSize(16)
          .fontColor($r("app.color.button_color_f86d05"))
          .onClick(() => {
            this.noteDataMoveDialogCtl.close()
          })
      }.height(56)
      .width(288)
    }
    .width(336)
    .borderRadius(36)
    .height(this.AllFolderArray.length > 12 ? 616 : (this.AllFolderArray.length - 1) * 56)
    .padding({ left: 24, right: 24 })
    .backgroundColor($r("app.color.choose_folder_bg_color"))
    .margin({ bottom: 16, left: 12, right: 12 })
  }
}

let inSetValue = AppStorage.Link('inSetValue')

@CustomDialog
export struct EditContentDialog {
  editContentDialogCtl: CustomDialogController
  confirm: (excuteJs: string) => void
  @State selectFontColor: string = fontColorArray[0]
  @Consume('SelectedNoteData') selectedNoteData: NoteData
  private circleColor: string
  private fontSize: number

  aboutToAppear() {
    this.confirm("javascript:RICH_EDITOR.getFontSizes()")
  }

  build() {
    Row() {
      Column() {
        Row({ space: 70 }) {
          Button({ type: ButtonType.Normal }) {
            Image($r('app.media.action_bold'))
              .height(24)
              .width(24)
              .onClick(() => {
                this.confirm("javascript:RICH_EDITOR.setBold()")
              })
          }.width(42)
          .height(42)
          .borderRadius(8)
          .backgroundColor($r('app.color.color_ffffff'))

          Button({ type: ButtonType.Normal }) {
            Image($r('app.media.format_italic'))
              .height(24)
              .width(24)
              .onClick(() => {
                this.confirm("javascript:RICH_EDITOR.setItalic()")
              })
          }.width(42)
          .height(42)
          .borderRadius(8)
          .backgroundColor($r('app.color.color_ffffff'))

          Button({ type: ButtonType.Normal }) {
            Image($r('app.media.underline'))
              .height(24)
              .width(24)
              .onClick(() => {
                this.confirm("javascript:RICH_EDITOR.setUnderline()")
              })
          }.width(42)
          .height(42)
          .borderRadius(8)
          .backgroundColor($r('app.color.color_ffffff'))

          Button({ type: ButtonType.Normal }) {
            Image($r('app.media.left_justify'))
              .height(24)
              .width(24)
              .onClick(() => {
                this.confirm("javascript:RICH_EDITOR.setJustifyLeft()")
              })
          }.width(42)
          .height(42)
          .borderRadius(8)
          .backgroundColor($r('app.color.color_ffffff'))

          Button({ type: ButtonType.Normal }) {
            Image($r('app.media.mid_justify'))
              .height(24)
              .width(24)
              .onClick(() => {
                this.confirm("javascript:RICH_EDITOR.setJustifyCenter()")
              })
          }.width(42)
          .height(42)
          .borderRadius(8)
          .backgroundColor($r('app.color.color_ffffff'))

          Button({ type: ButtonType.Normal }) {
            Image($r('app.media.right_justify'))
              .height(24)
              .width(24)
              .onClick(() => {
                this.confirm("javascript:RICH_EDITOR.setJustifyRight()")
              })
          }.width(42)
          .height(42)
          .borderRadius(8)
          .backgroundColor($r('app.color.color_ffffff'))
        }
        .alignItems(VerticalAlign.Bottom)
        .padding({ bottom: 2 })
        .height(71)

        Divider()
          .vertical(false)
          .color($r("app.color.divider_color_e4e4e4"))

        Row({ space: 70 }) {
          Button({ type: ButtonType.Normal }) {
            Image($r('app.media.suojin'))
              .height(24)
              .width(24)
              .onClick(() => {
                this.confirm("javascript:RICH_EDITOR.setIndent()")
              })
          }.width(42)
          .height(42)
          .borderRadius(8)
          .backgroundColor($r('app.color.color_ffffff'))

          Button({ type: ButtonType.Normal }) {
            Image($r('app.media.suojin_back'))
              .height(24)
              .width(24)
              .responseRegion({ x: -15.0, y: -15.0, width: 54, height: 54 })
              .onClick(() => {
                this.confirm("javascript:RICH_EDITOR.setOutdent()")
              })
          }.width(42)
          .height(42)
          .borderRadius(8)
          .backgroundColor($r('app.color.color_ffffff'))

          Button({ type: ButtonType.Normal }) {
            Image($r("app.media.format_menulist_number"))
              .height(24)
              .width(24)
              .onClick(() => {
                this.confirm("javascript:RICH_EDITOR.setNumbers()")
              })
          }.width(42)
          .height(42)
          .borderRadius(8)
          .backgroundColor($r('app.color.color_ffffff'))

          Button({ type: ButtonType.Normal }) {
            Image($r("app.media.format_menulist_alphabet"))
              .height(24)
              .width(24)
              .onClick(() => {
                this.confirm("javascript:RICH_EDITOR.setABC()")
              })
          }.width(42)
          .height(42)
          .borderRadius(8)
          .backgroundColor($r('app.color.color_ffffff'))

          Button({ type: ButtonType.Normal }) {
            Image($r('app.media.format_menubullte2'))
              .height(24)
              .width(24)
              .onClick(() => {
                this.confirm("javascript:RICH_EDITOR.setBullets()")
              })
          }.width(42)
          .height(42)
          .borderRadius(8)
          .backgroundColor($r('app.color.color_ffffff'))

          Button({ type: ButtonType.Normal }) {
            Image($r('app.media.format_menubullte1'))
              .height(24)
              .width(24)
              .onClick(() => {
                this.confirm("javascript:RICH_EDITOR.setSquare()")
              })
          }.width(42)
          .height(42)
          .borderRadius(8)
          .backgroundColor($r('app.color.color_ffffff'))
        }
        .alignItems(VerticalAlign.Top)
        .padding({ top: 2 })
        .height(56)
      }
      .width('50%')
      .padding({ left: 24, right: 24 })
      .height(128)

      Divider()
        .vertical(true)
        .height(128)
        .color($r("app.color.divider_color_e4e4e4"))
        .margin({ top: 4, bottom: 4 })

      Column() {
        Flex({ direction: FlexDirection.Row, wrap: FlexWrap.Wrap, justifyContent: FlexAlign.End }) {
          Image($r('app.media.cross'))
            .height(16)
            .width(16)
            .margin({ top: 8 })
            .opacity(0.6)
            .fillColor('#99182431')
            .onClick(() => {
              this.editContentDialogCtl.close()
            })
        }
        .height(36)

        Row() {
          Flex({ wrap: FlexWrap.NoWrap, justifyContent: FlexAlign.SpaceBetween }) {
            ForEach(fontColorArray, (colorStr: string) => {
              Stack({ alignContent: Alignment.Center }) {
                Circle({ width: 24, height: 24 })
                  .fill(colorStr)
                Circle({ width: 12, height: 12 })
                  .fill($r("app.color.color_ffffff"))
                  .visibility(colorStr == this.selectFontColor ? Visibility.Visible : Visibility.None)
              }.onClick(() => {
                this.selectFontColor = colorStr
                this.confirm("javascript:RICH_EDITOR.setTextColor('" + this.selectFontColor + "')")
              })
            }, colorStr => colorStr)
          }.padding({ bottom: 11 })
        }
        .alignItems(VerticalAlign.Top)
        .height(35)

        Divider()
          .vertical(false)
          .color($r("app.color.divider_color_e4e4e4"))

        Row({ space: 15 }) {
          Image($r('app.media.font_small'))
            .height(24)
            .width(24)
            .margin({ top: 8 })
          Slider({
            value: this.selectedNoteData.slider_value,
            min: 0,
            max: 16,
            step: 4,
            style: SliderStyle.InSet
          })
            .blockColor($r("app.color.color_ffffff"))
            .trackColor($r("app.color.divider_color_e4e4e4"))
            .selectedColor($r("app.color.text_color_f86d05"))
            .showSteps(false)
            .showTips(false)
            .onChange((value: number, mode: SliderChangeMode) => {
              this.selectedNoteData.slider_value = value
              this.fontSize = value + 12
              this.confirm("javascript:RICH_EDITOR.execFontSize('" + this.fontSize + "')")
              LogUtil.info(TAG, 'value:' + value + 'mode:' + mode.toString())
            })
            .width('88%')
          Image($r('app.media.font_large'))
            .height(24)
            .width(24)
            .margin({ top: 7 })
        }
        .alignItems(VerticalAlign.Top)
        .padding({ top: 5 })
        .height(56)
      }
      .width('50%')
      .height(128)
      .padding({ left: 24, right: 24 })
    }
    .width('100%')
    .height(128)
    .backgroundColor($r("app.color.color_ffffff"))
    .borderRadius(36)
  }
}

@CustomDialog
export struct EditTitleDialog {
  editTitleDialog: CustomDialogController
  confirm: (newTitle: string) => void
  @State inputName: string = ""
  @State isEquivalentVal: boolean = true

  build() {
    Column() {
      Text($r("app.string.editNoteTitle"))
        .fontSize(20)
        .height(56)
        .margin({ left: 24 })

      // title input
      Flex({ wrap: FlexWrap.NoWrap, justifyContent: FlexAlign.SpaceBetween }) {
        TextInput({ text: this.inputName, placeholder: $r("app.string.input_placeholder") })
          .placeholderFont({ size: 18 })
          .maxLength(20)
          .borderRadius(15)
          .backgroundColor($r("app.color.title_input_bg_color"))
          .width('90%')
          .onChange((value: string) => {
            if (this.inputName == value) {
              this.isEquivalentVal = true
            } else {
              this.isEquivalentVal = false
            }
            this.inputName = value
          })
          .restoreId(2)
      }.margin({ bottom: 4, left: 24, right: 24 })


      // button group
      Flex({ wrap: FlexWrap.Wrap, justifyContent: FlexAlign.SpaceBetween }) {
        Text($r("app.string.cancel"))
          .fontSize(18)
          .textAlign(TextAlign.Center)
          .fontColor($r("app.color.button_color_419fff"))
          .width('48%')
          .onClick(() => {
            this.editTitleDialog.close()
            inputMethod.getController().stopInputSession();
          })
        Divider()
          .vertical(true)
          .height(15)
          .strokeWidth(1)
          .color($r("app.color.divider_color_e4e4e4"))
        Text($r("app.string.save"))
          .opacity(this.isEquivalentVal ? 0.4 : 1)
          .enabled(this.isEquivalentVal ? false : true)
          .fontSize(18)
          .textAlign(TextAlign.Center)
          .fontColor($r("app.color.button_color_419fff"))
          .width('48%')
          .onClick(() => {
            this.editTitleDialog.close()
            inputMethod.getController().stopInputSession();
            if (this.inputName.replace(/\s+/g, '') == '') {
              return
            } else {
              this.confirm(this.inputName)
            }
          })
      }.width('100%')
      .margin({ top: 21, bottom: 25 })
    }
    .width(336)
    .borderRadius(36)
    .backgroundColor($r("app.color.Edit_title_bg_color"))
    .alignItems(HorizontalAlign.Start)
    .margin({ bottom: 16, left: 12, right: 12 })
  }
}

@CustomDialog
export struct EditContentDialogPortrait {
  editContentDialogCtl: CustomDialogController;
  confirm: (excuteJs: string) => void
  @State selectFontColor: string = fontColorArray[0]
  @Consume('SelectedNoteData') selectedNoteData: NoteData
  private circleColor: string
  private fontSize: number

  aboutToAppear() {
    try {
      this.confirm("javascript:RICH_EDITOR.getFontSizes()");
      LogUtil.info(TAG, `runJavaScript success.`);
    } catch (error) {
      LogUtil.error(TAG, `runJavaScript failed.code:${JSON.stringify(error.code)},message:${JSON.stringify(error.message)}`);
    }
  }

  build() {
    Column() {
      Flex({ direction: FlexDirection.Row, wrap: FlexWrap.NoWrap,
        justifyContent: FlexAlign.SpaceBetween, alignItems: ItemAlign.Center }) {
        Text($r("app.string.style")).margin({ top: 8 })
          .fontSize(14).fontColor($r("app.color.font_stylecolor_AD182431"))

        Image($r('app.media.cross'))
          .height(16)
          .width(16)
          .margin({ top: 8 })
          .fillColor($r("app.color.font_stylecolor_AD182431"))
          .onClick(() => {
            this.editContentDialogCtl.close()
          })
      }
      .height(48)
      .padding({ left: 24, right: 24 })


      Row({ space: 16 }) {
        Button({ type: ButtonType.Normal }) {
          Image($r('app.media.action_bold'))
            .height(24)
            .width(24)
            .onClick(() => {
              this.confirm("javascript:RICH_EDITOR.setBold()")
            })
        }.width(42)
        .height(42)
        .borderRadius(8)
        .backgroundColor($r('app.color.color_ffffff'))

        Button({ type: ButtonType.Normal }) {
          Image($r('app.media.format_italic'))
            .height(24)
            .width(24)
            .onClick(() => {
              this.confirm("javascript:RICH_EDITOR.setItalic()")
            })
        }.width(42)
        .height(42)
        .borderRadius(8)
        .backgroundColor($r('app.color.color_ffffff'))

        Button({ type: ButtonType.Normal }) {
          Image($r('app.media.underline'))
            .height(24)
            .width(24)
            .onClick(() => {
              this.confirm("javascript:RICH_EDITOR.setUnderline()")
            })
        }.width(42)
        .height(42)
        .borderRadius(8)
        .backgroundColor($r('app.color.color_ffffff'))

        Button({ type: ButtonType.Normal }) {
          Image($r('app.media.right_justify'))
            .height(24)
            .width(24)
            .onClick(() => {
              this.confirm("javascript:RICH_EDITOR.setJustifyRight()")
            })
        }.width(42)
        .height(42)
        .borderRadius(8)
        .backgroundColor($r('app.color.color_ffffff'))

        Button({ type: ButtonType.Normal }) {
          Image($r('app.media.mid_justify'))
            .height(24)
            .width(24)
            .onClick(() => {
              this.confirm("javascript:RICH_EDITOR.setJustifyCenter()")
            })
        }.width(42)
        .height(42)
        .borderRadius(8)
        .backgroundColor($r('app.color.color_ffffff'))

        Button({ type: ButtonType.Normal }) {
          Image($r('app.media.left_justify'))
            .height(24)
            .width(24)
            .onClick(() => {
              this.confirm("javascript:RICH_EDITOR.setJustifyLeft()")
            })
        }.width(42)
        .height(42)
        .borderRadius(8)
        .backgroundColor($r('app.color.color_ffffff'))
      }
      .height(48)

      Divider().vertical(false).color($r("app.color.divider_color_e4e4e4"))

      Row({ space: 16 }) {

        Button({ type: ButtonType.Normal }) {
          Image($r('app.media.suojin'))
            .height(24)
            .width(24)
            .onClick(() => {
              this.confirm("javascript:RICH_EDITOR.setIndent()")
            })
        }.width(42)
        .height(42)
        .borderRadius(8)
        .backgroundColor($r('app.color.color_ffffff'))

        Button({ type: ButtonType.Normal }) {
          Image($r('app.media.suojin_back'))
            .height(24)
            .width(24)
            .responseRegion({ x: -15.0, y: -15.0, width: 54, height: 54 })
            .onClick(() => {
              this.confirm("javascript:RICH_EDITOR.setOutdent()")
            })
        }.width(42)
        .height(42)
        .borderRadius(8)
        .backgroundColor($r('app.color.color_ffffff'))

        Button({ type: ButtonType.Normal }) {
          Image($r("app.media.format_menulist_number"))
            .height(24)
            .width(24)
            .onClick(() => {
              this.confirm("javascript:RICH_EDITOR.setNumbers()")
            })
        }.width(42)
        .height(42)
        .borderRadius(8)
        .backgroundColor($r('app.color.color_ffffff'))

        Button({ type: ButtonType.Normal }) {
          Image($r("app.media.format_menulist_alphabet"))
            .height(24)
            .width(24)
            .onClick(() => {
              this.confirm("javascript:RICH_EDITOR.setABC()")
            })
        }.width(42)
        .height(42)
        .borderRadius(8)
        .backgroundColor($r('app.color.color_ffffff'))

        Button({ type: ButtonType.Normal }) {
          Image($r('app.media.format_menubullte2'))
            .height(24)
            .width(24)
            .onClick(() => {
              this.confirm("javascript:RICH_EDITOR.setBullets()")
            })
        }.width(42)
        .height(42)
        .borderRadius(8)
        .backgroundColor($r('app.color.color_ffffff'))

        Button({ type: ButtonType.Normal }) {
          Image($r('app.media.format_menubullte1'))
            .height(24)
            .width(24)
            .onClick(() => {
              this.confirm("javascript:RICH_EDITOR.setSquare()")
            })
        }.width(42)
        .height(42)
        .borderRadius(8)
        .backgroundColor($r('app.color.color_ffffff'))
      }
      .height(48)

      Divider().vertical(false).color($r("app.color.divider_color_e4e4e4"))

      Row() {
        Flex({ wrap: FlexWrap.NoWrap, justifyContent: FlexAlign.SpaceBetween }) {
          ForEach(fontColorArray, (colorStr: string) => {
            Stack({ alignContent: Alignment.Center }) {
              Circle({ width: 24, height: 24 }).fill(colorStr)
              Circle({ width: 12, height: 12 }).fill($r("app.color.color_ffffff"))
                .visibility(colorStr == this.selectFontColor ? Visibility.Visible : Visibility.None)
            }.onClick(() => {
              this.selectFontColor = colorStr
              this.confirm("javascript:RICH_EDITOR.setTextColor('" + this.selectFontColor + "')")
            })
          }, colorStr => colorStr)
        }
      }
      .height(48)
      .padding({ left: 24, right: 24 })

      Divider().vertical(false).color($r("app.color.divider_color_e4e4e4"))

      Row({ space: 10 }) {
        Image($r('app.media.font_small')).height(24).width(24).margin({ top: 8 })
        Slider({
          value: this.selectedNoteData.slider_value,
          min: 0,
          max: 16,
          step: 4,
          style: SliderStyle.InSet
        })
          .blockColor($r("app.color.color_ffffff"))
          .trackColor($r("app.color.divider_color_e4e4e4"))
          .selectedColor($r("app.color.text_color_f86d05"))
          .showSteps(false)
          .showTips(false)
          .onChange((value: number, mode: SliderChangeMode) => {
            this.selectedNoteData.slider_value = value
            this.fontSize = value + 12
            this.confirm("javascript:RICH_EDITOR.execFontSize('" + this.fontSize + "')")
            LogUtil.info(TAG, 'value:' + value + 'mode:' + mode.toString())
          })
          .width('79%')
        Image($r('app.media.font_large')).height(24).width(24).margin({ top: 7 })
      }
      .alignItems(VerticalAlign.Top)
      .padding({ top: 5 })
      .height(72)
      .padding({ left: 24, right: 24 })
    }
    .width(360)
    .height(266)
    .backgroundColor($r("app.color.color_ffffff"))
    .borderRadius(36)
  }
}