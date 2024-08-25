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
import FolderData from '@ohos/utils/src/main/ets/default/model/databaseModel/FolderData'
import NoteData from '@ohos/utils/src/main/ets/default/model/databaseModel/NoteData'
import {
  TableName,
  NoteTableColumn,
  SysDefFolderUuid,
  Favorite,
  Delete,
  Top,
  NoteType
} from '@ohos/utils/src/main/ets/default/model/databaseModel/EnumData'
import { NoteDataMoveDialog, DeleteDialog } from './CusDialogComp'
import RdbStoreUtil from '@ohos/utils/src/main/ets/default/baseUtil/RdbStoreUtil'
import prompt from '@system.prompt'
import NoteUtil from '@ohos/utils/src/main/ets/default/baseUtil/NoteUtil'
import FolderUtil from '@ohos/utils/src/main/ets/default/baseUtil/FolderUtil'
import SearchModel from '@ohos/utils/src/main/ets/default/model/searchModel/SearchModel'
import { LogUtil } from '@ohos/utils/src/main/ets/default/baseUtil/LogUtil'
import router from '@ohos.router';
import inputMethod from '@ohos.inputMethod';

const TAG = "NoteListComp"

function routePage() {
  let options = {
    url: 'pages/NoteContentHome'
  }
  try {
    router.pushUrl(options)
  } catch (err) {
    LogUtil.info(TAG, "fail callback")
  }
}

abstract class BasicDataSource<T> implements IDataSource {
  private listeners: DataChangeListener[] = [];

  public abstract totalCount(): number;

  public getData(index: number): T | void {
    LogUtil.info(TAG, 'getDataindex: '+index);
  };

  registerDataChangeListener(listener: DataChangeListener): void {
    if (this.listeners.indexOf(listener) < 0) {
      this.listeners.push(listener);
    };
  };

  unregisterDataChangeListener(listener: DataChangeListener): void {
    const pos = this.listeners.indexOf(listener);
    if (pos >= 0) {
      this.listeners.splice(pos, 1);
    };
  };

  notifyDataReload(): void {
    this.listeners.forEach((listener: DataChangeListener) => {
      listener.onDataReloaded();
    });
  };

  notifyDataAdd(index: number): void {
    this.listeners.forEach((listener: DataChangeListener) => {
      listener.onDataAdd(index);
    });
  };

  notifyDataChange(index: number): void {
    this.listeners.forEach((listener: DataChangeListener) => {
      listener.onDataChange(index);
    });
  };

  notifyDataDelete(index: number): void {
    this.listeners.forEach((listener: DataChangeListener) => {
      listener.onDataDelete(index);
    });
  };

  notifyDataMove(from: number, to: number): void {
    this.listeners.forEach((listener: DataChangeListener) => {
      listener.onDataMove(from, to);
    });
  };
};

class noteListData extends BasicDataSource<NoteData> {
  private noteList: Array<NoteData> = [];

  public totalCount(): number {
    return this.noteList.length;
  };

  public getData(index: number): NoteData {
    LogUtil.info(TAG, 'getData, index=' + index);
    return this.noteList[index];
  };

  public addData(index: number, data: NoteData): void {
    this.noteList.splice(index, 0, data);
    this.notifyDataAdd(index);
  };

  public pushData(data: NoteData): void {
    this.noteList.push(data);
    this.notifyDataAdd(this.noteList.length - 1);
  };

  // 查找列表中对象的index
  public indexOf(data: NoteData): number {
    LogUtil.info(TAG, `indexOf data , id = ${data.id} , name = ${data.title}`);
    return this.noteList.indexOf(data);
  };

  // 删除列表中处于index位置的对象
  public deleteDataByIndex(index: number): void {
    LogUtil.info(TAG, `delete data , index = ${index}}`);
    this.noteList.splice(index, 1);
    this.notifyDataDelete(index);
  };

  // 删除列表中的对象
  public deleteData(data: NoteData): void {
    LogUtil.info(TAG, `delete data , data = ${data.id}}`);
    let index = this.indexOf(data);
    this.deleteDataByIndex(index);
  };

  // 修改列表中所有对象
  public modifyAllData(data: NoteData[]): void {
    LogUtil.info(TAG, `all data modified`);
    this.noteList = data;
    this.notifyDataReload();
  }
};

// Note list component
@Component
export struct NoteListComp {
  @StorageLink('AllFolderArray') AllFolderArray: FolderData[] = AppStorage.Link('AllFolderArray')
  @Consume('SelectedFolderData') selectedFolderData: FolderData
  @Consume('Search') search: boolean
  controllerShow: WebviewController
  @Consume('AsideWidth') asideWidth: number

  build() {
    Flex({ direction: FlexDirection.Column }) {
      Flex({ direction: FlexDirection.Column }) {
        NoteOverViewComp({ controllerShow: this.controllerShow })
        Column() {
        }
        .height(this.search ? 15 : 0)

        NoteItemListComp({ controllerShow: this.controllerShow })
      }
      .width('100%')
      .flexShrink(1)

      Column() {
        OperateNoteCompForPortrait()
      }
      .flexShrink(0)
    }
    .height('100%')
    .width('100%')
  }

  aboutToAppear(): void {
    AppStorage.SetOrCreate('isUpdate', false)
    LogUtil.info(TAG, "aboutToAppear")
  }

  aboutToDisappear(): void {
    LogUtil.info(TAG, "aboutToDisappear")
  }
}

@Component
struct NoteOverViewComp {
  @StorageLink('AllNoteArray') AllNoteArray: NoteData[] = AppStorage.Link('AllNoteArray')
  @StorageLink('breakPoint') breakPoints: string = AppStorage.Get('breakPoint')
  @StorageLink('CheckedNoteArray') CheckedNoteArray: NoteData[] = []
  @Consume('SelectedFolderData') selectedFolderData: FolderData
  @Consume('RefreshFlag') refreshFlag: number
  @Consume('SectionStatus') sectionStatus: number
  @Consume("Longpress") longpress: boolean
  @Consume('ExpandStatus') expandStatus: boolean
  @Consume('Search') search: boolean
  @Consume('PortraitModel') portraitModel: boolean
  controllerShow: WebviewController
  @State noteNumber: number = undefined
  @StorageLink('isUpdate') @Watch('notesNumberChange') isUpdate: boolean = false
  @Consume('AsideWidth') asideWidth: number
  @State isShow: boolean = false

  notesNumberChange() {
    let noteNumbers = FolderUtil.getNoteCount(AppStorage.Get('AllNoteArray'), this.selectedFolderData.uuid)
    if (noteNumbers == 0) {
      this.isShow = false
    } else {
      this.isShow = true
    }
  }

  build() {
    Flex({ justifyContent: FlexAlign.SpaceBetween, alignItems: ItemAlign.Center }) {
      Flex({ direction: FlexDirection.Row, alignItems: ItemAlign.Center }) {
        Column() {
          Image($r("app.media.suojin_back"))
            .height(24)
            .width(24)
            .responseRegion({
              x: -15.0,
              y: -15.0,
              width: 54,
              height: 54
            })
            .margin({ right: 24 }) // 两分栏时缩进图片与右边有个24的间距
            .visibility(this.breakPoints == 'lg' && this.sectionStatus == 3 ? Visibility.None : Visibility.Visible)
            .onClick(() => {
              if (this.breakPoints == 'sm' || this.breakPoints == 'md') {
                animateTo({ duration: 200 }, () => {
                  this.expandStatus = !this.expandStatus
                })
              } else {
                this.asideWidth = 200
                this.sectionStatus = (this.sectionStatus == 3 ? 2 : 3)
                // save continue data
                AppStorage.SetOrCreate<number>('ContinueSection', this.sectionStatus)
                LogUtil.info(TAG, "NoteOverViewComp, set continue section success")
              }
            })
        }.alignItems(HorizontalAlign.Center)

        Flex({
          direction: FlexDirection.Column,
          wrap: FlexWrap.Wrap,
          justifyContent: FlexAlign.Center,
          alignItems: ItemAlign.Start
        }) {
          Text(FolderUtil.getFolderText(this.selectedFolderData))
            .id(this.isUpdate + '')
            .maxLines(1)
            .fontSize(30)
            .fontColor($r("app.color.all_notes_font_color"))
            .fontWeight(FontWeight.Medium)
            .textOverflow({ overflow: TextOverflow.Ellipsis })
          Row() {
            Text(FolderUtil.getNoteCount(AppStorage.Get('AllNoteArray'), this.selectedFolderData.uuid).toString())
              .id(this.isUpdate + '')
              .maxLines(1)
              .fontSize(14)
              .fontColor($r("app.color.num_of_notes_font_color"))
            Text($r("app.string.noteslist"))
              .fontSize(14)
              .fontColor($r("app.color.num_of_notes_font_color"))
              .textOverflow({ overflow: TextOverflow.Ellipsis })
          }
          .margin({ top: 5 })
          .visibility(this.isShow ? Visibility.Visible : Visibility.None)
        }.visibility(this.longpress ? Visibility.None : Visibility.Visible)

        Row() {
          Image($r("app.media.cross"))
            .height(24)
            .width(24)
            .responseRegion({
              x: -15.0,
              y: -15.0,
              width: 54,
              height: 54
            })
            .onClick(() => {
              this.longpress = false
              this.refreshFlag = (this.refreshFlag == 0 ? 1 : 0)
              NoteUtil.unsetAllNotesChecked(this.CheckedNoteArray)
            })
          Text(this.CheckedNoteArray.length == 0 ? $r("app.string.none_selected") : $r("app.string.selected", this.CheckedNoteArray.length))
            .fontSize(20)
            .fontColor($r("app.color.note_selected_font_color"))
            .margin({ left: 16 })
            .textOverflow({ overflow: TextOverflow.Ellipsis })
            .fontWeight(FontWeight.Medium)
        }.alignItems(VerticalAlign.Center)
        .visibility(this.longpress ? Visibility.Visible : Visibility.None)
      }.padding({ top: 8, bottom: 8 })
      .height('100%')

      AddNoteComp({ controllerShow: this.controllerShow })
      OperateNoteComp({ controllerShow: this.controllerShow })
      Text(this.refreshFlag.toString()).visibility(Visibility.None)
    }
    .width('100%')
    .height(82)
    .padding({
      left: this.sectionStatus == 2 ? 24 : 36,
      right: 24
    }) // 两分栏时缩进图标与左侧不需要间距
    .visibility(this.search ? Visibility.None : Visibility.Visible)
  }
}

@Component
export struct NoteItemComp {
  public noteItem: NoteData
  public spans: any[]
  controllerShow: WebviewController
  @Consume('SelectedFolderData') selectedFolderData: FolderData
  @Consume('SelectedNoteData') selectedNoteData: NoteData
  @StorageLink('AllFolderArray') AllFolderArray: FolderData[] = AppStorage.Link('AllFolderArray')
  @StorageLink('CheckedNoteArray') CheckedNoteArray: NoteData[] = []
  @Consume('ChooseNote') chooseNote: boolean
  @Consume('RefreshFlag') refreshFlag: number
  @Consume('Search') search: boolean
  @Consume('selectedAll') selectedAll: boolean
  @Consume('PortraitModel') portraitModel: boolean
  @State isChecked: boolean = undefined
  @Consume('Longpress') @Watch('isLongPress') longpress: boolean
  @StorageLink('isUpdate') isUpdate: boolean = false

  isLongPress() {
    if (this.longpress) {
      this.isChecked = false
    }
  }

  updateAndGetChecked() {
    this.isChecked = NoteUtil.isNoteChecked(this.CheckedNoteArray, this.noteItem)
    return this.isChecked
  }

  build() {
    Flex({ justifyContent: FlexAlign.SpaceBetween, alignItems: ItemAlign.Center }) {
      Flex({ direction: FlexDirection.Row, alignItems: ItemAlign.Center }) {
        Text(JSON.stringify(this.refreshFlag)).visibility(Visibility.None) // 用于强制刷新使用
        Column({ space: 2 }) {
          Row({ space: 8 }) {
            Image($r("app.media.verticalBar"))
              .id(this.isUpdate + '')
              .height(16)
              .width(4)
              .fillColor(NoteUtil.getVerticalBarBgColor(AppStorage.Get('AllFolderArray'), this.noteItem.folder_uuid))
            Text(this.noteItem.title)
              .fontSize(16)
              .maxLines(1)
              .textOverflow({ overflow: TextOverflow.Ellipsis })
          }

          Row({ space: 4 }) {
            Text(DateUtil.formateDateForNoteTitle(new Date(this.noteItem.modified_time)))
              .id(this.isUpdate + '')
              .maxLines(1)
              .fontSize(14)
              .fontColor($r("app.color.list_modified_time_font_color"))
              .fontWeight(FontWeight.Regular)
              .textOverflow({ overflow: TextOverflow.Ellipsis })
            Image($r("app.media.favorite"))
              .height(16)
              .width(16)
              .visibility(this.noteItem.is_favorite == Favorite.Yes ? Visibility.Visible : Visibility.None)
            Image($r("app.media.topped"))
              .height(16)
              .width(16)
              .visibility(this.noteItem.is_top == Top.Yes ? Visibility.Visible : Visibility.None)
          }
          .padding({ left: 12 })
        }.alignItems(HorizontalAlign.Start)
      }.flexShrink(1)

      Flex({ justifyContent: FlexAlign.SpaceBetween, alignItems: ItemAlign.Center }) {
        Stack({ alignContent: Alignment.Center }) {
          Image(this.noteItem.content_img)
            .id(this.isUpdate + '')
            .height(47)
            .width(47)
            .borderRadius(12)
            .border({ width: 0.5, color: '#19182431' })
            .visibility(this.noteItem.content_img ? Visibility.Visible : Visibility.None)
        }

        Stack({ alignContent: Alignment.Center }) {
          Image($r("app.media.unChecked"))
            .height(24)
            .width(24)
          Image($r("app.media.checked"))
            .width(24)
            .height(24)
            .visibility(this.updateAndGetChecked() ? Visibility.Visible : Visibility.None)
            .id(this.isUpdate + '')
        }.width(24)
        .height(24)
        .visibility(this.longpress ? Visibility.Visible : Visibility.None)
      }
      .flexShrink(0)
      .height(48)
      .width(this.longpress ? 80 : 48)
    }
    .width('100%')
    .height(72)
    .padding({
      left: 16,
      right: 12,
      top: 4,
      bottom: 4
    })
    .borderRadius(24)
    .linearGradient({
      direction: GradientDirection.Right,
      colors: this.selectedNoteData?.uuid == this.noteItem.uuid ? [[0xffcdae, 0.0], [0xFfece2, 1.0]] : [[0xffffff, 0.0], [0xffffff, 1.0]]
    })
    .onClick(() => {
      if (this.search) {
        this.search = false
        AppStorage.SetOrCreate<boolean>('Search', this.search)
        return
      }
      if (this.longpress) {
        if (NoteUtil.isNoteChecked(this.CheckedNoteArray, this.noteItem)) {
          NoteUtil.unsetNoteChecked(this.CheckedNoteArray, this.noteItem)
          this.refreshFlag = (this.refreshFlag == 0 ? 1 : 0)
          this.isChecked = NoteUtil.isNoteChecked(this.CheckedNoteArray, this.noteItem)
        } else {
          NoteUtil.setNoteChecked(this.CheckedNoteArray, this.noteItem)
          this.refreshFlag = (this.refreshFlag == 0 ? 1 : 0)
          this.isChecked = NoteUtil.isNoteChecked(this.CheckedNoteArray, this.noteItem)
        }
        return;
      } else {
        this.selectedNoteData = this.noteItem
        this.chooseNote = true
        // save continue data
        let continueNote: string = JSON.stringify(this.selectedNoteData?.toNoteObject())
        AppStorage.SetOrCreate<string>('ContinueNote', continueNote)
        LogUtil.info(TAG, "NoteItemComp, set continue note success")
      }
      if (this.portraitModel == false) {
        this.controllerShow.runJavaScript(
          "RICH_EDITOR.setHtml('" + this.selectedNoteData?.content_text + "')"
        )
        this.controllerShow.runJavaScript(
          "RICH_EDITOR.cancelSelection()"
        )
      }
      if (this.portraitModel == true) {
        AppStorage.SetOrCreate<NoteData>('NewNote', this.selectedNoteData)
        AppStorage.SetOrCreate<FolderData>('NewFolder', this.selectedFolderData)
        routePage()
      }
      this.selectedAll = this.CheckedNoteArray.length ==
      NoteUtil.getNoteDataArray(AppStorage.Get('AllNoteArray'), this.selectedFolderData.uuid).length
      this.refreshFlag = (this.refreshFlag == 0 ? 1 : 0)
    })
    .gesture(
    GestureGroup(GestureMode.Exclusive,
      // 长按：对笔记列表进行操作
    LongPressGesture()
      .onAction(() => {
        if (this.longpress == false) {
          this.longpress = true
          NoteUtil.setNoteChecked(this.CheckedNoteArray, this.noteItem)
          this.isChecked = NoteUtil.isNoteChecked(this.CheckedNoteArray, this.noteItem)
        }
      })
    )
    )

  }
}

@Component
export struct NoteItemListComp {
  @StorageLink('AllNoteArray') AllNoteArray: NoteData[] = AppStorage.Link('AllNoteArray')
  @Consume('SelectedFolderData') selectedFolderData: FolderData
  @Consume('RefreshFlag') refreshFlag: number
  @Consume('Longpress') longpress: boolean
  @Consume('Search') search: boolean
  @Consume @Watch('doSearch') inputKeyword: string
  @Consume('SearchResultList') searchResultList: NoteData[]
  @Consume('SelectedNoteData') selectedNoteData: NoteData
  @Consume('PortraitModel') portraitModel: boolean
  @State @Watch('setNoteListLazy') dateList: NoteData[] = [];
  @State noteList: noteListData = new noteListData();
  controllerShow: WebviewController
  @StorageLink('isUpdate') @Watch('updateList') isUpdate: boolean = false

  updateList() {
    if (this.isUpdate) {
      this.dateList = NoteUtil.getNoteDataArray(AppStorage.Get('AllNoteArray'), this.selectedFolderData.uuid)
    }
    this.isUpdate = false
    this.doSearch()
  }

  aboutToAppear() {
    LogUtil.info(TAG, "inputKeyWord:" + this.inputKeyword)
    this.inputKeyword = ''
    this.dateList = NoteUtil.getNoteDataArray(AppStorage.Get('AllNoteArray'), this.selectedFolderData.uuid)
  }

  doSearch() {
    if (this.inputKeyword.length == 0) {
      this.setNoteListLazy()
      return;
    };
    SearchModel.search(NoteUtil.getNoteDataArray(AppStorage.Get('AllNoteArray'), this.selectedFolderData.uuid), this.inputKeyword)
      .then((result: NoteData[]) => {
        LogUtil.info(TAG, "result size " + result.length.toString())
        this.searchResultList = result
        this.setNoteListLazy()
        if (this.searchResultList.length != 0) {
          this.selectedNoteData = this.searchResultList[0]
        } else {
          this.selectedNoteData = NoteUtil.getFirstNoteData(AppStorage.Get('AllNoteArray'), this.selectedFolderData.uuid)
        }
        if (this.portraitModel == false) {
          this.controllerShow.runJavaScript(
            "RICH_EDITOR.setHtml('" + this.selectedNoteData?.content_text + "')"
          )
        }
        // save continue data
        let continueNote: string = JSON.stringify(this.selectedNoteData?.toNoteObject())
        AppStorage.SetOrCreate<string>('ContinueNote', continueNote)
        LogUtil.info(TAG, "doSearch, set continue note success")
        this.refreshFlag = (this.refreshFlag == 0 ? 1 : 0)
      })
  }

  setNoteListLazy() {
    let noteLazySource: NoteData[];
    this.inputKeyword.length === 0 ? noteLazySource = this.dateList : noteLazySource = this.searchResultList;
    this.noteList.modifyAllData(noteLazySource);
  }

  build() {
    Column() {
      Text(this.refreshFlag.toString()).visibility(Visibility.None)
      Flex() {
        SearchComp()
      }
      .id(this.isUpdate + '')
      .width("100%")
      .padding({ left: 24, right: 24, bottom: 12 })
      .visibility((FolderUtil.getNoteCount(AppStorage.Get('AllNoteArray'), this.selectedFolderData.uuid) == 0) ? Visibility.None : Visibility.Visible)

      Stack() {
        Flex({ direction: FlexDirection.Column }) {
          Flex({ justifyContent: FlexAlign.Center }) {
            Text($r("app.string.permanently_delete_tips"))
              .fontSize(12)
              .fontColor($r("app.color.Recently_delete_prompt_font_color"))
          }
          .padding({ bottom: this.selectedFolderData.uuid == SysDefFolderUuid.RecentDeletes ? 12 : 0 })
          .width('100%')
          .visibility(this.selectedFolderData.uuid == SysDefFolderUuid.RecentDeletes
                      && FolderUtil.getNoteCount(AppStorage.Get('AllNoteArray'), this.selectedFolderData.uuid) > 0 ? Visibility.Visible : Visibility.None)

          Column() {
            List({ initialIndex: 0 }) {
              ListItem() {
                Column({ space: 8 }) {
                  Image($r('app.media.emptyPage'))
                    .width(120)
                    .height(120)
                  Text($r("app.string.Empty_page"))
                    .fontSize(12)
                    .fontColor($r("app.color.Empty_page_font_color"))
                }
              }
              .id(this.isUpdate + '')
              .width('100%')
              .height('100%')
              .padding({ bottom: 120 })
              .visibility((FolderUtil.getNoteCount(AppStorage.Get('AllNoteArray'), this.selectedFolderData.uuid) == 0) ? Visibility.Visible : Visibility.None)
              LazyForEach(this.noteList, (noteItem) => {
                ListItem() {
                  Column() {
                    NoteItemComp({
                      noteItem: noteItem,
                      spans: SearchModel.splitToHighlightText(noteItem.title, this.inputKeyword),
                      controllerShow: this.controllerShow
                    })
                  }
                  .padding({ left: 24, right: 24, bottom: 12 })
                }
                .visibility((FolderUtil.getNoteCount(AppStorage.Get('AllNoteArray'), this.selectedFolderData.uuid) == 0) ? Visibility.None : Visibility.Visible)
              }, noteItem => JSON.stringify(noteItem))
            }
            .id(this.isUpdate + '')
            .margin((FolderUtil.getNoteCount(AppStorage.Get('AllNoteArray'), this.selectedFolderData.uuid) == 0) ? {
                                                                                                                     bottom: 0
                                                                                                                   } : {
                                                                                                                         bottom: 56
                                                                                                                       })
            .layoutWeight(1)
            .listDirection(Axis.Vertical)
            .edgeEffect(EdgeEffect.Spring)
            .cachedCount(10)
          }
          .layoutWeight(1)
          .height("100%")
          .margin({ top: this.search ? 8 : 0 })
        }
        .height("100%")
        .width("100%")

        // search input mask
        Column() {
        }
        .height("100%")
        .width("100%")
        .backgroundColor("#18181A")
        .opacity(0.1)
        .visibility(this.search ? Visibility.Visible : Visibility.Hidden)
      }
    }
    .onClick(() => {
      this.search = false
      inputMethod.getController().stopInputSession()
      AppStorage.SetOrCreate<boolean>('Search', this.search)
    })
  }
}

@Component
export struct OperateNoteComp {
  @Consume('Longpress') longpress: boolean
  @StorageLink('CheckedNoteArray') CheckedNoteArray: NoteData[] = []
  @StorageLink('AllNoteArray') AllNoteArray: NoteData[] = AppStorage.Link('AllNoteArray')
  @Consume('SelectedFolderData') selectedFolderData: FolderData
  @Consume('RefreshFlag') refreshFlag: number
  @Consume('SelectedNoteData') selectedNoteData: NoteData
  @Consume('PortraitModel') portraitModel: boolean
  @Consume('selectedAll') selectedAll: boolean
  @StorageLink('isUpdate') isUpdate: boolean = false
  controllerShow: WebviewController
  noteDataMoveDialogCtl: CustomDialogController = new CustomDialogController({
    builder: NoteDataMoveDialog({ onConfirm: this.onMoveConfirm.bind(this) }),
    alignment: DialogAlignment.Center,
    autoCancel: false,
    customStyle: true,
  })

  aboutToDisappear() {
    this.noteDataMoveDialogCtl = null
    this.noteDataDeleteDialogCtl = null
  }

  onMoveConfirm(folderUuid: string) {
    this.CheckedNoteArray.forEach((noteItem) => {
      noteItem.folder_uuid = folderUuid
      // update note to db
      let predicates_note = RdbStoreUtil.getRdbPredicates(TableName.NoteTable)
      predicates_note.equalTo(NoteTableColumn.Uuid, noteItem.uuid)
      RdbStoreUtil.update(noteItem.toNoteObject(), predicates_note, null)
    })
    this.selectedNoteData = NoteUtil.getFirstNoteData(this.AllNoteArray, this.selectedFolderData.uuid)
    // save continue data
    let continueNote: string = JSON.stringify(this.selectedNoteData?.toNoteObject())
    AppStorage.SetOrCreate<string>('ContinueNote', continueNote)
    LogUtil.info(TAG, "onMoveConfirm, set continue note success")
    if (this.portraitModel == false) {
      this.controllerShow.runJavaScript("RICH_EDITOR.setHtml('" + this.selectedNoteData?.content_text + "')")
    }
    this.longpress = false
    this.refreshFlag = (this.refreshFlag == 0 ? 1 : 0)
    NoteUtil.unsetAllNotesChecked(this.CheckedNoteArray)
    NoteUtil.refreshAll()
  }

  noteDataDeleteDialogCtl: CustomDialogController = new CustomDialogController({
    builder: DeleteDialog({ onConfirm: this.onDeleteConfirm.bind(this), multiSelect: true }),
    alignment: DialogAlignment.Center,
    autoCancel: false,
    customStyle: true,
  })

  onDeleteConfirm() {
    if (this.selectedFolderData.uuid != SysDefFolderUuid.RecentDeletes) {
      this.CheckedNoteArray.forEach((noteItem: NoteData) => {
        noteItem.is_deleted = Delete.Yes
        noteItem.deleted_time = new Date().getTime()
        // update note to db
        let predicates_note = RdbStoreUtil.getRdbPredicates(TableName.NoteTable)
        predicates_note.equalTo(NoteTableColumn.Uuid, noteItem.uuid)
        RdbStoreUtil.update(noteItem.toNoteObject(), predicates_note, null)
      })
    } else {
      this.CheckedNoteArray.forEach((noteItem: NoteData) => {
        NoteUtil.removeNoteData(this.AllNoteArray, noteItem.uuid)
        // delete note from db
        let predicates_note = RdbStoreUtil.getRdbPredicates(TableName.NoteTable)
        predicates_note.equalTo(NoteTableColumn.Uuid, noteItem.uuid)
        RdbStoreUtil.delete(predicates_note, null)
      })
    }
    NoteUtil.unsetAllNotesChecked(this.CheckedNoteArray)
    this.refreshFlag = (this.refreshFlag == 0 ? 1 : 0)
    this.longpress = false
    this.selectedNoteData = NoteUtil.getFirstNoteData(AppStorage.Get('AllNoteArray'), this.selectedFolderData.uuid)
    if (this.portraitModel == false) {
      this.controllerShow.runJavaScript("RICH_EDITOR.setHtml('" + this.selectedNoteData?.content_text + "')")
    }
    // save continue data
    let continueNote: string = JSON.stringify(this.selectedNoteData?.toNoteObject())
    AppStorage.SetOrCreate<string>('ContinueNote', continueNote)
    LogUtil.info(TAG, "OperateNoteComp, set continue note success")
    NoteUtil.refreshAll()
  }

  build() {
    Row() {
      Image($r('app.media.set_top'))
        .width(24)
        .height(24)
        .opacity(this.CheckedNoteArray.length == 0 ? 0.4 : 1)
        .enabled(this.CheckedNoteArray.length == 0 ? false : true)
        .margin({ right: this.selectedFolderData.uuid == SysDefFolderUuid.RecentDeletes ? 0 : 18 })
        .visibility(this.selectedFolderData.uuid == SysDefFolderUuid.RecentDeletes ? Visibility.None : Visibility.Visible)
        .onClick(() => {
          this.CheckedNoteArray.forEach((noteItem) => {
            noteItem.is_top = (noteItem.is_top == Top.Yes) ? Top.No : Top.Yes
            // update note to db
            let predicates_note = RdbStoreUtil.getRdbPredicates(TableName.NoteTable)
            predicates_note.equalTo(NoteTableColumn.Uuid, noteItem.uuid)
            RdbStoreUtil.update(noteItem.toNoteObject(), predicates_note, null)
          })
          this.longpress = false
          NoteUtil.unsetAllNotesChecked(this.CheckedNoteArray)
          NoteUtil.refreshAll()
        })
      Image($r('app.media.move'))
        .width(24)
        .height(24)
        .opacity(this.CheckedNoteArray.length == 0 ? 0.4 : 1)
        .enabled(this.CheckedNoteArray.length == 0 ? false : true)
        .margin({ right: this.selectedFolderData.uuid == SysDefFolderUuid.RecentDeletes ? 0 : 18 })
        .visibility(this.selectedFolderData.uuid == SysDefFolderUuid.RecentDeletes ? Visibility.None : Visibility.Visible)
        .onClick(() => {
          this.noteDataMoveDialogCtl.open()
        })
      Image($r('app.media.delete'))
        .width(24)
        .height(24)
        .margin({ right: 18 })
        .opacity(this.CheckedNoteArray.length == 0 ? 0.4 : 1)
        .enabled(this.CheckedNoteArray.length == 0 ? false : true)
        .onClick(() => {
          this.noteDataDeleteDialogCtl.open()
        })
      Image($r('app.media.recover'))
        .width(24)
        .height(24)
        .opacity(this.CheckedNoteArray.length == 0 ? 0.4 : 1)
        .enabled(this.CheckedNoteArray.length == 0 ? false : true)
        .margin({ right: this.selectedFolderData.uuid == SysDefFolderUuid.RecentDeletes ? 18 : 0 })
        .visibility(this.selectedFolderData.uuid == SysDefFolderUuid.RecentDeletes ? Visibility.Visible : Visibility.None)
        .onClick(() => {
          this.CheckedNoteArray.forEach((noteItem) => {
            noteItem.is_deleted = Delete.No
            noteItem.deleted_time = 0
            let context: any = getContext(this)
            let resource = {
              bundleName: "com.ohos.note",
              moduleName: "default",
              id: $r('app.string.restore').id
            };
            context.resourceManager.getString(resource, (error, value) => {
              if (error != null) {
                LogUtil.error(TAG, "error is " + error);
              } else {
                prompt.showToast({ message: value, duration: 2000 });
              }
            });
            // update note to db
            let predicates_note = RdbStoreUtil.getRdbPredicates(TableName.NoteTable)
            predicates_note.equalTo(NoteTableColumn.Uuid, noteItem.uuid)
            RdbStoreUtil.update(noteItem.toNoteObject(), predicates_note, null)
          })
          this.longpress = false
          NoteUtil.unsetAllNotesChecked(this.CheckedNoteArray)
          NoteUtil.refreshAll()
        })
      Image(this.CheckedNoteArray.length == NoteUtil.getNoteDataArray(AppStorage.Get('AllNoteArray'), this.selectedFolderData.uuid)
        .length ? $r('app.media.check_all1') : $r('app.media.check_all'))
        .width(24)
        .height(24)
        .id(this.isUpdate + '')
        .onClick(() => {
          LogUtil.info(TAG, "select all click")
          if (this.CheckedNoteArray.length <
          NoteUtil.getNoteDataArray(AppStorage.Get('AllNoteArray'), this.selectedFolderData.uuid).length) {
            NoteUtil.setAllNotesChecked(this.CheckedNoteArray, NoteUtil.getNoteDataArray(AppStorage.Get('AllNoteArray'), this.selectedFolderData.uuid))
          } else {
            NoteUtil.unsetAllNotesChecked(this.CheckedNoteArray)
          }
          this.selectedAll = !this.selectedAll
          this.refreshFlag = (this.refreshFlag == 0 ? 1 : 0)
          NoteUtil.refreshAll()
        })
    }
    .width(this.selectedFolderData.uuid == SysDefFolderUuid.RecentDeletes ? 168 : 248)
    .visibility(this.longpress && this.portraitModel == false ? Visibility.Visible : Visibility.None)
  }
}

@Component
export struct AddNoteComp {
  @StorageLink('AllNoteArray') AllNoteArray: NoteData[] = AppStorage.Link('AllNoteArray')
  @Consume('Longpress') longpress: boolean
  @Consume('SelectedFolderData') selectedFolderData: FolderData
  @Consume('SelectedNoteData') selectedNoteData: NoteData
  @Consume('SectionStatus') sectionStatus: number
  @Consume('LastSectionStatus') lastSectionStatus: number
  @Consume('EditModel') editModel: boolean
  @Consume('ChooseNote') chooseNote: boolean
  @Consume('PortraitModel') portraitModel: boolean
  controllerShow: WebviewController

  build() {
    Image($r('app.media.addNote'))
      .width(24)
      .height(24)
      .margin({ right: 12 })
      .responseRegion({ x: -15.0, y: -15.0, width: 54, height: 54 })
      .onClick(() => {
        let noteData
        if (this.selectedFolderData.uuid == SysDefFolderUuid.AllNotes || this.selectedFolderData.uuid == SysDefFolderUuid.MyFavorites) {
          noteData = new NoteData(0, "标题", new Date().getTime() + "", SysDefFolderUuid.UnClassified, "", "", NoteType.SysDef, Top.No, Favorite.No, Delete.No, new Date().getTime(), new Date().getTime(), 0, 0)
        } else {
          noteData = new NoteData(0, "标题", new Date().getTime() + "", this.selectedFolderData.uuid, "", "", NoteType.SysDef, Top.No, Favorite.No, Delete.No, new Date().getTime(), new Date().getTime(), 0, 0)
        }

        this.AllNoteArray.push(noteData)
        RdbStoreUtil.insert(TableName.NoteTable, noteData.toNoteObject(), null)
        LogUtil.info(TAG, 'insert new note is:' + noteData.uuid)

        this.selectedNoteData = noteData
        AppStorage.SetOrCreate<NoteData>('NewNote', noteData)
        if (this.portraitModel == false) {
          this.controllerShow.runJavaScript(
            "RICH_EDITOR.setHtml('" + this.selectedNoteData?.content_text + "')"
          )
        }
        if (this.portraitModel == true) {
          this.editModel = true
        }
        this.chooseNote = true
        // save continue data
        let continueNote: string = JSON.stringify(this.selectedNoteData?.toNoteObject())
        AppStorage.SetOrCreate<FolderData>('NewFolder', this.selectedFolderData)
        AppStorage.SetOrCreate<string>('ContinueNote', continueNote)
        LogUtil.info(TAG, "addNote, set continue note success")
        AppStorage.SetOrCreate('isUpdate', true)
        routePage()
      })
      .visibility(this.longpress || this.selectedFolderData.uuid == SysDefFolderUuid.RecentDeletes ? Visibility.None : Visibility.Visible)
  }
}

@Component
export struct SearchComp {
  @Consume('Search') search: boolean
  @Consume('InputKeyword') inputKeyword: string
  @Consume('Longpress') longpress: boolean
  @State text: string = ''
  @StorageLink('isFocusOnSearch') isFocusOnSearch: boolean = true

  build() {
    Row() {
      Image($r('app.media.back'))
        .width(24)
        .height(24)
        .responseRegion({ x: -15.0, y: -15.0, width: 54, height: 54 })
        .margin({ right: this.search ? 16 : 0 })
        .visibility(this.search ? Visibility.Visible : Visibility.None)
        .onClick(() => {
          focusControl.requestFocus('searchFocus')
          this.search = false
          // 退出键盘
          // @ts-ignore
          inputMethod.getController().stopInputSession();
          AppStorage.SetOrCreate<boolean>('Search', this.search)
        })

      Flex({ justifyContent: FlexAlign.Start }) {
        Image($r('app.media.search'))
          .width(20)
          .height(20)
          .focusable(true)
          .key('searchFocus')
          .defaultFocus(true)
        TextInput({ placeholder: $r('app.string.searchNote'), text: this.text })
          .backgroundColor(this.longpress ? $r("app.color.search_longpress_bgcolor_f7f8f9") : $r("app.color.color_ffffff"))
          .caretColor($r("app.color.search_note_caret_color"))
          .enabled(this.longpress ? false : true)
          .padding({ left: 6, top: 0, bottom: 0, right: 0 })
          .onEditChange((isEditing: boolean) => {
            //            this.search = isEditing
          })
          .onChange((value: string) => {
            if (!this.longpress) {
              LogUtil.info(TAG, "Search value: " + value)
              this.text = value
              this.inputKeyword = value
            }
          })
          .onClick(() => {
            if (this.longpress) {
              this.search = false
              AppStorage.SetOrCreate<boolean>('Search', this.search)
            } else {
              this.search = true
              AppStorage.SetOrCreate<boolean>('Search', this.search)
            }
          })
            // whether the focus is on the search input before coutinue
          .onFocus(() => {
            this.isFocusOnSearch = true
          })
          .onBlur(() => {
            this.isFocusOnSearch = false
          })
            // key for request focus after coutinue
          .key('searchInput')
          .restoreId(3)
      }
      .backgroundColor(this.longpress ? $r("app.color.search_longpress_bgcolor_f7f8f9") : $r("app.color.color_ffffff"))
      .height(40)
      .opacity(this.longpress ? 0.4 : 1)
      .padding({ left: 6, right: 12, top: 9, bottom: 9 })
      .borderRadius(20)
      .border({ width: 1.5, color: $r("app.color.divider_color_e4e4e4") })
      .margin({ right: this.search ? 40 : 0 })
    }
  }
}

@Component
export struct OperateNoteCompForPortrait {
  @Consume('Longpress') longpress: boolean
  @StorageLink('CheckedNoteArray') CheckedNoteArray: NoteData[] = []
  @StorageLink('AllNoteArray') AllNoteArray: NoteData[] = AppStorage.Link('AllNoteArray')
  @Consume('SelectedFolderData') selectedFolderData: FolderData
  @Consume('RefreshFlag') @Watch('opacityChange') refreshFlag: number
  @Consume('SelectedNoteData') selectedNoteData: NoteData
  @Consume('PortraitModel') portraitModel: boolean
  @State greyOpacity: boolean = false
  @StorageLink('isUpdate') isUpdate: boolean = false
  noteDataMoveDialogCtlBottom: CustomDialogController = new CustomDialogController({
    builder: NoteDataMoveDialog({ onConfirm: this.onMoveConfirm.bind(this) }),
    alignment: DialogAlignment.Bottom,
    autoCancel: false,
    customStyle: true,
  })

  aboutToDisappear() {
    this.noteDataMoveDialogCtlBottom = null
    this.noteDataDeleteDialogCtlBottom = null
  }

  opacityChange() {
    if (this.CheckedNoteArray.length == 0 && this.longpress == true) {
      this.greyOpacity = true
      LogUtil.info(TAG, "none checked array")
    } else {
      this.greyOpacity = false
      LogUtil.info(TAG, this.CheckedNoteArray.length.toString())
    }
  }

  onMoveConfirm(folderUuid: string) {
    this.CheckedNoteArray.forEach((noteItem) => {
      noteItem.folder_uuid = folderUuid
      // update note to db
      let predicates_note = RdbStoreUtil.getRdbPredicates(TableName.NoteTable)
      predicates_note.equalTo(NoteTableColumn.Uuid, noteItem.uuid)
      RdbStoreUtil.update(noteItem.toNoteObject(), predicates_note, null)
    })
    this.selectedNoteData = NoteUtil.getFirstNoteData(this.AllNoteArray, this.selectedFolderData.uuid)
    // save continue data
    let continueNote: string = JSON.stringify(this.selectedNoteData?.toNoteObject())
    AppStorage.SetOrCreate<string>('ContinueNote', continueNote)
    LogUtil.info(TAG, "onMoveConfirm, set continue note success")
    this.longpress = false
    this.refreshFlag = (this.refreshFlag == 0 ? 1 : 0)
    NoteUtil.unsetAllNotesChecked(this.CheckedNoteArray)
    NoteUtil.refreshAll()
  }

  noteDataDeleteDialogCtlBottom: CustomDialogController = new CustomDialogController({
    builder: DeleteDialog({ onConfirm: this.onDeleteConfirm.bind(this), multiSelect: true }),
    alignment: DialogAlignment.Bottom,
    autoCancel: false,
    customStyle: true,
  })

  onDeleteConfirm() {
    if (this.selectedFolderData.uuid != SysDefFolderUuid.RecentDeletes) {
      this.CheckedNoteArray.forEach((noteItem: NoteData) => {
        noteItem.is_deleted = Delete.Yes
        noteItem.deleted_time = new Date().getTime()
        // update note to db
        let predicates_note = RdbStoreUtil.getRdbPredicates(TableName.NoteTable)
        predicates_note.equalTo(NoteTableColumn.Uuid, noteItem.uuid)
        RdbStoreUtil.update(noteItem.toNoteObject(), predicates_note, null)
      })
    } else {
      this.CheckedNoteArray.forEach((noteItem: NoteData) => {
        NoteUtil.removeNoteData(this.AllNoteArray, noteItem.uuid)
        // delete note from db
        let predicates_note = RdbStoreUtil.getRdbPredicates(TableName.NoteTable)
        predicates_note.equalTo(NoteTableColumn.Uuid, noteItem.uuid)
        RdbStoreUtil.delete(predicates_note, null)
      })
    }
    NoteUtil.unsetAllNotesChecked(this.CheckedNoteArray)
    this.longpress = false
    this.refreshFlag = (this.refreshFlag == 0 ? 1 : 0)
    this.selectedNoteData = NoteUtil.getFirstNoteData(AppStorage.Get('AllNoteArray'), this.selectedFolderData.uuid)
    // save continue data
    let continueNote: string = JSON.stringify(this.selectedNoteData?.toNoteObject())
    AppStorage.SetOrCreate<string>('ContinueNote', continueNote)
    LogUtil.info(TAG, "OperateNoteCompForPortrait, set continue note success")
    NoteUtil.refreshAll()
  }

  build() {
    Row() {
      if (this.selectedFolderData.uuid != SysDefFolderUuid.RecentDeletes) {
        Column() {
          Image($r("app.media.set_top"))
            .opacity(this.greyOpacity ? 0.4 : 1)
            .width(24)
            .height(24)
            .responseRegion({ x: -15.0, y: -15.0, width: 54, height: 54 })
            .onClick(() => {
              this.CheckedNoteArray.forEach((noteItem) => {
                noteItem.is_top = (noteItem.is_top == Top.Yes) ? Top.No : Top.Yes
                // update note to db
                let predicates_note = RdbStoreUtil.getRdbPredicates(TableName.NoteTable)
                predicates_note.equalTo(NoteTableColumn.Uuid, noteItem.uuid)
                RdbStoreUtil.update(noteItem.toNoteObject(), predicates_note, null)
              })
              this.longpress = false
              this.refreshFlag = (this.refreshFlag == 0 ? 1 : 0)
              NoteUtil.unsetAllNotesChecked(this.CheckedNoteArray)
              NoteUtil.refreshAll()
            })
          Text($r("app.string.set_top"))
            .opacity(this.greyOpacity ? 0.4 : 1)
            .fontSize(10)
            .fontColor($r("app.color.set_top_font_color"))
            .padding({ top: 5 })
        }
        .width("25%")
        .height("100%")
        .opacity(this.greyOpacity ? 0.4 : 1)
        .enabled(this.greyOpacity ? false : true)
        .alignItems(HorizontalAlign.Center)
        .justifyContent(FlexAlign.Center)
      }

      Column() {
        Image($r('app.media.delete'))
          .opacity(this.greyOpacity ? 0.4 : 1)
          .width(24)
          .height(24)
          .responseRegion({ x: -15.0, y: -15.0, width: 54, height: 54 })
          .onClick(() => {
            this.noteDataDeleteDialogCtlBottom.open()
            AppStorage.SetOrCreate('isUpdate', true)
          })
        Text($r("app.string.delete"))
          .opacity(this.greyOpacity ? 0.4 : 1)
          .fontSize(10)
          .fontColor($r("app.color.delete_font_color"))
          .padding({ top: 5 })
      }
      .width(this.selectedFolderData.uuid == SysDefFolderUuid.RecentDeletes ? 120 : "25%")
      .height("100%")
      .opacity(this.greyOpacity ? 0.4 : 1)
      .enabled(this.greyOpacity ? false : true)
      .alignItems(HorizontalAlign.Center)
      .justifyContent(FlexAlign.Center)

      if (this.selectedFolderData.uuid != SysDefFolderUuid.RecentDeletes) {
        Column() {
          Image($r('app.media.move'))
            .opacity(this.greyOpacity ? 0.4 : 1)
            .width(24)
            .height(24)
            .responseRegion({ x: -15.0, y: -15.0, width: 54, height: 54 })
            .onClick(() => {
              this.noteDataMoveDialogCtlBottom.open()
              AppStorage.SetOrCreate('isUpdate', true)
            })
          Text($r("app.string.move"))
            .opacity(this.greyOpacity ? 0.4 : 1)
            .fontSize(10)
            .fontColor($r("app.color.move_font_color"))
            .padding({ top: 5 })
        }
        .width("25%")
        .height("100%")
        .opacity(this.greyOpacity ? 0.4 : 1)
        .enabled(this.greyOpacity ? false : true)
        .alignItems(HorizontalAlign.Center)
        .justifyContent(FlexAlign.Center)
      }


      if (this.selectedFolderData.uuid == SysDefFolderUuid.RecentDeletes) {
        Column() {
          Image($r('app.media.recover'))
            .width(24)
            .height(24)
            .responseRegion({ x: -15.0, y: -15.0, width: 54, height: 54 })
            .onClick(() => {
              this.CheckedNoteArray.forEach((noteItem) => {
                noteItem.is_deleted = Delete.No
                noteItem.deleted_time = 0
                let context: any = getContext(this)
                let resource = {
                  bundleName: "com.ohos.note",
                  moduleName: "default",
                  id: $r('app.string.restore').id
                };
                context.resourceManager.getString(resource, (error, value) => {
                  if (error != null) {
                    LogUtil.error(TAG, "error is " + error);
                  } else {
                    prompt.showToast({ message: value, duration: 2000 });
                  }
                });
                // update note to db
                let predicates_note = RdbStoreUtil.getRdbPredicates(TableName.NoteTable)
                predicates_note.equalTo(NoteTableColumn.Uuid, noteItem.uuid)
                RdbStoreUtil.update(noteItem.toNoteObject(), predicates_note, null)
              })
              this.longpress = false
              NoteUtil.unsetAllNotesChecked(this.CheckedNoteArray)
              this.refreshFlag = (this.refreshFlag == 0 ? 1 : 0)
              AppStorage.SetOrCreate('isUpdate', true)
              NoteUtil.refreshAll()
            })
          Text($r("app.string.recover"))
            .fontSize(10)
            .fontColor($r("app.color.recover_font_color"))
            .padding({ top: 5 })
        }
        .width(this.selectedFolderData.uuid == SysDefFolderUuid.RecentDeletes ? 120 : "25%")
        .height("100%")
        .opacity(this.greyOpacity ? 0.4 : 1)
        .enabled(this.greyOpacity ? false : true)
        .alignItems(HorizontalAlign.Center)
        .justifyContent(FlexAlign.Center)
      }

      Column() {
        Image($r('app.media.check_all'))
          .width(24)
          .height(24)
          .responseRegion({ x: -15.0, y: -15.0, width: 54, height: 54 })
          .id(this.isUpdate + '')
          .onClick(() => {
            if (this.CheckedNoteArray.length <
            NoteUtil.getNoteDataArray(AppStorage.Get('AllNoteArray'), this.selectedFolderData.uuid)
              .length) {
              NoteUtil.setAllNotesChecked(this.CheckedNoteArray, NoteUtil.getNoteDataArray(AppStorage.Get('AllNoteArray'), this.selectedFolderData.uuid))
            } else {
              NoteUtil.unsetAllNotesChecked(this.CheckedNoteArray)
            }
            this.refreshFlag = (this.refreshFlag == 0 ? 1 : 0)
            NoteUtil.refreshAll()
          })
        Text($r("app.string.check_all"))
          .fontSize(10)
          .fontColor($r("app.color.check_all_font_color"))
          .padding({ top: 5 })
      }
      .width(this.selectedFolderData.uuid == SysDefFolderUuid.RecentDeletes ? 120 : "25%")
      .height("100%")
      .alignItems(HorizontalAlign.Center)
      .justifyContent(FlexAlign.Center)
    }
    .justifyContent(FlexAlign.Center)
    .width("100%")
    .height(56)
    .visibility(this.longpress && this.portraitModel == true ? Visibility.Visible : Visibility.None)
  }
}
