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

import { FolderListComp } from '@ohos/component/src/main/ets/components/FolderListComp'
import { NoteListComp } from '@ohos/component/src/main/ets/components/NoteListComp'
import StyleConstants from '@ohos/utils/src/main/ets/default/constants/StyleConstants'
import { LogUtil } from '@ohos/utils/src/main/ets/default/baseUtil/LogUtil'
import { circleColorArray } from '@ohos/utils/src/main/ets/default/model/NoteBaseData'
import FolderData from '@ohos/utils/src/main/ets/default/model/databaseModel/FolderData'
import NoteData from '@ohos/utils/src/main/ets/default/model/databaseModel/NoteData'

@Entry
@Component
export struct NoteHomePortraitComp {
  // 当前文件夹、笔记、分栏
  @Provide('SelectedFolderData') selectedFolderData: FolderData = AppStorage.Get('Folder')
  @Provide('SelectedNoteData') selectedNoteData: NoteData = AppStorage.Get('Note')
  @Provide('SectionStatus') sectionStatus: number = 1; // 表示分栏状态， 3表示三分栏， 2表示二分栏，1表示一分栏
  @Provide('LastSectionStatus') lastSectionStatus: number = 1; // 记录分栏上一次的状态
  @Provide('SelectedColor') selectedColor: string = circleColorArray[0];
  @Provide('Longpress') longpress: boolean = false // 第二栏长按状态

  // 分栏状态
  @Provide('ExpandStatus') expandStatus: boolean = false // 笔记本折叠展开状态
  @Provide('ChooseNote') chooseNote: boolean = AppStorage.Get<boolean>('Choose') // 是否选择笔记进行打开

  @Provide('Search') search: boolean = false // 是否处于搜索状态
  @Provide('SearchResultList') searchResultList: NoteData[] = [] // 搜索得到的笔记列表
  @Provide('InputKeyword') inputKeyword: string = '' // 搜索的字串
  @Provide('SelectedAll') selectedAll: boolean = false;
  @Provide('EditModel') editModel: boolean = false
  TAG = "NoteHomePortraitComp_Phone"
  @Provide('AsideWidth') asideWidth: number = 200

  build() {
    Stack({ alignContent: Alignment.Start }) {
      // Note list display area
      Flex({ direction: FlexDirection.Column, wrap: FlexWrap.Wrap, justifyContent: FlexAlign.Start }) {
        NoteListComp()
      }
      .width(StyleConstants.PERCENTAGE_100)
      .height(StyleConstants.PERCENTAGE_100)
      .enabled(this.expandStatus ? false : true)
      .backgroundColor($r("app.color.notelist_bgcolor_f1f3f5"))

      // 蒙层
      if (this.expandStatus) {
        Column()
          .width('100%')
          .height('100%')
          .position({ x: 0, y: 0 })
          .backgroundColor(Color.Black)
          .opacity(0.2)
          .transition({ opacity: 0 })
      }
      //Folder list display area
      Column() {
        FolderListComp()
      }
      .width(200)
      .height(StyleConstants.PERCENTAGE_100)
      .position({ x: 0, y: 0 })
      .translate({ x: this.expandStatus ? 0 : '-200', y: 0 })
    }
    .width(StyleConstants.PERCENTAGE_100).height(StyleConstants.PERCENTAGE_100)
  }

  aboutToAppear(): void {
    LogUtil.info(this.TAG, "aboutToAppear")
  }

  aboutToDisappear(): void {
    LogUtil.info(this.TAG, "aboutToDisappear")
  }
}