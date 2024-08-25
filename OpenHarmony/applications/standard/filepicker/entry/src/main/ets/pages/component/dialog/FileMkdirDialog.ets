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

import { FilesData } from '../../../databases/model/FileData'
import FileAccessExec from '../../../base/utils/FileAccessExec'
import { toast, isValidFileName } from '../../../base/utils/Common'
import { getResourceString } from '../../../base/utils/Tools'
import Logger from '../../../base/log/Logger'
import { DialogTitle, DialogButton, DialogButtonDivider } from '../common/DialogComponent'

const TAG = 'FileMkdirDialog'

@Component
@CustomDialog
export struct FileMkdirDialog {
  controller: CustomDialogController
  cancel: Function
  confirm: Function
  @State folderName: string = ''
  @State errorText: Resource = null
  fileItems: Array<FilesData>
  getCurrentDir: string = ''

  aboutToAppear() {
    this.folderName = this.getNewFolderName()
  }

  getNewFolderName(): string {
    const newFolderText = getResourceString($r('app.string.addFolder'));
    const regExp = new RegExp(`^${newFolderText}([ ]{1}[0-9]+)*$`);
    const tempFolderList = this.fileItems.filter(item => item.isFolder && regExp.test(item.fileName));
    let tempFolderName = newFolderText;
    let index = 0;
    while (tempFolderList.some(item => item.fileName === tempFolderName)) {
      index += 1;
      tempFolderName = newFolderText + ' ' + index.toString();
    };
    return tempFolderName;
  }

  isSameName() {
    let nameArr = []
    this.fileItems.forEach(item => {
      nameArr.push(item.fileName)
    })
    return nameArr.includes(this.folderName)
  }

  build() {
    Column() {
      DialogTitle({
        title: $r('app.string.addFolder')
      })
      TextInput({ text: this.folderName })
        .margin({
          left: $r('app.float.text_input_margin_minus10'),
          right: $r('app.float.text_input_margin_minus20')
        })
        .fontSize($r('app.float.common_font_size16'))
        .backgroundColor($r('app.color.text_input_bg_color'))
        .onSubmit(() => {
        })
        .onChange((value: string) => {
          this.folderName = value
          this.errorText = null
        })
      Divider().vertical(false).strokeWidth(1).color(Color.Gray)
        .margin({
          bottom: $r('app.float.common_margin10')
        })
      Text(this.errorText)
        .width('100%')
        .padding({
          top: $r('app.float.common_padding5'),
          bottom: $r('app.float.common_padding10')
        })
        .fontSize($r('app.float.common_font_size14'))
        .fontColor($r('app.color.error_message_color'))
      Row() {
        DialogButton({
          text: $r('app.string.cancel'),
          isDisabled: false,
          click: () => {
            this.controller.close()
          }
        })
        DialogButtonDivider()
        DialogButton({
          text: $r('app.string.confirm'),
          isDisabled: !this.folderName.trim(),
          click: () => {
            if (!isValidFileName(this.folderName)) {
              this.errorText = $r('app.string.illegal')
            } else if (this.isSameName()) {
              this.errorText = $r('app.string.sameName')
            } else {
              FileAccessExec.createFolder(this.getCurrentDir, this.folderName).then(folderUri => {
                this.confirm({
                  mkdirName: this.folderName,
                  path: folderUri
                })
              }).catch(err => {
                Logger.e(TAG, 'create Folder err: ' + JSON.stringify(err))
                toast($r('app.string.addFolder_fail'))
              })
              this.controller.close()
            }
          }
        })
      }.width('100%')
      .margin({ bottom: $r('app.float.common_margin10') })
    }.padding({
      left: $r('app.float.common_margin24'),
      right: $r('app.float.common_margin24')
    })
  }
}

