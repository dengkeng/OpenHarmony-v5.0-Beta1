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

import { FilesData } from '../../databases/model/FileData';
import { on } from '../../base/utils/EventBus';
import FileAccessExec from '../../base/utils/FileAccessExec';
import { TREE_LAYER } from '../../base/constants/UiConstant';
import { FOLDER_LEVEL } from '../../base/constants/Constant';
import { FileUtil } from '../../base/utils/FileUtil';
import { ArrayUtil } from '../../base/utils/ArrayUtil';
import { FileBase } from '../../databases/model/base/FileBase';
import Logger from '../../base/log/Logger';
import fileAccess from '@ohos.file.fileAccess';
import ObjectUtil from '../../base/utils/ObjectUtil';

@Styles
function pressedStyles() {
  .backgroundColor($r('app.color.hicloud_hmos_bg'))
}

const TAG = 'TreeItem';

@Component
export struct TreeItem {
  fileItem: FilesData = new FilesData({});
  loadPath?: string = '';
  isNeedExpand: boolean = false;
  @State iconRotate: boolean = false;
  @State subFolderList: FilesData[] = [];
  @Link chooseItem: FilesData;
  @Link selectUri: string;
  @Link selectName: string;
  @Link fileList: FilesData[];
  @Link folderList: FilesData[];
  @State isShowArrow: boolean = true;
  @Prop layer: number;
  @State isLoading: boolean = false;
  @Link @Watch('clickExpandChange') isClickExpand: boolean;

  private changeSelectItem(selectedItem: FilesData, autoShow: boolean) {
    if (selectedItem) {
      selectedItem.autoShow = autoShow;
      this.chooseItem = selectedItem;
      this.selectUri = this.chooseItem.uri;
      this.selectName = this.chooseItem.fileName;
    }
  }

  private async executeQuery(dirUri: string, defaultExpandPath: string, call: Function) {
    this.isLoading = true;
    if (!this.isNeedExpand || (this.isNeedExpand && !this.isClickExpand)) {
      this.changeSelectItem(this.fileItem, false);
    }

    let queryRes = await this.getPickPathListFiles(dirUri, defaultExpandPath, this.fileItem.layer);
    this.isLoading = false;
    let subList: FilesData[] = this.fileBaseToFileData(queryRes);
    let { folderList, fileList } = this.transfer(subList);
    this.fileList = fileList
    call(folderList);
  }

  private async getPickPathListFiles(dirUri: string, expandPath: string, level: number): Promise<FileBase[]> {
    let fileHelper = await FileUtil.getFileAccessHelperAsync(globalThis.abilityContext);
    let fileInfo: fileAccess.FileInfo = await FileUtil.getFileInfoByUri(dirUri, fileHelper);
    if (ObjectUtil.isNullOrUndefined(fileInfo) || !FileUtil.isFolder(fileInfo.mode)) {
      Logger.e(TAG, 'uri is not folder');
      return;
    }
    let queryRes = FileAccessExec.getPathPickSubFiles(fileInfo, expandPath, level);
    if (ObjectUtil.isNull(queryRes)) {
      Logger.e(TAG, 'files is null');
      return;
    }
    return queryRes;
  }

  transfer(list: FilesData[]) {
    let folderList: FilesData[] = [];
    let fileList: FilesData[] = [];
    if (ArrayUtil.isEmpty(list)) {
      return { folderList, fileList };
    }
    for (let i = 0; i < list.length; i++) {
      let fileData = list[i];
      if (fileData.isFolder) {
        folderList.push(fileData);
      } else {
        fileList.push(fileData);
      }
    }
    return { folderList, fileList };
  }

  fileBaseToFileData(list: FileBase[]): FilesData[] {
    let fileArray: FilesData[] = [];
    if (ArrayUtil.isEmpty(list)) {
      return fileArray;
    }
    for (let i = 0; i < list.length; i++) {
      let data = list[i];
      let fileData = new FilesData([]);
      fileData.uri = data.uri;
      fileData.fileName = data.fileName;
      fileData.isFolder = data.isFolder;
      fileData.size = data.fileSize;
      fileData.mtime = data.modifyTime;
      fileData.path = data.relativePath;
      fileData.currentDir = data.currentDir;
      if (data.isFolder) {
        if (!ArrayUtil.isEmpty(data.subList)) {
          fileData.setSubList(this.fileBaseToFileData(data.subList));
        }
      }
      fileArray.push(fileData);
    }
    return fileArray;
  }

  /**
   * 是否需要展开目录，如果最近保存的目录不为空，需要展开到最近保存的目录
   *
   * @returns true：需要展开目录
   */
  needExpandPath(): boolean {
    if (!this.canExpandPath() || this.isClickExpand) {
      return false;
    }
    return FileUtil.hasSubFolder(this.loadPath, this.fileItem.currentDir);
  }

  clickExpandChange() {
    this.isNeedExpand = false;
    this.loadPath = '';
  }

  canExpandPath(): boolean {
    return this.layer <= FOLDER_LEVEL.MAX_LEVEL;
  }

  loadSubFolder(subFolderList: FilesData[]) {
    this.subFolderList = subFolderList;
    this.folderList = this.subFolderList;
    this.fileItem.setSubFolderList(subFolderList);
    Logger.i(TAG, 'loadSubFolder:selectUri = ' + this.selectUri +
      ' ; subFolderListSize = ' + this.subFolderList.length +
      ' ; iconRotate = ' + this.iconRotate);
  }

  aboutToAppear() {
    on('fileMkdir', async (e) => {
      if (this.selectUri === this.fileItem.uri) {
        // 获取当前选中文件夹下的所有子文件
        let queryArray = await this.getPickPathListFiles(this.fileItem.uri, '', this.fileItem.layer);
        let subList: FilesData[] = this.fileBaseToFileData(queryArray);
        let { folderList, fileList } = this.transfer(subList);
        this.fileList = fileList;
        // 获取当前选中文件夹下的所有子文件
        this.subFolderList = folderList;
        this.expandSubFolderCall(folderList);
        // 查找刚刚新建的文件夹index
        const index = this.subFolderList.findIndex(item => item.fileName === e.mkdirName);
        if (index !== -1 && this.canExpandPath()) {
          // 默认选中刚刚新建的文件夹
          this.changeSelectItem(this.subFolderList[index], true);
          this.iconRotate = true;
          this.fileList = [];
          this.folderList = [];
        }
      }
    })

    this.fileItem.setLayer(this.layer);
    this.isNeedExpand = this.needExpandPath();
    if (this.isNeedExpand) {
      Logger.i(TAG, 'NeedExpand:loadPath = ' + this.loadPath +
        ' ; path = ' + this.fileItem.currentDir);
      this.clickExpand(false);
    }
  }

  clickExpand(forceLoading: boolean) {
    if (!this.isLoading) {
      if (this.iconRotate) {
        this.iconRotate = !this.iconRotate;
        this.changeSelectItem(this.fileItem, false);
        this.fileItem.subFileList = null;
        this.folderList = this.fileItem.subFolderList;
      } else {
        if (this.canExpandPath()) {
          if (this.fileItem.hasSubFolderList() && !forceLoading) {
            this.changeSelectItem(this.fileItem, false);
            this.fileList = this.fileItem.subFileList;
            this.expandSubFolderCall(this.fileItem.getSubFolderList());
          } else {
            this.executeQuery(this.fileItem.uri, this.loadPath, this.expandSubFolderCall.bind(this));
          }
        }
      }
    }
  }

  private expandSubFolderCall(subFolderList: FilesData[]) {
    this.iconRotate = !this.iconRotate;
    this.loadSubFolder(subFolderList);
    this.isShowArrow = this.subFolderList.length !== 0;
  }

  build() {
    Column() {
      Row() {
        Image($r('app.media.hidisk_ic_list_empty_folder'))
          .objectFit(ImageFit.Contain)
          .renderMode(ImageRenderMode.Original)
          .aspectRatio(1)
          .width($r('app.float.common_size24'))
          .alignSelf(ItemAlign.Center)
          .margin({ right: $r('app.float.common_margin16') })
        Text(this.fileItem.fileName)
          .fontSize($r('app.float.common_font_size16'))
          .layoutWeight(1)
          .maxLines(1)
          .textOverflow({ overflow: TextOverflow.Ellipsis })
        if (this.isLoading) {
          LoadingProgress()
            .width($r('app.float.common_size24'))
            .height($r('app.float.common_size24'))
            .color($r('sys.color.ohos_id_color_text_secondary'))
        } else {
          Image($r('app.media.ic_arrow_right'))
            .objectFit(ImageFit.Contain)
            .autoResize(true)
            .height($r('app.float.common_size12'))
            .width($r('app.float.common_size12'))
            .interpolation(ImageInterpolation.Medium)
            .rotate({ z: 90, angle: this.iconRotate ? 90 : 0 })
            .visibility(this.isShowArrow ? Visibility.Visible : Visibility.None)
        }
      }
      .width('100%')
      .padding({
        top: $r('app.float.common_padding16'),
        bottom: $r('app.float.common_padding16'),
        right: $r('app.float.common_padding24'),
        left: this.layer * TREE_LAYER + 'vp'
      })
      .backgroundColor(this.selectUri === this.fileItem.uri ? $r('app.color.move_dialog_background') : '')
      .stateStyles({
        pressed: pressedStyles
      })
      .onClick(() => {
        this.isClickExpand = true;
        this.clickExpand(true);
      })

      if (this.subFolderList.length && this.iconRotate) {
        ForEach(this.subFolderList, (item) => {
          TreeItem({
            fileItem: item,
            loadPath: this.loadPath,
            chooseItem: $chooseItem,
            selectUri: $selectUri,
            selectName: $selectName,
            layer: this.layer + 1,
            folderList: $folderList,
            fileList: $fileList,
            isClickExpand: $isClickExpand
          })
        })
      }
    }
  }
}