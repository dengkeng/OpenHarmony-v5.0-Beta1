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

import { BreadData, FilesData, FileDataSource } from '../../../databases/model/FileData';
import { TopBar } from '../../component/common/TopBar';
import { BreadCrumb } from '../../component/myphone/BreadCrumb';
import { FilesList } from '../../component/myphone/FilesList';
import { setSystemBar, setImmersion } from '../../../base/utils/Common';
import router from '@ohos.router';
import FileAccessExec from '../../../base/utils/FileAccessExec';
import { SYSTEM_BAR_COLOR } from '../../../base/constants/UiConstant';
import { getResourceString } from '../../../base/utils/Tools';
import { TopOperateBar } from '../../component/common/TopOperateBar';
import { FileMkdirDialog } from '../../component/dialog/FileMkdirDialog';
import { Loading } from '../../component/common/Loading';
import { getMediaType, getDurationByUri } from '../../../databases/model/FileAssetModel';
import Logger from '../../../base/log/Logger';
import multimedia_image from '@ohos.multimedia.image';
import AbilityCommonUtil from '../../../base/utils/AbilityCommonUtil';
import ObjectUtil from '../../../base/utils/ObjectUtil';
import StringUtil from '../../../base/utils/StringUtil';
import { FileUtil } from '../../../base/utils/FileUtil';
import fileAccess from '@ohos.file.fileAccess';

const TAG = 'myPhone';

@Entry
@Component
struct MyPhone {
  /**
   * 正在加载
   */
  @State isShowLoading: boolean = true;
  /**
   * 文件或文件夹数据
   */
  @State fileListSource: FileDataSource = new FileDataSource();
  /**
   * 面包屑
   */
  @State @Watch('onDireListChange') direList: BreadData[] = [];
  @State selectFilesList: FilesData[] = [];
  @State isMulti: boolean = false;
  @State selectAll: boolean = false;
  @State @Watch('checkedNumChange') checkedNum: number = 0;
  @Provide isList: boolean = true;
  @State selectName: string = '';
  @State fileSize: number = 0;
  fileMkdirDialog: CustomDialogController = new CustomDialogController({
    builder: FileMkdirDialog({
      fileItems: this.fileListSource.getDataArray(),
      getCurrentDir: this.getCurrentDirUri(),
      confirm: this.refreshData.bind(this)
    }),
    autoCancel: true,
    alignment: DialogAlignment.Bottom,
    offset: { dx: 0, dy: -80 }
  });

  checkedNumChange(): void {
    this.selectAll = this.checkedNum === this.fileListSource.totalCount();
    this.selectFilesList = this.fileListSource.getSelectedFileList();
    this.fileSize = 0;
    this.selectFilesList.forEach(item => {
      this.fileSize += item.size;
    });
  }

  getCurrentDirUri(): string {
    if (this.direList.length) {
      const lastBread = this.direList[this.direList.length-1];
      return lastBread.url;
    } else if (globalThis.documentInfo) {
      return globalThis.documentInfo.uri;
    } else {
      Logger.e(TAG, 'currentDir uri is null');
      return '';
    }
  }

  async getBreadCrumb(data: string): Promise<void> {
    if (!data) {
      data = '';
    }
    if (FileUtil.isUriPath(data)) {
      let fileHelper = await FileUtil.getFileAccessHelperAsync(globalThis.abilityContext);
      // 将uri转换成相对路径
      let curFileInfo: fileAccess.FileInfo = await FileUtil.getFileInfoByUri(data, fileHelper);
      if (!ObjectUtil.isNullOrUndefined(curFileInfo)) {
        data = FileUtil.getCurrentDir(curFileInfo.relativePath, FileUtil.isFolder(curFileInfo.mode));
      }
    }
    data = FileUtil.getPathWithFileSplit(data);

    let fileIterator;
    let fileData;
    let isContinue: boolean = true;
    let isRoot: boolean = true;
    while (isContinue) {
      isContinue = false;
      if (!fileIterator) {
        fileData = FileAccessExec.getRootFolder();
        isRoot = true;
      } else {
        fileData = FileAccessExec.getFileByCurIterator(fileIterator);
        isRoot = false;
      }
      if (Array.isArray(fileData)) {
        isContinue = true;
        for (let i = 0;i < fileData.length; i++) {
          let fileName: string = fileData[i].fileName;
          let currentDir: string = FileUtil.getPathWithFileSplit(fileData[i].currentDir);
          if (data.startsWith(currentDir)) {
            if (fileData[i].isFolder) {
              this.direList.push({ title: fileName, url: fileData[i].uri, fileIterator: fileData[i].fileIterator });
              fileIterator = fileData[i].fileIterator;
              if (data === currentDir) {
                isContinue = false;
              } else {
                break;
              }
            }
          }
        }
      }
      if (isRoot && !fileIterator) {
        isContinue = false;
      }
    }
    if (fileIterator) {
      fileData = FileAccessExec.getFileByCurIterator(fileIterator);
      this.fileListSource.setData(fileData);
    } else {
      this.getRootListFile();
    }
  }

  onPageShow() {
    // 文件选择器并且是多选模式下详情返回不更新，避免原有多选被重置
    if (globalThis.filePickerViewFlag && this.isMulti) {
      return;
    }
    setImmersion(false);
    setSystemBar(SYSTEM_BAR_COLOR.WHITE, SYSTEM_BAR_COLOR.WHITE, SYSTEM_BAR_COLOR.BLACK, SYSTEM_BAR_COLOR.BLACK);
  }

  getRootListFile() {
    let fileList = FileAccessExec.getRootFolder();
    this.fileListSource.setData(fileList);
    this.getVideoAudioDuration(fileList);
  }

  getListFile(fileInfo) {
    let fileList = FileAccessExec.getFileByCurIterator(fileInfo);
    this.fileListSource.setData(fileList);
    this.getVideoAudioDuration(fileList);
  }

  async getVideoAudioDuration(fileList) {
    const videoAudioList = fileList.filter(item => item.mimeTypeObj.isVideo() || item.mimeTypeObj.isAudio());
    for (let item of videoAudioList) {
      const mediaType = getMediaType(item.fileName);
      await getDurationByUri(mediaType, item.uri).then((duration) => {
        item.duration = duration;
        let index = this.fileListSource.getIndex(item.uri);
        if (index >= 0) {
          this.fileListSource.replaceData(index, item);
        }
      })
    }
  }

  addCallBack() {
    this.fileMkdirDialog.open();
  }

  initData(): void {
    this.selectFilesList = [];
    this.selectAll = false;
    this.isMulti = false;
    this.checkedNum = 0;
    // 全部数据列表的isChecked置为false
    this.fileListSource.selectAll(false);
  }

  backCallback(): void {
    if (!this.isMulti) {
      AbilityCommonUtil.terminateFilePicker([], [], AbilityCommonUtil.RESULT_CODE.CANCEL);
    } else {
      this.initData();
    }
  }

  menuCallback(): void {
    this.selectAll = !this.selectAll;
    this.fileListSource.selectAll(this.selectAll);
    if (this.selectAll) {
      this.checkedNum = this.fileListSource.totalCount();
    } else {
      this.checkedNum = 0;
      this.selectFilesList = [];
    }
  }

  refreshData() {
    if (this.direList.length) {
      const lastBread = this.direList[this.direList.length-1];
      this.getListFile(lastBread.fileIterator);
    } else {
      this.getRootListFile();
    }
  }

  aboutToAppear(): void {
    // 激活image媒体库，能够读取缩略图pixelMap
    multimedia_image.createPixelMap(new ArrayBuffer(4096), { size: { height: 1, width: 2 } }).then((pixelMap) => {
    })
    this.setShowLoading(true);
    let pickPath = this.getParams();
    if (StringUtil.isEmpty(pickPath)) {
      this.getRootListFile();
    } else {
      this.getBreadCrumb(pickPath);
    }
    this.setShowLoading(false);
  }

  aboutToDisappear() {
    this.fileMkdirDialog = null;
  }

  getParams(): string {
    let defaultPickPath = globalThis.keyFileDefaultPickPath;
    if (!ObjectUtil.isNullOrUndefined(defaultPickPath)) {
      return defaultPickPath;
    }
    let params = router.getParams();
    if (!ObjectUtil.isNullOrUndefined(params)) {
      defaultPickPath = params['path'];
      if (!ObjectUtil.isNullOrUndefined(defaultPickPath)) {
        return defaultPickPath;
      }
    }
    return '';
  }

  onDireListChange(): void {
    if (this.isMulti) {
      this.backCallback();
    }
    this.setShowLoading(true);
    if (this.direList.length) {
      const lastBreadCrumb = this.direList[this.direList.length-1];
      this.getListFile(lastBreadCrumb.fileIterator);
    } else {
      this.getRootListFile();
    }
    this.setShowLoading(false);
    Logger.i(TAG, 'onDireListChange BreadCrumb length:' + this.direList.length);
  }

  setShowLoading(isShow: boolean) {
    this.isShowLoading = isShow;
  }

  onBackPress() {
    const direList = this.direList;
    const dirLen = this.direList.length;
    if (this.isMulti) {
      this.initData();
      return true;
    } else {
      if (router.getParams()) {
        router.back();
      } else {
        if (dirLen) {
          direList.splice(-1, 1);
          if (direList.length) {
            const lastDir = direList[direList.length-1];
            this.getListFile(lastDir.fileIterator);
          } else {
            this.getRootListFile();
          }
        } else {
          AbilityCommonUtil.terminateFilePicker([], [], AbilityCommonUtil.RESULT_CODE.CANCEL);
        }
      }
      return true;
    }
  }

  build() {
    Column() {
      // 头部导航
      TopBar({
        title: getResourceString($r('app.string.myPhone')),
        isMulti: this.isMulti,
        selectAll: this.selectAll,
        checkedNum: $checkedNum,
        checkedList: $selectFilesList,
        backCallback: this.backCallback.bind(this),
        menuCallback: this.menuCallback.bind(this)
      })
      // 面包屑
      BreadCrumb({
        direList: $direList
      })

      TopOperateBar({
        isDisabled: this.isMulti,
        addFolder: this.addCallBack.bind(this)
      })

      Column() {
        Loading({ isLoading: !!this.isShowLoading })
        if (!this.isShowLoading) {
          // 文件列表
          FilesList({
            fileListSource: $fileListSource,
            direList: $direList,
            isMulti: $isMulti,
            checkedNum: $checkedNum
          })
        }
      }.layoutWeight(1)
    }
    .width('100%')
  }
}