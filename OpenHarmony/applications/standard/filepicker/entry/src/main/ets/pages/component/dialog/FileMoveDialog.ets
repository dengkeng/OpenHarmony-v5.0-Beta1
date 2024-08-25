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

import { FilesData } from '../../../databases/model/FileData';
import FileAccessExec from '../../../base/utils/FileAccessExec';
import { toast, isValidFileName } from '../../../base/utils/Common';
import { TreeItem } from '../TreeItem';
import { FileMkdirDialog } from './FileMkdirDialog';
import { emit } from '../../../base/utils/EventBus';
import { getResourceString } from '../../../base/utils/Tools';
import { FILENAME_MAX_LENGTH, FILE_MANAGER_PREFERENCES, FOLDER_LEVEL } from '../../../base/constants/Constant';
import StringUtil from '../../../base/utils/StringUtil';
import { setPreferencesValue } from '../../../base/utils/PreferencesUtil';
import { FileUtil } from '../../../base/utils/FileUtil';
import Logger from '../../../base/log/Logger';
import { ArrayUtil } from '../../../base/utils/ArrayUtil';
import ErrorCodeConst from '../../../base/constants/ErrorCodeConst';

@Styles function pressedStyles () {
  .borderRadius($r('app.float.common_borderRadius8'))
  .backgroundColor($r('app.color.hicloud_hmos_bg'))
}

@Styles function normalStyles() {
  .borderRadius($r('app.float.common_borderRadius8'))
  .backgroundColor($r('app.color.transparent_color'))
}

const TAG = 'fileTree';

@Component
export struct fileTree {
  @State listLength: number = 0;
  @State positionY: string | number = '100%';
  @State topRotate: boolean = false;
  @State rootData: FilesData[] = [];
  @State selectUri: string = '';
  @State @Watch('nameChange') selectName: string = getResourceString($r('app.string.myPhone'));
  public moveCallback: (e) => void;
  @State @Watch('selectChange') chooseItem: FilesData = new FilesData({});
  @State folderList: FilesData[] = [];
  @State fileList: FilesData[] = [];
  @State changeTitle: Resource = undefined;
  @State fileName: string = '';
  @State suffix: string = '';
  fileMkdirDialog: CustomDialogController = new CustomDialogController({
    builder: FileMkdirDialog({
      fileItems: this.folderList,
      getCurrentDir: this.selectUri,
      confirm: this.fileMkdir.bind(this)
    }),
    autoCancel: true,
    alignment: DialogAlignment.Bottom,
    offset: { dx: 0, dy: -80 }
  });
  @State isSelectRootPath: boolean = true;
  @State errorText: Resource = undefined;
  @State isNeedLoadDefaultPath: boolean = false;
  @State isClickExpand: boolean = false;
  @Link @Watch('createFileFailTypeChange') createFileFailType: number;
  lastSelectPath: string = AppStorage.Get<string>(FILE_MANAGER_PREFERENCES.lastSelectPath.key);
  defaultExpandPath: string = '';
  scroller: Scroller = new Scroller();
  context: Context = globalThis.abilityContext;

  async aboutToAppear() {
    toast($r('app.string.select_location'))
    const fileNameList = globalThis.keyPickFileName;
    this.listLength = fileNameList.length;
    const fileName: string = fileNameList[0];
    if (fileName) {
      const dotIndex = fileName.lastIndexOf('.');
      let fileSuffix = globalThis.keyFileSuffixChoices;
      if (!StringUtil.isEmpty(fileSuffix)) {
        this.suffix = fileSuffix;
        if (dotIndex > 0) {
          this.fileName = fileName.substring(0, dotIndex) + fileSuffix;
        } else {
          this.fileName = fileName + fileSuffix;
        }
      } else {
        this.fileName = fileName;
      }
    }
    this.nameChange();
    this.isSelectRootPath = true;
    let { folderList, fileList } = FileAccessExec.getFileData();
    this.fileList = fileList;
    this.rootData = folderList;
    this.folderList = this.rootData;
    this.topRotate = !this.topRotate;
    if (globalThis.documentInfo) {
      this.selectUri = globalThis.documentInfo.uri;
    }
    this.loadDefaultExpandPath();
  }

  aboutToDisappear() {
    this.fileMkdirDialog = null;
  }

  fileMkdir(e) {
    emit('fileMkdir', e)
    if (this.isSelectRootPath) {
      // 获取当前选中文件夹下的所有子文件
      let { folderList, fileList } = FileAccessExec.getFileData();
      this.rootData = folderList;
      // 查找刚刚新建的文件夹index
      const index = this.rootData.findIndex(item => item.fileName === e.mkdirName);
      if (index !== -1) {
        // 默认选中刚刚新建的文件夹
        this.selectUri = this.rootData[index].uri;
        this.selectName = this.rootData[index].fileName;
        this.topRotate = true;
        this.fileList = [];
        this.folderList = [];
      } else {
        this.fileList = fileList;
        this.folderList = folderList;
      }
    }
  }

  nameChange() {
    this.changeTitle = this.listLength <= 1 ?
    $r('app.string.to_save', this.selectName) : $r('app.string.to_save_plural', this.listLength, this.selectName)
    if (this.isSelectRootPath) {
      this.isSelectRootPath = false;
    }
  }

  createFileFailTypeChange() {
    if (this.createFileFailType === ErrorCodeConst.PICKER.FILE_NAME_EXIST) {
      this.errorText = $r('app.string.save_file_has_same_file');
      this.createFileFailType = ErrorCodeConst.PICKER.NORMAL;
    }
  }

  selectChange() {
    let autoShow: boolean = false;
    if (this.chooseItem) {
      autoShow = this.chooseItem.autoShow;
      this.chooseItem.autoShow = false;
    }
    if (!this.isClickExpand || autoShow) {
      let loadSubFinish = FileUtil.loadSubFinish(this.defaultExpandPath,
        this.chooseItem.currentDir, FOLDER_LEVEL.MAX_LEVEL - 2);
      if (loadSubFinish || autoShow) {
        let allData: FilesData[] = [];
        let pos = this.getSelectItemPos(this.rootData, allData);
        let itemHeight: number = this.context.resourceManager.getNumber($r('app.float.common_size56'));
        let scrollY: number = itemHeight * (pos - 1);
        Logger.i(TAG, 'selectItemPos = ' + pos + ',itemHeight = ' + itemHeight + ' ; scrollY = ' + scrollY);
        setTimeout(() => {
          if (scrollY < 0) {
            this.scroller.scrollEdge(Edge.Start);
          } else {
            this.scroller.scrollTo({ xOffset: 0, yOffset: scrollY });
          }
        }, 0);
      }
    }
  }

  private getSelectItemPos(fileList: FilesData[], allData: FilesData[]): number {
    if (ArrayUtil.isEmpty(allData)) {
      allData = [];
    }
    if (!ArrayUtil.isEmpty(fileList)) {
      for (let index = 0; index < fileList.length; index++) {
        const fileData: FilesData = fileList[index];
        allData.push(fileData);
        if (fileData.uri === this.selectUri) {
          return allData.length;
        }
        if (fileData.hasSubFolderList()) {
          let subFolderList: FilesData[] = fileData.getSubFolderList();
          let result = this.getSelectItemPos(subFolderList, allData);
          if (result > 0) {
            return result;
          }
        }
      }
    }
    return 0;
  }

  /**
   * 加载默认展开目录，如果是路径选择器拉起的，优先使用三方指定的目录
   */
  async loadDefaultExpandPath() {
    let defaultPickDir = globalThis.keyPathDefaultPickDir;
    let loadUri = this.lastSelectPath;
    if (!StringUtil.isEmpty(defaultPickDir)) {
      loadUri = defaultPickDir;
    }
    if (!StringUtil.isEmpty(loadUri)) {
      let fileHelper = await FileUtil.getFileAccessHelperAsync(globalThis.abilityContext);
      let fileInfo = await FileUtil.getFileInfoByUri(loadUri, fileHelper);
      if (fileInfo) {
        this.defaultExpandPath = FileUtil.getCurrentFolderByFileInfo(fileInfo);
        Logger.i(TAG, 'loadDefaultExpandPath = ' + this.defaultExpandPath);
        // 值为true，说明需要刷新树布局，并且传入loadPath
        this.isNeedLoadDefaultPath = !StringUtil.isEmpty(this.defaultExpandPath);
      }
    }
  }

  private canCreateFolder(): boolean {
    if (this.chooseItem && this.chooseItem.layer) {
      return this.chooseItem.layer < FOLDER_LEVEL.MAX_LEVEL;
    }
    return true;
  }

  build() {
    Column() {
      Row() {
        Image($r('app.media.hidisk_cancel_normal'))
          .width($r('app.float.common_size46'))
          .height($r('app.float.common_size46'))
          .objectFit(ImageFit.Contain)
          .padding($r('app.float.common_padding10'))
          .stateStyles({
            pressed: pressedStyles,
            normal: normalStyles
          })
          .interpolation(ImageInterpolation.Medium)
          .onClick(() => {
            this.moveCallback.call(this, {
              cancel: true
            });
          })
        Blank()
        Image($r('app.media.hidisk_ic_add_folder'))
          .width($r('app.float.common_size46'))
          .height($r('app.float.common_size46'))
          .objectFit(ImageFit.Contain)
          .margin({ left: $r('app.float.common_margin2') })
          .padding($r('app.float.common_padding10'))
          .stateStyles({
            pressed: pressedStyles,
            normal: normalStyles
          })
          .enabled(this.canCreateFolder())
          .opacity(this.canCreateFolder() ? $r('app.float.common_opacity10') : $r('app.float.common_opacity2'))
          .interpolation(ImageInterpolation.Medium)
          .onClick(() => {
            this.fileMkdirDialog.open();
          })
        Image($r('app.media.ic_ok'))
          .width($r('app.float.common_size46'))
          .height($r('app.float.common_size46'))
          .objectFit(ImageFit.Contain)
          .objectFit(ImageFit.Contain)
          .margin({ left: $r('app.float.common_margin2') })
          .padding($r('app.float.common_padding10'))
          .stateStyles({
            pressed: pressedStyles,
            normal: normalStyles
          })
          .onClick(async () => {
            setPreferencesValue(FILE_MANAGER_PREFERENCES.name,
              FILE_MANAGER_PREFERENCES.lastSelectPath.key, this.selectUri);
            AppStorage.SetOrCreate<string>(FILE_MANAGER_PREFERENCES.lastSelectPath.key, this.selectUri);
            const prefix = this.fileName.trim();
            if (!prefix) {
              this.errorText = $r('app.string.input_nothing');
              return;
            }
            const fileName = this.fileName.trim();
            if (StringUtil.getBytesCount(fileName) > FILENAME_MAX_LENGTH) {
              this.errorText = $r('app.string.max_input_length');
            } else if (!isValidFileName(fileName)) {
              this.errorText = $r('app.string.input_invalid');
            } else {
              this.errorText = null;
              this.moveCallback({
                selectUri: this.selectUri,
                fileName: fileName
              });
            }
          })
      }.width('100%')
      .padding({
        top: $r('app.float.common_padding5'),
        right: $r('app.float.common_padding15'),
        bottom: $r('app.float.common_padding30'),
        left: $r('app.float.common_padding15')
      })

      Row() {
        if (this.listLength > 1) {
          Image($r('app.media.hidisk_icon_unknown'))
            .objectFit(ImageFit.Contain)
            .renderMode(ImageRenderMode.Original)
            .aspectRatio(1)
            .width($r('app.float.common_size52'))
            .height($r('app.float.common_size52'))
            .alignSelf(ItemAlign.Center)
            .margin({ right: $r('app.float.common_margin10') })
            .borderRadius($r('app.float.common_borderRadius8'))
        }
        Column() {
          Text(this.changeTitle)
            .fontSize($r('app.float.common_font_size16'))
            .maxLines(1)
            .textOverflow({ overflow: TextOverflow.Ellipsis })
        }
        .layoutWeight(1).alignItems(HorizontalAlign.Start)
      }
      .padding({
        right: $r('app.float.common_padding15'),
        left: $r('app.float.common_padding15'),
        bottom: $r('app.float.common_padding15')
      })

      if (this.listLength <= 1) {
        Column() {
          TextInput({ text: this.fileName })
            .fontSize($r('app.float.common_font_size16'))
            .backgroundColor($r('app.color.text_input_bg_color'))
            .onChange((newVal) => {
              this.fileName = newVal
              this.errorText = null
            })
          Divider().vertical(false).strokeWidth(1).color(Color.Gray)
            .margin({
              left: $r('app.float.common_margin20'),
              right: $r('app.float.common_margin20'),
              bottom: $r('app.float.common_margin2')
            })

          Text(this.errorText)
            .margin({
              left: $r('app.float.common_margin20'),
              right: $r('app.float.common_margin20')
            })
            .padding({
              top: $r('app.float.common_padding5'),
              bottom: $r('app.float.common_padding10')
            })
            .fontSize($r('app.float.common_font_size14'))
            .fontColor($r('app.color.error_message_color'))
            .alignSelf(ItemAlign.Start)
        }
        .margin({ bottom: $r('app.float.common_size10') })
      }

      Row().width('100%').height($r('app.float.common_size4')).opacity(0.05).backgroundColor($r('app.color.black'))

      Row() {
        Image($r('app.media.hidisk_ic_classify_phone'))
          .objectFit(ImageFit.Contain)
          .renderMode(ImageRenderMode.Original)
          .aspectRatio(1)
          .width($r('app.float.common_size24'))
          .alignSelf(ItemAlign.Center)
          .margin({ right: $r('app.float.common_margin16') })
        Text($r('app.string.myPhone'))
          .fontSize($r('app.float.common_font_size16'))
          .layoutWeight(1)
        Image($r('app.media.ic_arrow_right'))
          .objectFit(ImageFit.Contain)
          .autoResize(true)
          .height($r('app.float.common_size12'))
          .width($r('app.float.common_size12'))
          .interpolation(ImageInterpolation.Medium)
          .rotate({ z: 90, angle: this.topRotate ? 90 : 0 })
      }
      .width('100%')
      .padding({
        top: $r('app.float.common_padding16'),
        bottom: $r('app.float.common_padding16'),
        left: $r('app.float.common_padding24'),
        right: $r('app.float.common_padding24')
      })
      .backgroundColor(this.isSelectRootPath ? $r('app.color.path_pick_selected_bg') : '')
      .onClick(async () => {
        this.selectName = getResourceString($r('app.string.myPhone'));
        this.selectUri = globalThis.documentInfo && globalThis.documentInfo?.uri;
        this.isSelectRootPath = true;
        let { folderList, fileList } = await FileAccessExec.getFileData();
        this.topRotate = !this.topRotate;
        this.fileList = fileList;
        this.rootData = folderList;
        this.folderList = this.rootData;
        this.isClickExpand = true;
        this.defaultExpandPath = '';
      })

      Scroll(this.scroller) {
        Column() {
          if (this.rootData.length && this.topRotate) {
            ForEach(this.rootData, (item) => {
              if (this.isNeedLoadDefaultPath) {
                TreeItem({
                  fileItem: item,
                  loadPath: this.defaultExpandPath,
                  selectUri: $selectUri,
                  chooseItem: $chooseItem,
                  selectName: $selectName,
                  layer: 2,
                  folderList: $folderList,
                  fileList: $fileList,
                  isClickExpand: $isClickExpand
                })
              } else {
                TreeItem({
                  fileItem: item,
                  selectUri: $selectUri,
                  chooseItem: $chooseItem,
                  selectName: $selectName,
                  layer: 2,
                  folderList: $folderList,
                  fileList: $fileList,
                  isClickExpand: $isClickExpand
                })
              }
            })
          }
        }
      }
      .width('100%')
      .scrollBar(BarState.Off)
      .layoutWeight(1)
      .padding({ bottom: $r('app.float.common_padding10') })
      .align(Alignment.TopStart)
    }
    .width('100%')
    .height('100%')
    .backgroundColor($r('app.color.white'))
    .borderRadius({ topLeft: $r('app.float.common_size24'), topRight: $r('app.float.common_size24') })
    .position({ y: this.positionY })

    .onAppear(() => {
      animateTo({
        duration: 500, // 动画时长
        curve: Curve.Ease, // 动画曲线
        iterations: 1, // 播放次数
        playMode: PlayMode.Normal, // 动画模式
        onFinish: () => {
        }
      }, () => {
        this.positionY = 0
      })
    })

  }
}
