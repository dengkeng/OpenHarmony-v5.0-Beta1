/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

import { ErrorMessage, MediaSizeHelper, MediaTypeCode, MediaTypes, PreviewAttribute, PrinterCapsOptions, PrintJob, PrintJobOptions, PrintUtil, startPrintJob } from '@ohos/common';
import WifiP2pHelper from '../Common/Adapter/WifiP2pHelper';
import FileModel from '../Model/FileModel';
import SelectionModel from '../Model/SelectionModel';
import { WLANConfirmDialog, PrintingSelectDialog, alarmDialog, connectConfirmDialog } from './component/CusDialogComp';
import {
  PrinterSelection,
  MediaSizeSelection,
  DirectionSelection,
  MediaTypeSelection,
  QualitySelection,
  DuplexSelection
} from './component/SelectComponent';
import { MediaSize, MediaSizeUtil } from '@ohos/common';
import { StringUtil } from '@ohos/common';
import { PreviewComponent } from './component/PreviewComponent';
import { ErrorCode, PrintPageSize, PrinterRange, PrintMargin, PrinterCapability, PrinterInfo } from '@ohos/common';
import PrintAdapter from '../Common/Adapter/PrintAdapter';
import { GlobalThisHelper, GlobalThisStorageKey} from '@ohos/common';
import FileUtil from '../Common/Utils/FileUtil';
import CheckEmptyUtils from '@ohos/common';
import { CopyUtil } from '@ohos/common';
import {
  Constants,
  AppCommonEvent,
  AppStorageKeyName,
  PrintRangeType,
  PrintQuality,
  Duplex,
  PageDirection,
  ColorCode,
  MediaType,
  MouseState
} from '@ohos/common';
import { Log } from '@ohos/common';
import { uuidGenerator } from '@ohos/common';
import { BISHENG_PRINTER } from '@ohos/common';
import emitter from '@ohos.events.emitter';
import print from '@ohos.print';
import promptAction from '@ohos.promptAction';
import common from '@ohos.app.ability.common';
import {CancelButton} from './component/BaseComponent';
import image from '@ohos.multimedia.image';
import { AboutPageComponent } from './component/AboutPageComponent';
import router from '@ohos.router';
import Want from '@ohos.app.ability.Want';
import { BusinessError } from '@ohos.base';

const TAG = 'PrintPage';

let storage = LocalStorage.getShared();
@Entry(storage)
@Component
struct Index {
  @Provide('ImageCount') imageCount: number = Constants.NUMBER_1;//预览显示的页数
  @Provide('CurrentIndex') currentIndex: number = Constants.NUMBER_1;
  @Provide('Printer') @Watch('onPrinterChange') printer: PrinterInfo | undefined = undefined; //打印机
  @Provide('ShowPageNum') showPageNum: number = Constants.NUMBER_1
  @Provide('PrinterList') printerList: Array<PrinterInfo> = [];
  @Provide('PrintJob') printJob: PrintJob | undefined = undefined;
  @Provide('UsedPrinterId') usedPrinterId: string | undefined = undefined;
  @Provide('PrintAdapter') adapter: PrintAdapter | undefined = undefined;
  @Provide('ConnectCountDown') connectCount: number = Constants.CONNECT_COUNT;
  @Provide('ConnectCountDownTimer') connectTimer: number | undefined = undefined;
  @Provide('CanPrint') canPrint: boolean = false;
  @Provide('WLANFlag') wlanFlag: boolean = false;
  @Provide('IsNeedListenWlan') isNeedListenWlan: boolean = false;
  @Provide('ConnectingPrinterId') connectingPrinterId: string = Constants.DEFAULT_CONNECTING_PRINTER_ID;
  @Provide('PrinterSelectArray') printerSelectArray: Array<SelectionModel> = [];
  @Provide('CurrentPrinter') currentPrinterSelection: SelectionModel = SelectionModel.NO_Printer;
  @Provide('MediaSizeSelectArray') mediaSizeSelectArray: Array<SelectionModel> = [];
  @Provide('CurrentMediaSize') @Watch('updateMediaSize') currentMediaSize: SelectionModel = SelectionModel.MediaSize_ISO_A4;
  @Provide('DirectionSelectArray') directionSelectArray: Array<SelectionModel> = [];
  @Provide('CurrentDirection') @Watch('updateDirection') currentDirection: SelectionModel = SelectionModel.Direction_AUTO;
  @Provide('MediaTypeSelectArray') mediaTypeSelectArray: Array<SelectionModel> = [];
  @Provide('CurrentMediaType') @Watch('updateMediaType') currentMediaType: SelectionModel = SelectionModel.MediaType_NORMAL;
  @Provide('QualitySelectArray') qualitySelectArray: Array<SelectionModel> = [];
  @Provide('CurrentQuality') currentQuality: SelectionModel = SelectionModel.PrintQuality_STANDARD;
  @Provide('DuplexSelectArray') duplexSelectArray: Array<SelectionModel> = [];
  @Provide('CurrentDuplex') currentDuplex: SelectionModel = SelectionModel.DuplexMode_SINGLE;
  @Provide('PrintRange') printRange: Array<number> = []; //打印范围
  @Provide('NeedDuplex') @Watch('needDuplexChange')needDuplex: boolean = true;
  @Provide('IsBorderless') isBorderless: boolean = false //是否无边距
  @Provide('IsPreviewFailed') isPreviewFailed: boolean = false //是否需要显示预览失败图示
  private abilityContext: common.UIAbilityContext | undefined = undefined;
  @State @Watch('updateImageSources')imageSources: FileModel[] = [];
  @State startPage: number = Constants.NUMBER_1 //打印范围起始页
  @State startPageStr: string = Constants.STRING_ONE //打印范围起始页
  @State endPage: number = Constants.NUMBER_1 //打印范围终止页
  @State endPageStr: string = Constants.STRING_ONE //打印范围终止页
  @State printCount: number = Constants.NUMBER_1 //份数
  @State printCountStr: string = Constants.STRING_ONE //份数
  @State isColored: boolean = false //是否彩印
  @State isColorEnabled: boolean = true //是否支持彩印
  @State isDuplexEnabled: boolean = true //是否支持双面
  @State isPhotoEnabled: boolean = true //是否支持相片纸
  @State isPlusPressed: boolean = false //是否按下份数+
  @State plusMouseState: number = MouseState.NONE //份数+
  @State minusMouseState: number = MouseState.NONE //份数-
  @State isMinusPressed: boolean = false //是否按下份数-
  @State mediaSizeList: Array<MediaSize> = []; //所有纸张尺寸
  @State printRangeType: number = PrintRangeType.ALL; //打印范围类型 0：全部页面 1：范围打印
  @State colorMode: number = ColorCode.MONOCHROME;
  @State mediaSize: MediaSize = MediaSizeHelper.ISO_A4; //纸张尺寸
  @State pageDirection: number = Constants.NUMBER_0; //纸张方向
  @State printerRange: PrinterRange | undefined = undefined; //打印框架需要的参数，实际不起效
  @State printerPageSize: PrintPageSize | undefined = undefined; //纸张尺寸
  @State alarmText: string | undefined = undefined;
  @State lastPrinterExist: boolean = false;
  @State isConnected: boolean = false;
  @State printerCap: print.PrinterCapability | undefined = undefined;
  @State printButtonFlag: boolean = true;
  @State cusRangeBorderColor: Resource = $r('app.color.border_line');
  @State errorMessage: Resource | undefined = undefined;
  @State isCusRangeError: boolean = false;
  @State isCusRangeMax: boolean = false;
  @State cusRangeArr: number[] = [];
  @State cusRangeText: string | undefined = undefined;
  @State isRangeRadioEnable: boolean = false;
  @State isCustomRadioEnable: boolean = false;
  @State isAbovePageLimit: boolean = false;//是否超过页数限制
  @State printParamCompHeight: number = 0;//参数区组件高度
  @Provide('PreviewCompHeight') previewCompHeight: number = 0;//预览区组件高度
  @Provide('IsGlobalDisable') isGlobalDisable: boolean = false;
  @Provide('PrinterSelectFlag') @Watch('openPrinterSelectDialog') printerSelectFlag: boolean = false;
  @Provide('OpenWLANFlag') @Watch('openWLANDialog') openWlanFlag: boolean = true;
  @Provide('ConnectFlag') @Watch('connectAlarm') connectFlag: boolean = true;
  @StorageLink('JobQueue') jobQueue: PrintJob[] = [];
  private usedPrinterFileName: string = 'lastUsedPrinter'
  private firstFileName: string = Constants.STRING_NONE;
  private totalPage: number = Constants.NUMBER_1//总页数
  private allPages: Array<number> = [];
  private jobName: string = Constants.STRING_NONE
  private jobNum: number = Constants.NUMBER_1
  private jobDes: string = Constants.STRING_NONE
  private jobId: string = Constants.STRING_NONE
  private jobFileList: Array<string> = []
  private supportedMediaTypes: Array<number> = []
  private scroller: Scroller = new Scroller()
  private firstStartPageEdit: boolean = true
  private firstEndPageEdit: boolean = true
  private editCusRangeFlag: boolean = true//自定义输入框自动置空时为false，不触发编辑
  private rangeInputLimit: number = Constants.NUMBER_3 //范围输入框位数限制
  private firstPrinterDiscoveredFlag: boolean = false;
  private changeRangeTypeFlag: boolean = true;//范围框radio选中是否让startPage输入框获焦
  private fileNum: number = Constants.NUMBER_0;

  WLANConfirmDialogCtl: CustomDialogController = new CustomDialogController({
    builder: WLANConfirmDialog(),
    alignment: DialogAlignment.Center,
    autoCancel: false,
    customStyle: true,
  })
  PrintingSelectDialogCtl: CustomDialogController = new CustomDialogController({
    builder: PrintingSelectDialog(),
    alignment: DialogAlignment.Center,
    autoCancel: false,
    customStyle: true,
  })
  alarmDialogCtl: CustomDialogController = new CustomDialogController({
    builder: alarmDialog({ alarmText: this.alarmText }),
    alignment: DialogAlignment.Center,
    autoCancel: false,
    customStyle: true,
  })
  connectConfirmDialogCtl: CustomDialogController = new CustomDialogController({
    builder: connectConfirmDialog(),
    alignment: DialogAlignment.Center,
    autoCancel: false,
    customStyle: true,
  })

  build() {
    Flex({ direction: FlexDirection.Column, alignItems: ItemAlign.Center }) {
      // 预览组件
      PreviewComponent({
        pageDirection: $pageDirection,
        colorMode: $colorMode,
        mediaSize: $mediaSize,
        imageSources: $imageSources
      })
        .height('40%')
        .onAreaChange((oldValue: Area, newValue: Area) => {
          Log.info(`Ace: on area change, oldValue is ${JSON.stringify(oldValue)} value is ${JSON.stringify(newValue)}`)
          this.previewCompHeight = newValue.height as number;
          this.printParamCompHeight = this.previewCompHeight*1.5
        })
      Column() {
        Scroll(this.scroller) {
          Column() {
            PrinterSelection()
            Flex({ direction: FlexDirection.Row, alignItems: ItemAlign.Center }) {
              Text($r('app.string.index_add_copies'))
                .fontSize($r('app.float.font_size_body2'))
                .width($r('app.float.text_label_width'))
                .textAlign(TextAlign.End)
                .key('Index_Text_copies')
                .focusable(true)
                .onFocus(()=>{
                  if (this.printRangeType === PrintRangeType.CUSTOM) {
                    this.checkCustomRangeTextInput(false)
                  }
                })
              TextInput({ text: this.printCountStr })
                .type(InputType.Number)
                .maxLength(Constants.NUMBER_2)
                .fontSize($r('app.float.font_size_body2'))
                .border({
                  width: $r('app.float.border_width'),
                  radius: $r('app.float.radius_s'),
                  color: $r('app.color.border_line')
                })
                .backgroundColor(Color.White)
                .width($r('app.float.print_copies_textInput_width'))
                .height($r('app.float.params_comp_height'))
                .margin({
                  left: $r('app.float.print_copies_textInput_left_margin'),
                  right: $r('app.float.print_copies_textInput_right_margin')
                })
                .key('Index_TextInput_copies')
                .onChange((value: string) => {
                  Log.info(TAG, 'copies onChange value:' + value)
                  this.printCount = Number.parseInt(value)
                  this.printCountStr = value//规避前置0输入
                  this.printCountStr = this.printCount.toString()
                  Log.info(TAG, 'copies onChange printCount:' + this.printCount)
                  if (Number.isNaN(this.printCount)) {
                    this.printCount = Constants.NUMBER_1
                    this.printCountStr = Constants.STRING_NONE
                  }
                  if (this.printCount < Constants.NUMBER_1) {
                    this.printCount = Constants.NUMBER_1
                  }
                  if (this.printCount > Constants.NUMBER_99||this.printCount >= Number.MAX_VALUE) {
                    this.printCount = Constants.NUMBER_99
                  }
                })
                .onSubmit(() => {
                  this.printCountStr = Constants.STRING_NONE
                  this.printCountStr = this.printCount.toString()
                })
                .onBlur(() => {
                  this.printCountStr = ''
                  this.printCountStr = this.printCount.toString()
                  Log.info(TAG,'copies onBlur printCountStr: ',this.printCountStr)
                })
                .onTouch((e:TouchEvent)=>{
                  e.stopPropagation()
                })
                .onMouse((e:MouseEvent)=>{
                  e.stopPropagation()
                })
              Column() {
                Image(this.getPlusImage(this.plusMouseState,this.printCount < Constants.NUMBER_99))
                  .width($r('app.float.print_copies_image_width'))
                  .height($r('app.float.print_copies_image_height'))
                  .enabled(this.printCount < Constants.NUMBER_99)
                  .key('Index_Image_plus_copies')
                  .onClick(() => {
                    if (this.printCount < Constants.NUMBER_99) {
                      this.printCount++
                      this.printCountStr = this.printCount.toString()
                    }
                  })
                  .onTouch((event: TouchEvent) => {
                    if (event.type === TouchType.Down) {
                      this.plusMouseState = MouseState.PRESS
                    }
                    if (event.type === TouchType.Up) {
                      this.plusMouseState = MouseState.NONE
                    }
                  })
                  .onHover((isHover: boolean) => {
                    if (isHover) {
                      this.plusMouseState = MouseState.HOVER
                    } else {
                      this.plusMouseState = MouseState.NONE
                    }
                  })
                Image(this.getMinusImage(this.minusMouseState,this.printCount > Constants.NUMBER_1))
                  .width($r('app.float.print_copies_image_width'))
                  .height($r('app.float.print_copies_image_height'))
                  .enabled(this.printCount > Constants.NUMBER_1)
                  .key('Index_Image_minus_copies')
                  .onClick(() => {
                    if (this.printCount > Constants.NUMBER_1) {
                      this.printCount--
                      this.printCountStr = this.printCount.toString()
                    }
                  })
                  .onTouch((event: TouchEvent) => {
                    if (event.type === TouchType.Down) {
                      this.minusMouseState = MouseState.PRESS
                    }
                    if (event.type === TouchType.Up) {
                      this.minusMouseState = MouseState.NONE
                    }
                  })
                  .onHover((isHover: boolean) => {
                    if (isHover) {
                      this.minusMouseState = MouseState.HOVER
                    } else {
                      this.minusMouseState = MouseState.NONE
                    }
                  })
              }
              .width($r('app.float.print_copies_image_width'))
              .height($r('app.float.params_comp_height'))

              Text($r('app.string.ColorMode'))
                .key('Index_Text_color')
                .fontSize($r('app.float.font_size_body2'))
                .height($r('app.float.params_comp_height'))
                .margin({
                  left: $r('app.float.text_colorMode_left_margin'),
                  right: $r('app.float.text_colorMode_right_margin')
                })
                .textAlign(TextAlign.Start)
                .visibility(this.isColorEnabled ? Visibility.Visible : Visibility.None)
              Toggle({ type: ToggleType.Switch, isOn: !this.isColored })
                .key('Index_Toggle_color')
                .width($r('app.float.toggle_colorMode_width'))
                .margin({ right: $r('app.float.toggle_colorMode_right_margin') })
                .alignSelf(ItemAlign.Center)
                .visibility(this.isColorEnabled ? Visibility.Visible : Visibility.None)
                .onChange((isOn: boolean) => {
                  this.isColored = !isOn
                  Log.info(TAG, 'ColorMode onChange: ' + this.isColored)
                  if (this.isColored) {
                    this.colorMode = ColorCode.COLOR
                  } else {
                    this.colorMode = ColorCode.MONOCHROME
                  }
                })
            }
            .height($r('app.float.params_row_height'))
            .width($r('app.float.params_row_width'))

            Column() {
              Row() {
                Text($r('app.string.index_page_range'))
                  .fontSize($r('app.float.font_size_body2'))
                  .width($r('app.float.text_label_width'))
                  .textAlign(TextAlign.End)
                  .key('Index_Text_pageRange')
                Radio({ value: 'Radio1', group: 'radioGroup' })
                  .checked(this.printRangeType === PrintRangeType.ALL)
                  .key('Index_Radio_allPages_pageRange')
                  .width($r('app.float.image_comp_width'))
                  .margin({
                    left: $r('app.float.Radio_pageRange_left_margin'),
                    right: $r('app.float.Radio_pageRange_right_margin')
                  })
                  .onChange((value: boolean) => {
                    Log.info(TAG,'Radio_range_pageRange all')
                    if (value) {
                      if (this.printRangeType === PrintRangeType.CUSTOM) {
                        this.checkCustomRangeTextInput(true);
                        this.printRangeType = PrintRangeType.ALL
                        focusControl.requestFocus('Index_Text_copies')
                      }
                      this.printRangeType = PrintRangeType.ALL;
                      this.updatePrintRange()
                    }
                  })
                Text($r('app.string.index_all_pages'))
                  .fontSize($r('app.float.font_size_body2'))
                  .key('Index_Text_allPages_pageRange')
              }
              .height($r('app.float.params_row_height'))
              .width($r('app.float.params_row_width'))

              Row() {
                Radio({ value: 'Radio2', group: 'radioGroup' })
                  .checked(this.printRangeType === PrintRangeType.RANGE)
                  .key('Index_Radio_range_pageRange')
                  .width($r('app.float.image_comp_width'))
                  .margin({
                    left: $r('app.float.Radio_pageRange2_left_margin'),
                    right: $r('app.float.Radio_pageRange2_right_margin')
                  })
                  .onChange((value: boolean) => {
                    if (value) {
                      if (this.changeRangeTypeFlag) {
                        focusControl.requestFocus('Index_TextInput_from_pageRange')
                      }
                      this.checkCustomRangeTextInput(true)
                      Log.info(TAG, 'Radio_range_pageRange onChange: '+ this.endPage)
                      this.printRangeType = PrintRangeType.RANGE;
                      this.editCusRangeFlag = false;this.cusRangeText = Constants.NUMBER_1+Constants.HYPHEN +
                      Constants.MAX_PAGES.toString()
                      this.isRangeRadioEnable = true
                      this.updatePrintRange()
                    }else{
                      Log.info(TAG,'this.isRangeRadioEnable = false')
                      this.isRangeRadioEnable = false
                      this.setStartPageStr()
                      this.setEndPageStr()
                    }
                  })
                  .onTouch((e:TouchEvent)=>{
                    e.stopPropagation()
                  })
                  .onMouse((e:MouseEvent)=>{
                    e.stopPropagation()
                  })
                Text($r('app.string.index_from'))
                  .maxLines(Constants.NUMBER_2)
                  .textOverflow({ overflow: TextOverflow.Ellipsis})
                  .textAlign(TextAlign.Start)
                  .fontSize($r('app.float.font_size_body2'))
                  .key('Index_Text_from_pageRange')
                TextInput({ text: this.startPageStr })
                  .key('Index_TextInput_from_pageRange')
                  .width($r('app.float.textInput_pageRange_width'))
                  .height($r('app.float.params_comp_height'))
                  .type(InputType.Number)
                  .maxLength(this.rangeInputLimit)
                  .fontSize($r('app.float.font_size_body2'))
                  .fontColor(this.isRangeRadioEnable?Color.Black:Color.Gray)
                  .border({
                    width: $r('app.float.border_width'),
                    radius: $r('app.float.radius_s'),
                    color: $r('app.color.border_line')
                  })
                  .margin({
                    left: $r('app.float.textInput_pageRange_left_margin'),
                    right: $r('app.float.textInput_pageRange_right_margin')
                  })
                  .backgroundColor(Color.White)
                  .onChange((value: string) => {
                    this.startPage = Number.parseInt(value)
                    this.startPageStr = value//规避前置0输入
                    this.startPageStr = this.startPage.toString()
                    Log.info(TAG, 'from change; value = ' + this.startPage + ' endpage = ' + this.endPage)
                    if (this.startPage < Constants.NUMBER_1) {
                      this.startPage = Constants.NUMBER_1
                    } else if (this.startPage > this.endPage) {
                      this.startPage = this.endPage
                      Log.info(TAG, 'from change; startPage = ' + this.startPage)
                    }
                    if (Number.isNaN(this.startPage)) {
                      this.startPage = Constants.NUMBER_1
                      this.startPageStr = Constants.STRING_NONE
                    }
                    if (!this.firstStartPageEdit) {
                      this.printRangeType = PrintRangeType.RANGE;
                      this.firstStartPageEdit = false
                    }
                    this.updatePrintRange();
                  })
                  .onSubmit(() => {
                    Log.info(TAG,'startPageStr  onSubmit: ',this.startPage.toString())
                    this.setStartPageStr()
                  })
                  .onBlur(() => {
                    Log.info(TAG,'startPageStr  onBlur: ',this.startPage.toString())
                    this.setStartPageStr()
                  })
                  .onFocus(()=>{
                    this.printRangeType = PrintRangeType.RANGE;
                  })
                  .onTouch((e:TouchEvent)=>{
                    e.stopPropagation()
                  })
                  .onMouse((e:MouseEvent)=>{
                    e.stopPropagation()
                  })

                Text($r('app.string.index_to'))
                  .maxLines(Constants.NUMBER_2)
                  .textOverflow({ overflow: TextOverflow.Ellipsis})
                  .textAlign(TextAlign.Start)
                  .fontSize($r('app.float.font_size_body2'))
                  .key('Index_Text_to_pageRange')
                TextInput({ text: this.endPageStr })
                  .width($r('app.float.textInput_pageRange_width'))
                  .height($r('app.float.params_comp_height'))
                  .key('Index_TextInput_to_pageRange')
                  .type(InputType.Number)
                  .maxLength(this.rangeInputLimit)
                  .fontSize($r('app.float.font_size_body2'))
                  .backgroundColor(Color.White)
                  .fontColor(this.isRangeRadioEnable?Color.Black:Color.Gray)
                  .margin({
                    left: $r('app.float.textInput_pageRange_left_margin'),
                    right: $r('app.float.textInput_pageRange_right_margin')
                  })
                  .border({
                    width: $r('app.float.border_width'),
                    radius: $r('app.float.radius_s'),
                    color: $r('app.color.border_line')
                  })
                  .onChange((value: string) => {
                    this.endPage = Number.parseInt(value)
                    this.endPageStr = value//规避前置0输入
                    this.endPageStr = this.endPage.toString()
                    if (this.endPage > this.totalPage) {
                      this.endPage = this.totalPage
                    } else if (this.endPage < this.startPage) {
                      this.endPage = this.startPage
                    }
                    if (Number.isNaN(this.endPage)) {
                      this.endPage = this.startPage
                      this.endPageStr = Constants.STRING_NONE
                    }
                    if(!this.firstEndPageEdit){
                      this.printRangeType = PrintRangeType.RANGE;
                      this.firstEndPageEdit = false
                    }
                    this.updatePrintRange();
                  })
                  .onSubmit(() => {
                    Log.info(TAG,'endPageStr  onSubmit: ',this.endPage.toString())
                    this.setEndPageStr();
                  })
                  .onBlur(() => {
                    this.changeRangeTypeFlag = true;
                    Log.info(TAG,'endPageStr  onBlur: ',this.endPage.toString())
                    this.setEndPageStr();
                  })
                  .onFocus(()=>{
                    this.changeRangeTypeFlag = false;
                    this.printRangeType = PrintRangeType.RANGE;
                    this.updatePrintRange()
                  })
                  .onTouch((e:TouchEvent)=>{
                    e.stopPropagation()
                  })
                  .onMouse((e:MouseEvent)=>{
                    e.stopPropagation()
                  })
              }.height($r('app.float.params_row_height')).width($r('app.float.params_row_width'))
              Row() {
                Radio({ value: 'Radio3', group: 'radioGroup' })
                  .checked(this.printRangeType === PrintRangeType.CUSTOM)
                  .key('Index_Radio_custom_pageRange')
                  .width(24)
                  .margin({
                    left: 98,
                    right: 8
                  })
                  .onChange((value: boolean) => {
                    if (value) {
                      focusControl.requestFocus('Index_TextInput_custom_pageRange')
                      this.printRangeType = PrintRangeType.CUSTOM;
                      Log.info(TAG,'isCustomRadioEnable = true')
                      this.isCustomRadioEnable = true
                      this.updatePrintRange()
                    }else{
                      Log.info(TAG,'isCustomRadioEnable = false')
                      this.isCustomRadioEnable = false
                    }
                  })
                  .onTouch((e:TouchEvent)=>{
                    e.stopPropagation()
                  })
                  .onMouse((e:MouseEvent)=>{
                    e.stopPropagation()
                  })
                Text($r('app.string.index_page_custom'))
                  .fontSize(14)
                  .key('Index_Text_custom_pageRange')
              }.height(48).width(432)
              TextInput({placeholder:$r('app.string.index_page_custom_example'),text: this.cusRangeText }).key('Index_TextInput_custom_pageRange')
                .width(326).height(32).border({ width: 1, radius: 8, color: this.cusRangeBorderColor })
                .margin({
                  bottom: 8,
                  left: 98,
                  right: 8
                })
                .backgroundColor(Color.White)
                .placeholderFont({size:14})
                .fontColor(this.isCustomRadioEnable?Color.Black:Color.Gray)
                .fontSize(14)
                .maxLength(50)
                .onChange((value:string)=>{
                  if (this.editCusRangeFlag) {
                    this.printRangeType = PrintRangeType.CUSTOM;
                  }else{
                    this.editCusRangeFlag = true
                  }
                  this.checkCustomRange(value);
                  this.updatePrintRange();
                  this.cusRangeText = value;
                })
                .onBlur(() => {
                  Log.info(TAG,'cusRangeTextInput onBlur')
                })
                .onFocus(()=>{
                  this.printRangeType = PrintRangeType.CUSTOM;
                })
                .onTouch((e:TouchEvent)=>{
                  e.stopPropagation()
                })
                .onMouse((e:MouseEvent)=>{
                  e.stopPropagation()
                })
              Text(this.errorMessage).key('Index_Text_custom_errorMessage')
                .fontSize($r('app.float.font_size_body3')).fontColor('#E84026').fontWeight(FontWeight.Medium)
                .margin({
                  top: 8,
                  left: 98,
                  right: 20,
                  bottom: 8
                })
                .visibility((this.isCusRangeError || this.isCusRangeMax)?Visibility.Visible:Visibility.None)
            }
            .alignItems(HorizontalAlign.Start)

            MediaSizeSelection()
            DirectionSelection()
            MediaTypeSelection().visibility(!this.isPhotoEnabled ? Visibility.None : Visibility.Visible)
            Row() {
              Blank()
              Row(){
                Checkbox()
                  .select(this.isBorderless)
                  .width($r('app.float.image_comp_width'))
                  .height($r('app.float.image_comp_height'))
                  .enabled(SelectionModel.getSelectionValue<number>(this.currentMediaType.name) === MediaType.PHOTO)
                  .key('Index_Checkbox_borderless')
                  .onChange((value: boolean) => {
                    if (value) {
                      this.showToast($r('app.string.borderless_enable_toast'))
                    }
                    this.isBorderless = value
                  })
              }
              .onClick(() => {
                if (SelectionModel.getSelectionValue<number>(this.currentMediaType.name) !== MediaType.PHOTO) {
                  this.showToast($r('app.string.borderless_type_toast'))
                }
              })
              Text($r('app.string.index_borderless'))
                .fontSize($r('app.float.font_size_body2'))
                .width($r('app.float.text_borderless_width'))
                .opacity(SelectionModel.getSelectionValue<number>(this.currentMediaType.name) === MediaType.PHOTO ? Constants.NUMBER_1 : $r('app.float.disable_opacity'))
                .key('Index_Text_borderless')
            }
            .visibility(!this.isPhotoEnabled? Visibility.None : Visibility.Visible)
            .height($r('app.float.params_row_height'))
            .width($r('app.float.params_row_width'))

            QualitySelection()
            DuplexSelection().visibility(this.isDuplexEnabled ? Visibility.Visible : Visibility.None)
          }
          .alignItems(HorizontalAlign.Start)
          .justifyContent(FlexAlign.Start)
          .margin({ top: $r('app.float.print_setting_padding_top')
          , bottom: $r('app.float.print_setting_padding_bottom')
          })

        }
        // .height($r('app.float.print_setting_height'))
        .height(this.printParamCompHeight-73)
        .width($r('app.float.print_setting_width'))
        .margin({left:24,right:24})
        .scrollable(ScrollDirection.Vertical)  // 滚动方向纵向
        .scrollBar(BarState.Off)
        .edgeEffect(EdgeEffect.None)
        .align(Alignment.Top)
        .enabled(!this.isGlobalDisable)
        .opacity(this.isGlobalDisable?0.4:1)

        Column().height(12)
        Divider()
          .width($r('app.float.print_setting_width'))
          .strokeWidth(Constants.NUMBER_1)
          .color($r('app.color.black'))
          .opacity($r('app.float.divider_opacity'))
          .key('Index_Divider')
        Flex({ direction: FlexDirection.Row, justifyContent: FlexAlign.End, alignItems: ItemAlign.Center }) {
          AboutPageComponent().margin({left:24,right:152})
          CancelButton({
            cancelLabel: $r('app.string.Cancel'),
            cancelWidth: $r('app.float.button_index_width'),
            cancelHeight: $r('app.float.button_index_height'),
            cancelClick: () => {
              this.abilityContext?.terminateSelf().then((data) => {
                console.info('===>terminateSelfCallBack===>: ' + data);
              });
            }
          })
            .key('Index_Button_cancel')
            .margin({ right: $r('app.float.button_index_cancel_margin_right') })

          Button($r('app.string.Index_doPrint'))
            .key('Index_Button_doPrint')
            .width($r('app.float.button_index_width'))
            .height($r('app.float.button_index_height'))
            .margin({ right: $r('app.float.button_index_doPrint_margin_right') })
            .enabled(this.canPrint && this.printButtonFlag && !this.isCusRangeError && !this.isGlobalDisable)
            .fontColor($r('app.color.white'))
            .onClick(() => {
              this.getJobDescription()
              this.startPrint()
            })
        }
        .margin({
          top: $r('app.float.print_setting_margin_top'),
          bottom: $r('app.float.print_setting_margin_bottom')
        })
      }.width($r('app.float.print_setting_width'))
    }
    .onTouch((event:TouchEvent)=>{
      if (event.type === TouchType.Down) {
        Log.info(TAG,'requestFocus')
        focusControl.requestFocus('Index_Text_copies')
      }
    })
  }

  public getPlusImage(mouseState: number,isEnabled :boolean): Resource {
    if (!isEnabled){
      return $r('app.media.ic_plus_disabled');
    }
    switch (mouseState) {
      case MouseState.PRESS:
        return $r('app.media.ic_plusPress');
      case MouseState.HOVER:
        return $r('app.media.ic_plusHover');
      default:
        return $r('app.media.ic_plus');
    }
  }

  public getMinusImage(mouseState: number,isEnabled :boolean): Resource {
    if (!isEnabled){
      return $r('app.media.ic_minus_disabled');
    }
    switch (mouseState) {
      case MouseState.PRESS:
        return $r('app.media.ic_minusPress');
      case MouseState.HOVER:
        return $r('app.media.ic_minusHover');
      default:
        return $r('app.media.ic_minus');
    }
  }

  aboutToAppear() {
    Log.info(TAG, 'aboutToAppear')
    this.getWant()
    this.loadImageSources();
    this.setSelect();
    this.initParams();
    this.bindService();
    this.recordLastUsedPrinter();
    this.preDiscovery();
    this.checkWlan();
    this.subscribe();
  }

  aboutToDisappear() {
    this.unsubscribe()
    this.abilityContext = undefined
    clearInterval(this.connectTimer)
    this.releaseResource();
  }

  releaseResource() {
    Log.info(TAG, 'start release resource');
    if (CheckEmptyUtils.isEmptyArr<FileModel>(this.imageSources)) {
      return;
    }
    for (let imageModel of this.imageSources) {
      imageModel.imageSource.release();
    }
  }

  showToast(message: Resource) {
    try {
      promptAction.showToast({
        message: message,
        duration: Constants.TOAST_INTERVAL,
        bottom: Constants.TOAST_BOTTOM
      });
    } catch (error) {
      Log.error(TAG, `showToast args error code is ${error.code}, message is ${error.message}`);
    }
    ;
  }

  private getWant() {
    this.abilityContext = GlobalThisHelper.getValue<common.UIAbilityContext>(
      GlobalThisStorageKey.KEY_MAIN_ABILITY_CONTEXT)
    if (CheckEmptyUtils.isEmpty<LocalStorage>(storage)) {
      storage = router.getParams() as LocalStorage;
    }
    this.jobId = storage.get<string>(Constants.WANT_JOB_ID_KEY)!;
    this.jobFileList = storage.get<Array<string>>(Constants.WANT_FILE_LIST_KEY)!;
    Log.debug(TAG, 'aboutToAppear jobId: ' + JSON.stringify(this.jobId) + ', fileList: ' + JSON.stringify(this.jobFileList));
  }

  private subscribe() {

    let innerEventState: emitter.InnerEvent = { eventId: AppCommonEvent.PRINTER_STATE_CHANGE_EVENT }
    emitter.on(innerEventState, (eventData) => {
      let printers = AppStorage.get<Array<PrinterInfo>>(AppStorageKeyName.PRINTER_QUEUE_NAME)

      if (this.printer === undefined || printers === undefined) {
        Log.error(TAG, 'emitter callback this printer is null or printers is null, return');
        return
      }
      Log.info(TAG, 'emitter PRINTER_STATE_CHANGE_EVENT callback this.printer: ' +
      StringUtil.encodeCommonString(this.printer.printerName));
      for (let index = 0; index < printers.length; index++) {
        if (printers[index].printerId === this.printer.printerId) {
          this.checkPrinterConnection(printers[index].printerState)
        }
      }
    })

    let innerEventCap: emitter.InnerEvent = { eventId: AppCommonEvent.PRINTER_UPDATE_CAPABILITY_EVENT }
    emitter.on(innerEventCap, (eventData) => {
      let printers = AppStorage.get<Array<PrinterInfo>>(AppStorageKeyName.PRINTER_QUEUE_NAME);
      if (this.printer === undefined || this.printer === null) {
        Log.error(TAG, 'printer is undefined');
        return;
      }
      Log.error(TAG, 'emitter PRINTER_UPDATE_CAPABILITY_EVENT callback this.printer: ' + StringUtil.encodeCommonString(this.printer.printerName));
      if (printers === undefined) {
        Log.error(TAG, 'emitter callback printers is null, return');
        return
      }
      for (let index = 0; index < printers.length; index++) {
        if (printers[index].printerId === this.printer.printerId) {
          clearInterval(this.connectTimer)
          this.connectConfirmDialogCtl.close()
          this.printer.capability = printers[index].capability
          this.printer.options = printers[index].options
          this.printer.description = printers[index].description
          Log.info(TAG, 'this.printer.capability update: ', JSON.stringify(this.printer.capability))
          this.updateSupportParam(printers[index])
        }
      }
    })

    let inactiveWlanEvent: emitter.InnerEvent = { eventId: AppCommonEvent.WLAN_INACTIVE_EVENT }
    emitter.on(inactiveWlanEvent, (eventData) => {
      Log.info(TAG, 'WLAN_INACTIVE_EVENT')
      this.isNeedListenWlan = true
      let isPrinterSelectDialogOpen = GlobalThisHelper.getValue<boolean>(
        GlobalThisStorageKey.KEY_PRINTER_SELECT_DIALOG_OPEN);
      Log.info(TAG, 'isPrinterSelectDialogOpen: ' + isPrinterSelectDialogOpen)
      if (isPrinterSelectDialogOpen) {
        this.PrintingSelectDialogCtl.close()
        GlobalThisHelper.createValue<boolean>(false, GlobalThisStorageKey.KEY_PRINTER_SELECT_DIALOG_OPEN, true);
        this.WLANConfirmDialogCtl.open()
      }
    })

    let activeWlanEvent: emitter.InnerEvent = { eventId: AppCommonEvent.WLAN_ACTIVE_EVENT }
    emitter.on(activeWlanEvent, (eventData) => {
      Log.info(TAG, 'WLAN_ACTIVE_EVENT')
      if (this.isNeedListenWlan) {
        this.isNeedListenWlan = false
        this.adapter?.getPrinterDiscCtl()?.startDiscovery(Constants.STRING_NONE, [])
      }

    })

    let innerEventPrinter: emitter.InnerEvent = { eventId: AppCommonEvent.ADD_PRINTER_EVENT }
    emitter.on(innerEventPrinter, (eventData) => {
      if (!this.firstPrinterDiscoveredFlag){
        this.firstPrinterDiscoveredFlag = true;
      }
      if(this.isGlobalDisable){
        Log.info(TAG, 'last printer no need connecting');
        emitter.off(AppCommonEvent.ADD_PRINTER_EVENT);
        return;
      }
      if (CheckEmptyUtils.isEmpty(eventData) || CheckEmptyUtils.isEmpty(eventData.data)) {
        Log.error(TAG, 'add_printer info is empty.');
        return;
      }
      let printerJSON: string = eventData!.data!.printer
      let printer: PrinterInfo = JSON.parse(printerJSON)
      Log.info(TAG, 'ADD_PRINTER_EVENT')
      if (printer.printerId === this.usedPrinterId) {
        Log.info(TAG, 'last printer is connecting');
        this.printer = printer;
        this.adapter?.getPrinterDiscCtl()?.connectPrinter(printer)
        emitter.off(AppCommonEvent.ADD_PRINTER_EVENT)
      }

    })


    print.on('extInfoChange', (extensionId: string, info: string) => {
      let extInfo: ErrorMessage = JSON.parse(info)
      Log.info(TAG, 'extInfoChange: ', info)
      if (CheckEmptyUtils.isEmpty(this.printer)){
        Log.info(TAG, 'invalid printer！')
        return;
      }
      switch (extInfo.code){
        case ErrorCode.IPP_CONNECT_ERROR:
          this.connectionFailed();
          break;
        case ErrorCode.GET_CAPS_ERROR:
          this.adapter?.getPrinterDiscCtl()?.queryPrinterCapability(this.printer!.printerId);
          break;
        case ErrorCode.CONNECTION_POP:
          if (this.printer!.printerId !== this.usedPrinterId){
            this.connectFlag = !this.connectFlag
          }
        default:
          break;
      }
    })
  }

  private unsubscribe() {
    emitter.off(AppCommonEvent.PRINTER_STATE_CHANGE_EVENT)
    emitter.off(AppCommonEvent.PRINTER_UPDATE_CAPABILITY_EVENT)
    emitter.off(AppCommonEvent.WLAN_INACTIVE_EVENT)

    print.off('extInfoChange')
  }

  preDiscovery() {
    this.adapter?.getPrinterDiscCtl()?.startDiscovery(Constants.STRING_NONE, [])
  }

  checkWlan(){
    if (!WifiP2pHelper.checkWifiActive()) {
      Log.info(TAG,'checkWlan: inactive')
      this.isNeedListenWlan = true;
    }
  }

  bindService() {
    this.adapter = PrintAdapter.getInstance();
  }

  setSelectDefault(disconnectFlag: boolean) {
    if (this.printer === undefined || disconnectFlag) {
      Log.info(TAG, 'setSelectDefault')
      this.currentPrinterSelection = SelectionModel.NO_Printer
      this.printerSelectArray = []
      this.printerSelectArray.push(SelectionModel.Add_Printer)
    }
  }

  initParams() {
    this.printButtonFlag = true
    this.printerPageSize = MediaSizeUtil.mediaSizeToPageSize(
      SelectionModel.getSelectionValue<MediaSize>(SelectionModel.MediaSize_ISO_A4.name))
  }

  setSelect() {
    SelectionModel.initSelectionMap();
    this.setSelectDefault(false);
    this.setMediaSizesSelect();
    this.setDirectionSelect();
    this.setMediaTypeSelect();
    this.setPrintQualitySelect();
    this.setDuplexSelect();
  }

  updatePrintRange() {
    Log.info(TAG, 'updatePrintRange'+ this.startPage+' '+this.endPage)
    this.printRange = []
    switch (this.printRangeType) {
      case PrintRangeType.ALL:
        for (let num = 1; num <= this.totalPage; ) {
          this.printRange.push(num)
          num++
        }
        break;
      case PrintRangeType.RANGE:
        for (let num = this.startPage; num <= this.endPage; ) {
          this.printRange.push(num)
          num++
        }
        break;
      case PrintRangeType.CUSTOM:
        this.printRange = CopyUtil.deepClone(this.cusRangeArr)
        Log.info(TAG,'updatePrintRange CUSTOM  this.printRange ',JSON.stringify(this.printRange))
        break;
      default:
        break;
    }

    if (this.printRange.length === 0){
      if (this.allPages != undefined) {
        this.printRange = CopyUtil.deepClone(this.allPages)
      }else{
        for (let num = 1; num <= this.totalPage; ) {
          this.printRange.push(num)
          num++
        }
      }
    }
    this.imageCount = this.printRange.length
    this.needDuplex = this.imageCount>1?true:false
  }

  updateMediaSize() {
    if (CheckEmptyUtils.isEmpty(this.currentMediaSize)) {
      return
    }
    if (!CheckEmptyUtils.isEmpty(SelectionModel.getSelectionValue<MediaSize>(this.currentMediaSize.name))) {
      this.mediaSize = SelectionModel.getSelectionValue<MediaSize>(this.currentMediaSize.name)!;
      Log.info(TAG, 'updateMediaSize:MediaSize = ' + JSON.stringify(this.mediaSize))
      this.printerPageSize = MediaSizeUtil.mediaSizeToPageSize(this.mediaSize)
    }
    Log.info(TAG, 'afterUpdateMediaSize: ' + this.printerPageSize?.name)
  }

  updateMediaType() {
    if (this.printer !== undefined) {
      let isBSH = this.isBiSheng(this.printer.printerName)
      if (isBSH) {
        this.mediaSizeList = MediaSizeUtil.getDefaultMediaSizeByMediaType(
          SelectionModel.getSelectionValue<number>(this.currentMediaType.name)!);
      }
      this.setMediaSizesSelect()
    }
    this.setPrintQualitySelect()
    if (this.currentMediaType.name === SelectionModel.MediaType_NORMAL.name) {
      Log.info(TAG,'this.isBorderless = false')
      this.isBorderless = false
    }
  }

  updateDirection() {
    this.pageDirection = SelectionModel.getSelectionValue<number>(this.currentMediaType.name)!;
  }

  /**
   * 更新打印机能力支持的参数
   *
   * @param cap
   */
  updateSupportParam(printer: PrinterInfo) {
    Log.info(TAG, 'updateSupportParam printer: ' + StringUtil.encodeCommonString(this.printer?.printerName));
    let cap = printer.capability
    if (CheckEmptyUtils.isEmpty(cap)) {
      return
    }

    if (cap!.colorMode === ColorCode.MONOCHROME) {
      this.colorMode = ColorCode.MONOCHROME
      this.isColored = false
      this.isColorEnabled = false
    }else{
      this.isColorEnabled = true
    }

    if (cap!.duplexMode === Duplex.SINGLE) {
      this.isDuplexEnabled = false;
      this.currentDuplex = SelectionModel.DuplexMode_SINGLE;
    } else {
      this.isDuplexEnabled = true;
    }
    let isBSH = this.isBiSheng(printer.printerName)
    if (isBSH) {
      this.mediaSizeList = MediaSizeUtil.getDefaultMediaSizeByMediaType(
        SelectionModel.getSelectionValue<number>(this.currentMediaType.name)!);
    } else {
      this.mediaSizeList = [];
      for (let index = 0; index < cap!.pageSize.length; index++) {
        this.mediaSizeList.push(MediaSizeUtil.pageSizeToMediaSize(cap!.pageSize[index]))
      }
    }
    Log.debug(TAG,'printer.options:',printer.options)
    let options: PrinterCapsOptions = JSON.parse(printer.options!);
    if(!CheckEmptyUtils.isEmpty(options?.supportedMediaTypes)){
      this.supportedMediaTypes = options?.supportedMediaTypes
    }
    Log.debug(TAG,'supportedMediaTypes:',JSON.stringify(this.supportedMediaTypes))
    this.setMediaTypeSelect()
    this.setMediaSizesSelect()
    this.canPrint = true
  }

  updateImageSources(){
    Log.info(TAG,'updateImageSources length = '+this.imageSources.length)
    this.allPages = []
    for (let num = 1; num <= this.imageSources.length; ) {
      this.allPages.push(num)
      num++
    }
  }

  isBiSheng(printerName: string): boolean {
    Log.info(TAG, 'isBiSheng：', StringUtil.encodeCommonString(printerName));
    return printerName.includes(BISHENG_PRINTER);
  }

  setMediaSizesSelect() {
    if (CheckEmptyUtils.isEmptyArr(this.mediaSizeList)) {
      MediaSizeUtil.initMediaSizeArray(this.mediaSizeList);
    }
    Log.info(TAG, 'setMediaSizesSelect mediaSizeList.length:' + this.mediaSizeList.length);
    this.mediaSizeSelectArray = [];
    let isNeedResetMediaSize = true
    this.mediaSizeList.forEach(mediaSize => {
      if (this.currentMediaSize.res === mediaSize.label) {
        isNeedResetMediaSize = false
      }
      let mediaSizeSelection = SelectionModel.getSelectionModelByLabel(mediaSize.label)!
      if(!CheckEmptyUtils.isEmpty(mediaSizeSelection)){
        this.mediaSizeSelectArray.push(mediaSizeSelection)
      }
    });
    Log.info(TAG, 'this.mediaSizeSelectArray.length: ' + this.mediaSizeSelectArray.length)
    if(isNeedResetMediaSize){
      this.currentMediaSize = SelectionModel.MediaSize_ISO_A4;
    }
  }

  setDirectionSelect() {
    this.directionSelectArray = [];
    this.directionSelectArray.push(SelectionModel.Direction_AUTO,
      SelectionModel.Direction_LANDSCAPE, SelectionModel.Direction_VERTICAL);
  }

  setMediaTypeSelect() {
    this.mediaTypeSelectArray = [];
    if(this.supportedMediaTypes.length === Constants.NUMBER_1){
      this.isPhotoEnabled = false
      this.mediaTypeSelectArray.push(SelectionModel.MediaType_NORMAL)
      if (this.currentMediaType.name == SelectionModel.MediaType_PHOTO.name) {
        this.currentMediaType = SelectionModel.MediaType_NORMAL
      }
    } else {
      this.isPhotoEnabled = true
      this.mediaTypeSelectArray.push(SelectionModel.MediaType_NORMAL, SelectionModel.MediaType_PHOTO)
    }
  }

  setPrintQualitySelect() {
    this.qualitySelectArray = [];
    if (SelectionModel.getSelectionValue<number>(this.currentMediaType.name) === MediaType.NORMAL) {
      this.qualitySelectArray.push(SelectionModel.PrintQuality_BEST, SelectionModel.PrintQuality_STANDARD,
        SelectionModel.PrintQuality_ECONOMY);
    } else {
      this.qualitySelectArray.push(SelectionModel.PrintQuality_BEST, SelectionModel.PrintQuality_STANDARD);
      if (this.currentQuality == SelectionModel.PrintQuality_ECONOMY) {
        this.currentQuality = SelectionModel.PrintQuality_STANDARD
      }
    }
  }


  setDuplexSelect() {
    this.duplexSelectArray = [];
    this.duplexSelectArray.push(SelectionModel.DuplexMode_SINGLE, SelectionModel.DuplexMode_LONG,
      SelectionModel.DuplexMode_SHORT)
  }

  isPrintRangeAll(): boolean {
    Log.info(TAG,'startPage,endPage,totalPage'+this.startPage+' '+this.endPage+' '+this.totalPage )
    if (this.startPage === 1 && (this.endPage === this.totalPage || this.totalPage === Constants.NUMBER_0)) {
      return true;
    } else {
      return false;
    }
  }

  /**
   * 加载第三方应用传过来的图片信息
   *
   * @param name
   */
  async loadImageSources() {
    Log.info(TAG, 'loadImageSources start')
    if (this.jobFileList) {
      this.fileNum = this.jobFileList.length;
      this.imageSources = await FileUtil.initImageData(this.checkMaxPages(this.jobFileList));
    } else {
      await print.queryPrintJobById(this.jobId).then(async (printJob) => {
        if (!CheckEmptyUtils.isEmpty(printJob) && !CheckEmptyUtils.isEmptyArr(printJob.fdList)) {
          this.fileNum = printJob.fdList.length;
          Log.debug(TAG, 'queryPrintJobById printJob: ', JSON.stringify(printJob));
          this.imageSources = await FileUtil.initFdImageData(printJob.fdList);
        }
      })
    }
    Log.debug(TAG, 'loadImageSources imageSources: ', JSON.stringify(this.imageSources))
    this.totalPage = this.imageSources.length === 0 ? 1 : this.imageSources.length
    this.imageCount = this.totalPage
    this.rangeInputLimit = this.totalPage.toString().length
    let errorCount: number = GlobalThisHelper.getValue<number>(GlobalThisStorageKey.KEY_IMAGE_ERROR_COUNT)
    let errorName: string = GlobalThisHelper.getValue<string>(GlobalThisStorageKey.KEY_IMAGE_ERROR_NAME)
    if (this.imageSources.length !== 0){
      if (errorCount === 1) {
        Log.info(TAG, 'loadImageSources this.showToast ')
        setTimeout(() => {//延迟弹窗，否则会概率弹窗失败
          this.showToast($r('app.string.toast_preview_failed',errorName))
        }, Constants.SHOW_TOAST_TIMEOUT);
      } else if (errorCount > 1) {
        setTimeout(() => {//延迟弹窗，否则会概率弹窗失败
          this.showToast($r('app.string.toast_preview_failed_plurals',errorName,errorCount))
        }, Constants.SHOW_TOAST_TIMEOUT);
      }
    }else{
      this.isPreviewFailed = true;
    }
    this.endPage = this.totalPage
    if (this.imageSources.length > Constants.MAX_PAGES) {//需要弹预览失败toast时不用弹100张限制的toast
      this.isAbovePageLimit = true;
      this.endPage = Constants.MAX_PAGES;
    }
    this.isGlobalDisable = this.imageSources.length === 0 ? true : false
    this.endPageStr = this.endPage.toString()
    this.updatePrintRange()


  }

  /**
   * 记录上一次使用过的打印机
   */
  async recordLastUsedPrinter() {
    let printerString = FileUtil.readStringFromFile(this.usedPrinterFileName, this.abilityContext)
    if (CheckEmptyUtils.checkStrIsEmpty(printerString)) {
      Log.error(TAG, 'lasted used printer is null');
      return;
    }
    let printer: PrinterInfo = JSON.parse(printerString);
    this.usedPrinterId = printer.printerId
    Log.info(TAG, 'load last printer: ' + StringUtil.encodeCommonString(printer.printerName));
  }

  /**
   * 保存成功连接并执行过打印的打印机
   *
   * @param printer 打印机信息
   */
  saveLastedUsedPrinter(printer: PrinterInfo | undefined) {
    Log.info(TAG, 'saveLastedUsedPrinter printer: ' + StringUtil.encodeCommonString(printer?.printerName));
    if (CheckEmptyUtils.isEmpty(printer)) {
      Log.error(TAG, 'printer is null')
      return;
    }
    let printerString = JSON.stringify(printer!)
    if (CheckEmptyUtils.checkStrIsEmpty(printerString)) {
      Log.error(TAG, 'printer string is null')
      return;
    }
    FileUtil.writeStringToFile(printerString, this.usedPrinterFileName, this.abilityContext);
    Log.info(TAG, 'printer save success')
  }

  openPrinterSelectDialog() {
    Log.info(TAG,'openPrinterSelectDialog printerSelectFlag : '+this.printerSelectFlag)
    if (this.printerSelectFlag) {
      this.printerSelectFlag = false
      this.PrintingSelectDialogCtl.close();
      this.PrintingSelectDialogCtl.open();
    }
  }

  openWLANDialog() {
    this.WLANConfirmDialogCtl.open()
  }

  connectAlarm() {
    clearInterval(this.connectTimer)
    this.connectConfirmDialogCtl.open()
    this.connectCount = Constants.CONNECT_COUNT
    this.connectTimer = setInterval(() => {
      this.connectCountDown()
    }, Constants.COUNTDOWN_INTERVAL);
  }

  connectCountDown() {
    this.connectCount--
    if (this.connectCount === Constants.COUNTDOWN_ALARM_TO_FAIL) {
      this.connectConfirmDialogCtl.close()
    } else if (this.connectCount === Constants.NUMBER_0 && !this.isConnected) {
      this.connectionFailed()
    }
  }

  onPrinterChange() {
    if (this.printer !== undefined) {
      this.currentPrinterSelection = new SelectionModel(this.printer.printerName, this.printer.printerName);
      SelectionModel.createSelectionValue<PrinterInfo>(this.printer,this.printer.printerName);
      Log.info(TAG, 'onPrinterChange printerName: ' + StringUtil.encodeCommonString(this.currentPrinterSelection.name));
    }
  }


  /**
   * 打印机状态发生变化时进行处理
   *
   * @param printerState 打印机状态
   */
  checkPrinterConnection(printerState: print.PrinterState) {
    Log.error(TAG, 'checkPrinterConnection printerState: ' + JSON.stringify(printerState));
    if (CheckEmptyUtils.isEmpty(this.printer)) {
      Log.error(TAG, 'checkPrinterConnection, invalid printer.');
      return;
    }
    switch (printerState) {
      case print.PrinterState.PRINTER_CONNECTED:
        this.isConnected = true
        this.connectingPrinterId = this.printer!.printerId;
        clearInterval(this.connectTimer)
        this.connectConfirmDialogCtl.close();
        break;
      case print.PrinterState.PRINTER_DISCONNECTED:
        this.connectionFailed()
        break;
      default:
        break;
    }

  }
  /**
   * 将渲染的图片保存
   */
  async saveImage(jobFiles: string[]): Promise<number[]> {
    Log.info(TAG, 'enter saveImage')
    let fileList: number[] = [];
    if (this.mediaSize === undefined) {
      Log.error(TAG, 'this.mediaSize is undefined')
      return fileList;
    }
    let size = this.mediaSize.get300PixelMediaSize();
    let imageSourceIndexList: number[] = [];
    let finalPrintRange = this.checkPrintRange();
    for (let index = 0; index < finalPrintRange.length; index++) {
      imageSourceIndexList.push(finalPrintRange[index] - 1);
    }
    Log.info(TAG, 'imageSourceIndexList: ', JSON.stringify(imageSourceIndexList))
    let len = imageSourceIndexList.length;
    for (let index = 0; index < len; index++) {
      Log.info(TAG,'imageModel START ,this.imageSources '+JSON.stringify(this.imageSources))
      let imageModel = this.imageSources[imageSourceIndexList[index]];
      Log.info(TAG,'imageModel: '+JSON.stringify(imageModel))
      let offCanvas: OffscreenCanvasRenderingContext2D | undefined = undefined;
      let scale: number;
      let offCanvasWidth: number;
      let offCanvasHeight: number;
      let orientation: PageDirection = PageDirection.AUTO;
      if (this.pageDirection === PageDirection.VERTICAL ||
        (this.pageDirection === PageDirection.AUTO && imageModel.height >= imageModel.width)) {
        //竖向 或者 自适应且图片竖向
        Log.debug('VERTICAL');
        offCanvasWidth = px2fp(size.width);
        offCanvasHeight = px2fp(size.height);
        orientation = PageDirection.VERTICAL
      } else if (this.pageDirection === PageDirection.LANDSCAPE ||
        (this.pageDirection === PageDirection.AUTO && imageModel.height <= imageModel.width)) {
        //横向 自适应且图片横向
        Log.debug('LANDSCAPE');
        offCanvasWidth = px2fp(size.height);
        offCanvasHeight = px2fp(size.width);
        orientation = PageDirection.LANDSCAPE
      } else {
        offCanvasWidth = px2fp(size.width);
        offCanvasHeight = px2fp(size.height);
        Log.error('set offCanvas size error');
      }
      offCanvas = new OffscreenCanvasRenderingContext2D(offCanvasWidth, offCanvasHeight,
        new RenderingContextSettings(true));
      if (offCanvas === undefined) {
        Log.error(TAG, 'offCanvas is undefined');
        continue;
      }
      offCanvas.imageSmoothingEnabled = false;
      offCanvas.fillStyle = '#fff'
      offCanvas.fillRect(Constants.NUMBER_0, Constants.NUMBER_0, offCanvasWidth, offCanvasHeight);
      scale = this.isBorderless ? Math.max(offCanvasWidth /
      px2fp(imageModel.width), offCanvasHeight / px2fp(imageModel.height)) :
      Math.min(offCanvasWidth / px2fp(imageModel.width), offCanvasHeight / px2fp(imageModel.height));
      let xPosition = (offCanvasWidth - px2fp(imageModel.width * scale)) / Constants.NUMBER_2;
      let yPosition = (offCanvasHeight - px2fp(imageModel.height * scale)) / Constants.NUMBER_2;

      //将处理好的offCanvas图片写到本地文件
      if (CheckEmptyUtils.isEmpty(imageModel.imageSource)) {
        Log.error(TAG, 'imageSource is error');
        continue;
      }
      Log.info(TAG, 'begin createPixelMap');
      let imageSource: image.ImageSource | undefined = undefined;
      let pixelMap: image.PixelMap | undefined = undefined;
      let canvasPixelMap: image.PixelMap | undefined = undefined;
      try {
        imageSource = image.createImageSource(imageModel.fd);
        if (CheckEmptyUtils.isEmpty(imageSource)) {
          Log.error(TAG, 'imageSource is error')
          continue;
        };
        const editResult: boolean = orientation === PageDirection.LANDSCAPE ? true : false;
        pixelMap = await imageSource!.createPixelMap({editable: editResult});
        if (CheckEmptyUtils.isEmpty(pixelMap)) {
          Log.error(TAG, 'pixelMap is error')
          continue;
        };
        imageModel.imageSource!.release();
        Log.info(TAG, 'end createPixelMap');
        offCanvas.drawImage(pixelMap, xPosition, yPosition, px2fp(imageModel.width * scale),
          px2fp(imageModel.height * scale)) //5184 3456 //1200 2133
        canvasPixelMap = offCanvas.getPixelMap(Constants.NUMBER_0, Constants.NUMBER_0, offCanvasWidth, offCanvasHeight);

        //保存图片
        Log.info(TAG, 'begin createDataShareUri');
        if (CheckEmptyUtils.checkStrIsEmpty(this.firstFileName)) {
          this.firstFileName = imageModel.name;
          Log.info(TAG, 'init firstFileName:' + this.firstFileName)
        }
        let fileName = uuidGenerator() + Constants.JPEG_SUFFIX;
        FileUtil.createJobsDir(this.abilityContext?.filesDir)
        let uri = this.abilityContext?.filesDir + Constants.FILE_SEPARATOR +
        Constants.TEMP_JOB_FOLDER + Constants.FILE_SEPARATOR + fileName
        await FileUtil.saveImageToJpeg(canvasPixelMap, uri, orientation);
        Log.debug(TAG, 'end saveImageToJpeg');
        jobFiles.push(uri);
      } catch (error) {
        Log.error(TAG, 'error happened: ' + JSON.stringify(error))
      } finally {
        //释放资源
        if (pixelMap !== undefined) {
          pixelMap.release();
        }
        if (canvasPixelMap !== undefined) {
          canvasPixelMap.release();
        }
        if (imageSource !== undefined) {
          imageSource.release();
        }
      }
    }
    Log.info(TAG, 'exit saveImage');
    fileList = FileUtil.getFdList(jobFiles);
    this.jobNum = fileList.length
    this.jobName = this.getJobName(this.jobNum)

    return fileList;
  }

  /**
   * 开始打印
   *
   */
  startPrint() {
    Log.info(TAG, 'startPrint')
    this.isGlobalDisable = true
    this.saveLastedUsedPrinter(this.printer)
    if (this.printRangeType === PrintRangeType.CUSTOM) {
      this.checkCustomRangeTextInput(false)
    }

    let jobFiles: string[] = [];
    this.saveImage(jobFiles).then((fileList) => {
      let ops: PrintJobOptions = {
        jobName: this.jobName,
        jobNum: this.jobNum * this.printCount,
        jobDescription: this.jobDes,
        mediaType: this.getMediaType(SelectionModel.getSelectionValue<number>(this.currentMediaType.name)!),
        documentCategory: SelectionModel.getSelectionValue<number>(this.currentMediaType.name) ===
        MediaType.PHOTO ? Constants.NUMBER_1 : Constants.NUMBER_0,
        printQuality: SelectionModel.getSelectionValue<number>(this.currentQuality.name)!.toString(),
        printerName: this.removeSpaces(this.printer?.printerName),
        printerUri: this.getPrinterUri(),
        documentFormat: 'image/jpeg',
        files: jobFiles
      }
      let options = JSON.stringify(ops);
      this.printJob = new PrintJob(jobFiles,fileList,this.jobId, this.printer!.printerId,
        print.PrintJobState.PRINT_JOB_PREPARE, print.PrintJobSubState.PRINT_JOB_COMPLETED_SUCCESS,
        this.printCount,this.printerRange!,true,this.printerPageSize!,true,
        this.colorMode,SelectionModel.getSelectionValue<number>(this.currentDuplex.name)!,
        new PrintMargin(Constants.NUMBER_0, Constants.NUMBER_0, Constants.NUMBER_0, Constants.NUMBER_0),
        new PreviewAttribute(this.printerRange!, Constants.NUMBER_1), options);

      startPrintJob(this.printJob).then((result) => {
        if (result) {
          this.startJobAbility();
        } else { // 任务下发失败
          this.showToast($r('app.string.error_task_send_msg'));
        }
      });
    });
  }

  startJobAbility(){
    let jobAbilityWant: Want = {
      bundleName: Constants.BUNDLE_NAME,
      abilityName: Constants.JOB_MANAGER_ABILITY_NAME,
      parameters: {
        jobId: this.jobId
      },
    }

    this.abilityContext?.startAbility(jobAbilityWant).then(() => {
      Log.info(TAG,'startJobManagerAbility')
      this.canPrint = false;
      this.abilityContext?.terminateSelf().then((data) => {
        console.info('===>terminateSelfCallBack===>: '+data);
      });
    }).catch((err: BusinessError) => {
      Log.error(TAG, 'fail to startAbility, err =' + JSON.stringify(err));
    })
  }

  removeSpaces(name: string | undefined) {
    if (CheckEmptyUtils.checkStrIsEmpty(name)) {
      return '';
    }
    let regex: RegExp = new RegExp('\\s+', 'g');
    return name!.replace(regex, '_');
  }

  getMediaType(selectType: number): string {
    if (MediaTypes.sCodeToStringMap.has(selectType)) {
      return MediaTypes.sCodeToStringMap.get(selectType)!;
    }
    return MediaTypes.sCodeToStringMap.get(MediaTypeCode.MEDIA_PLAIN)!;
  }

  getPrinterUri(): string {
    if (CheckEmptyUtils.isEmpty(this.printer)) {
      return '';
    }
    let options = this.printer!.options;
    let optionObject: PrinterCapsOptions = JSON.parse(options!);
    if (CheckEmptyUtils.checkStrIsEmpty(optionObject.printerUri)) {
      return '';
    }
    return optionObject.printerUri;
  }

  connectionFailed() {
    if (CheckEmptyUtils.isEmpty(this.printer)) {
      Log.error(TAG, 'connectionFailed, invalid printer!');
      return;
    }
    clearInterval(this.ConnectTimer)
    this.alarmText = StringUtil.getString('alarm_dialog_connect_failed')
    this.alarmDialogCtl.open()
    this.printer!.printerId = Constants.STRING_NEGATIVE_ONE
    this.connectingPrinterId = Constants.DEFAULT_CONNECTING_PRINTER_ID
    Log.info(TAG, 'connectCountDown setPrinterId:' + this.printer!.printerId)
    this.setSelectDefault(true)
  }

  getJobName(fileCount: number): string {
    Log.info(TAG, 'getJobName: COUNT' + fileCount)
    let jobName: string = this.firstFileName
    if (fileCount > 1) {
      let nameExt = StringUtil.getString('print_job_name_plurals',fileCount)
      jobName = jobName + nameExt
    }
    Log.debug(TAG,'jobName: ',jobName)
    return jobName
  }

  getJobDescription() {

    let color = Constants.STRING_NONE
    switch (this.colorMode) {
      case ColorCode.COLOR:
        color = StringUtil.getString('ColorMode_COLOR') + StringUtil.getString('pauseMark')
        break;
      case ColorCode.MONOCHROME:
        color = StringUtil.getString('ColorMode_MONOCHROME') + StringUtil.getString('pauseMark')
        break;
    }
    let mediaType = Constants.STRING_NONE
    switch (SelectionModel.getSelectionValue<number>(this.currentMediaType.name)) {
      case MediaType.NORMAL:
        mediaType = StringUtil.getString('MediaType_NORMAL') + StringUtil.getString('pauseMark')
        break;
      case MediaType.PHOTO:
        mediaType = StringUtil.getString('MediaType_PHOTO') + StringUtil.getString('pauseMark')
        break;
    }
    let borderless = Constants.STRING_NONE
    if (this.isBorderless) {
      borderless = StringUtil.getString('pauseMark') + StringUtil.getString('JobDes_BorderLess')
    }
    let quality = Constants.STRING_NONE
    switch (SelectionModel.getSelectionValue<number>(this.currentQuality.name)) {
      case PrintQuality.ECONOMY:
        quality = StringUtil.getString('PrintQuality_ECONOMY') + StringUtil.getString('pauseMark')
        break;
      case PrintQuality.STANDARD:
        quality = StringUtil.getString('PrintQuality_STANDARD') + StringUtil.getString('pauseMark')
        break;
      case PrintQuality.BEST:
        quality = StringUtil.getString('PrintQuality_BEST') + StringUtil.getString('pauseMark')
        break;
    }
    let direction = Constants.STRING_NONE
    switch (SelectionModel.getSelectionValue<number>(this.currentDirection.name)) {
      case PageDirection.AUTO:
        direction = StringUtil.getString('PageDirection_AUTO') + StringUtil.getString('pauseMark')
        break;
      case PageDirection.LANDSCAPE:
        direction = StringUtil.getString('PageDirection_LANDSCAPE') + StringUtil.getString('pauseMark')
        break;
      case PageDirection.VERTICAL:
        direction = StringUtil.getString('PageDirection_VERTICAL') + StringUtil.getString('pauseMark')
        break;
    }
    let duplex = Constants.STRING_NONE

    let size = this.currentMediaSize.res
    let sizeStr =size.toString().split(' ')[0]
    this.jobDes = `${color}${quality}${direction}${mediaType}${sizeStr}${borderless}`
  }

  checkCustomRange(value:string){
    this.cusRangeArr = []
    this.isCusRangeError = false
    this.isCusRangeMax = false
    this.cusRangeBorderColor = $r('app.color.border_line')

    if (value === Constants.STRING_NONE) {
      return
    }

    let prePageArray: string[] = [];
    let pageArray: string[] = [];
    prePageArray = value.split(Constants.EU_COMMA)
    prePageArray.forEach((prePage:string)=>{
      pageArray.push(...prePage.split(Constants.CN_COMMA));
    })

    for (let index = 0; index < pageArray.length; index++){
      let range =pageArray[index].split(Constants.HYPHEN)
      if (range.length === Constants.NUMBER_2) {
        let startNum =  this.checkNum(range[0])
        let endNum =  this.checkNum(range[1])
        if (!(startNum && endNum)){
          this.cusRangeArr = []
          return
        }
        if (startNum>endNum) {
          this.setInvalidRange()
          this.cusRangeArr = []
          return
        }else{
          for (let index:number = startNum; index <= endNum; index++) {
            this.cusRangeArr.push(index);
          }
        }
        continue;
      }

      let num = this.checkNum(pageArray[index])

      if (num){
        this.cusRangeArr.push(num);
      }else{
        this.cusRangeArr = []
        return
      }

    }
    const set = new Set(this.cusRangeArr)
    this.cusRangeArr =  Array.from(set)
    let length = value.length
    if (length >= Constants.MAX_CUSTOM_PRINT_RANGE_LENGTH) {
      this.errorMessage = $r('app.string.cus_range_error_words_limit')
      this.cusRangeBorderColor = $r('app.color.border_line_error')
      this.isCusRangeMax = true
      return
    }
    Log.info(TAG,'checkCustomRange this.cusRangeArr = ',JSON.stringify(this.cusRangeArr))
  }

  checkNum(numStr:string):number | undefined{
    if (numStr.includes('.')||numStr.startsWith('0')){
      this.setInvalidRange()
      return
    }
    let num = Number(numStr)
    if (Number.isNaN(num)||num < 1){
      this.setInvalidRange()
      return undefined
    }else if (num > this.totalPage) {
      this.errorMessage = $r('app.string.cus_range_error_max_image_count',this.totalPage.toString())
      this.cusRangeBorderColor = $r('app.color.border_line_error')
      this.isCusRangeError = true
      return undefined
    }
    return num
  }

  setInvalidRange(){
    this.errorMessage = $r('app.string.cus_range_error_invalid_range')
    this.cusRangeBorderColor = $r('app.color.border_line_error')
    this.isCusRangeError = true
  }

  needDuplexChange(){
    Log.info(TAG,'needDuplexChange ')
    if(!this.needDuplex && !(this.currentDuplex === SelectionModel.DuplexMode_SINGLE)){
      this.currentDuplex = SelectionModel.DuplexMode_SINGLE
    }
  }

  setStartPageStr(){
    this.startPageStr = ''
    this.startPageStr = this.startPage.toString();
  }
  setEndPageStr(){
    this.endPageStr = ''
    this.endPageStr = this.endPage.toString();
  }
  /**
   * 检查传入图片数量，大于100时不与加载
   *
   */
  checkMaxPages(fileList: Array<string>):  Array<string>{
    let returnList: string[] = [];
    if (fileList.length > Constants.MAX_PAGES) {
      returnList = fileList.slice(0,Constants.MAX_PAGES);
      setTimeout(() => {//延迟弹窗，否则会概率弹窗失败
        this.showToast($r('app.string.toast_max_copies'));
      }, Constants.SHOW_TOAST_TIMEOUT);
    } else {
      returnList = fileList
    }
    return returnList
  }

  checkCustomRangeTextInput(isChangeRangeType: boolean){
    if (!isChangeRangeType && this.printRangeType === PrintRangeType.ALL){
      return;
    }
    if (isChangeRangeType) {
      this.editCusRangeFlag = false
      this.cusRangeText = ''
      this.cusRangeArr = []
      this.isCusRangeError = false
      this.isCusRangeMax = false
      this.cusRangeBorderColor = $r('app.color.border_line')
    } else {
      if (CheckEmptyUtils.isEmpty(this.cusRangeText)) {
        if (this.totalPage > Constants.NUMBER_1) {
          if (this.isAbovePageLimit) {
            this.cusRangeText = Constants.NUMBER_1+Constants.HYPHEN+Constants.MAX_PAGES.toString()
          }else{
            this.cusRangeText = Constants.NUMBER_1+Constants.HYPHEN+this.totalPage.toString()
          }
        }else{
          this.cusRangeText = Constants.STRING_ONE
        }
      }
    }

    if (this.cusRangeArr.length === 0 ) {
      this.printRangeType = PrintRangeType.ALL;
      this.updatePrintRange()
    }
  }

  checkPrintRange(): Array<number>{
    let returnList: number = [];
    if (this.printRange.length>100) {
      returnList = PrintUtil.getDefaultArray(100);
    }else{
      returnList = CopyUtil.deepClone(this.printRange);
    }
    if (this.printerRange === undefined) {//下发打印参数需要
      this.printerRange = {
        startPage: this.startPage,
        endPage: this.endPage,
        pages: returnList.slice()
      };
    }else{
      this.printerRange.startPage = this.startPage;
      this.printerRange.endPage = this.endPage;
      this.printerRange.pages = returnList.slice();
    }
    return returnList;
  }
}