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

import { PrinterInfo, PrintJob, queryAllPrintJobs} from '@ohos/common';
import PrintAdapter from '../../Common/Adapter/PrintAdapter'
import { GlobalThisHelper, GlobalThisStorageKey} from '@ohos/common';
import {Constants } from '@ohos/common'
import { Log } from '@ohos/common';
import { CopyUtil }from '@ohos/common';
import promptAction from '@ohos.promptAction';
import {CancelButton} from '../component/BaseComponent';

const TAG = 'CusDialogComp'

@CustomDialog
export struct PrintingSelectDialog{
  @StorageLink('PrinterQueue') printerList: PrinterInfo[] = [];
  @Consume('PrintAdapter') adapter:PrintAdapter;
  @Consume('PrinterSelectFlag') printerSelectFlag:boolean;
  @Consume('WLANFlag') wlanFlag:boolean;
  private printingSelectDialogCtl?: CustomDialogController;

  build(){
    Column() {
      Row(){
        Text($r('app.string.custom_dialog_choose_printer')).key('PrintingSelectDialog_Text_choosePrinter')
          .fontWeight(FontWeight.Medium)
          .fontSize($r('app.float.font_size_headline8'))
          .textAlign(TextAlign.Start)
      }
      .justifyContent(FlexAlign.Start)
      .width('100%')
      .height($r('app.float.printer_select_title_height'))
      .padding({left:$r('app.float.printer_select_padding_left'),right:$r('app.float.printer_select_padding_right')})
      //show printer list
      Stack(){
        List({initialIndex: Constants.NUMBER_0}){
          ForEach(this.printerList,(printer: PrinterInfo)=>{
            ListItem(){
              printerItem({currentPrinter:printer,printingSelectDialogCtl:this.printingSelectDialogCtl})
            }.key(`PrintingSelectDialog_ListItem_${printer.printerName}`)
          },(printer: PrinterInfo)=>JSON.stringify(printer))
        }.key('PrintingSelectDialog_List_printerList')
        .width('100%')
        .height(this.getAdjustedHeight())
        .edgeEffect(EdgeEffect.Spring)

        Flex({ direction: FlexDirection.Column, alignItems: ItemAlign.Center, justifyContent: FlexAlign.Center }) {
          Column(){
            Image($r('app.media.ic_no_printer')).fillColor('#66000000').width(96).height(96).margin({bottom:8})
            Text($r('app.string.custom_dialog_no_printer')).fontColor('#66000000').fontSize($r('app.float.font_size_body2'))
          }
        }.width($r('app.float.no_printer_image_width')).height($r('app.float.no_printer_image_height')).backgroundColor($r('app.color.white'))
        .visibility(this.printerList.length === Constants.NUMBER_0 ? Visibility.Visible : Visibility.None)
      }

      CancelButton({
        cancelLabel: $r('app.string.Cancel'),
        cancelWidth: $r('app.float.dialog_button_width'),
        cancelHeight: $r('app.float.dialog_button_height'),
        cancelClick: () => {
          this.printingSelectDialogCtl?.close()
          GlobalThisHelper.createValue<boolean>(false, GlobalThisStorageKey.KEY_PRINTER_SELECT_DIALOG_OPEN, true)
        }
      })
        .margin({top:$r('app.float.printer_select_button_margin_top'), bottom:$r('app.float.printer_select_button_margin_bottom')})
        .key('PrintingSelectDialog_Button_cancel')


    }
    .width($r('app.float.dialog_width'))
    .backgroundColor(Color.White)
    .borderRadius($r('app.float.radius_l'))
    .alignItems(HorizontalAlign.Center)
  }

  aboutToAppear(){
    Log.info(TAG,'PrintingSelectDialog aboutToAppear');
    GlobalThisHelper.createValue<boolean>(true, GlobalThisStorageKey.KEY_PRINTER_SELECT_DIALOG_OPEN, true);
    Log.info(TAG,'createValue KEY_PRINTER_SELECT_DIALOG_OPEN: '+true)
  }

  getAdjustedHeight():number | Resource {
    let height: number | Resource = Constants.NUMBER_48;
    if(this.printerList.length < Constants.NUMBER_9){
      height = Constants.NUMBER_48 * this.printerList.length
    }else{
      height = $r('app.float.printer_select_max_height')
    }
    Log.info(TAG,'getAdjustedHeight: '+height)
    return height
  }
}

@Component
struct printerItem{
  private printingSelectDialogCtl?: CustomDialogController;
  private currentPrinter ?: PrinterInfo;
  @Consume('CanPrint') canPrint:boolean;
  @Consume('Printer') printer:PrinterInfo;
  @Consume('PrintAdapter') adapter:PrintAdapter;
  @Consume('ConnectFlag') connectFlag:boolean;
  @Consume('PrinterSelectFlag') printerSelectFlag:boolean;
  @Consume('ConnectCountDownTimer') timer:number;
  @Consume('ConnectingPrinterId') connectingPrinterId:string;
  @Consume('UsedPrinterId') usedPrinterId: string;
  @State bgColor : Resource = $r('app.color.white')

  build(){
    Row() {
      Image($r('app.media.ic_public_printer'))
        .width($r('app.float.image_comp_width'))
        .height($r('app.float.image_comp_height'))
        .margin({left:$r('app.float.printer_select_item_image_margin_left'),right:$r('app.float.printer_select_item_image_margin_right')})
      Text(this.currentPrinter?.printerName)
        .margin({right:$r('app.float.printer_select_item_text_margin_right')})
        .fontSize($r('app.float.font_size_body1'))
    }
    .backgroundColor(this.bgColor)
    .borderRadius($r('app.float.radius_l')).height($r('app.float.printer_select_item_height'))
    .width('100%').margin({left:$r('app.float.printer_select_item_padding_left'),right:$r('app.float.printer_select_item_padding_right')})
    .onClick(()=>{
      this.handleToConnect()
    })
    .onHover((isHover: boolean) => {
      if (isHover) {
        this.bgColor =  $r('app.color.effect_color_hover')
      } else {
        this.bgColor =  $r('app.color.white')
      }
    })
    .onTouch((event: TouchEvent) => {
      if (event.type === TouchType.Down) {
        this.bgColor =  $r('app.color.effect_color_press')
      }
      if (event.type === TouchType.Up) {
        this.bgColor =  $r('app.color.white')
      }
    })
  }

  async handleToConnect(){
    let result:PrintJob[] = await queryAllPrintJobs(this.usedPrinterId)
    Log.info(TAG,'handleToConnect after queryAllPrintJobs')
    Log.info(TAG,'handleToConnect typeof result'+typeof result)
    Log.info(TAG,'handleToConnect this.currentPrinter.printerId'+this.currentPrinter?.printerId)
    if (this.usedPrinterId !== this.currentPrinter?.printerId &&
      result!==undefined && result.length!==0 &&
      !this.checkPrintingPrinter(this.currentPrinter!.printerId,result)){
      this.printingSelectDialogCtl?.close()
      GlobalThisHelper.createValue<boolean>(false, GlobalThisStorageKey.KEY_PRINTER_SELECT_DIALOG_OPEN, true)
      this.showToast($r('app.string.toast_cannot_connect_while_printing'))
    }else{
      Log.info(TAG,'handleToConnect result.length==0 ')
      clearInterval(this.timer)
      if (this.printer === undefined ||
        this.printer.printerId === Constants.STRING_NEGATIVE_ONE ||
        this.printer.printerId !== this.currentPrinter!.printerId) {
        this.checkConnectingPrinter()
        if (this.canPrint) {
          this.canPrint = false
        }
      }
      this.printer = CopyUtil.deepClone(this.currentPrinter)
      this.printingSelectDialogCtl?.close()
      GlobalThisHelper.createValue<boolean>(false, GlobalThisStorageKey.KEY_PRINTER_SELECT_DIALOG_OPEN, true)
    }

  }


  checkConnectingPrinter(){
    if (this.connectingPrinterId !== Constants.DEFAULT_CONNECTING_PRINTER_ID) {
      this.adapter?.getPrinterDiscCtl()?.disconnectPrinter(this.connectingPrinterId).then(() => {
        this.startConnect();
      });
    } else {
      this.startConnect()
    }
  }

  checkPrintingPrinter(printerId: string,jobs: Array<PrintJob>): boolean{
    let job = jobs.find((printJob)=>{
      return printJob.printerId === printerId
    });
    if (job === undefined || job === null) {
      Log.info(TAG,'checkPrintingPrinter false')
      return false;
    }else{
      Log.info(TAG,'checkPrintingPrinter true')
      return true;
    }
  }

  startConnect(){
    Log.info(TAG, 'startConnect printConnect: ' + JSON.stringify(this.currentPrinter));
    this.adapter?.getPrinterDiscCtl()?.connectPrinter(this.currentPrinter)
    this.connectingPrinterId = this.currentPrinter!.printerId
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
    };
  }



}

@CustomDialog
export struct alarmDialog{
  private alarmDialogCtl?: CustomDialogController
  private alarmText: string = Constants.STRING_NONE;
  build(){
    Column(){
      Image($r('app.media.ic_tip')).key('AlarmDialog_Image_tips')
        .height($r('app.float.alarm_dialog_image_height'))
        .width($r('app.float.alarm_dialog_image_width'))
        .margin({top:$r('app.float.alarm_dialog_image_margin_top')})
      Text(this.alarmText).key('AlarmDialog_Text_alarmText')
        .fontWeight(FontWeight.Medium)
        .fontSize($r('app.float.font_size_headline8'))
        .margin({top:$r('app.float.alarm_dialog_text_margin_top'),left:$r('app.float.alarm_dialog_text_margin_left')
        ,right:$r('app.float.alarm_dialog_text_margin_right'),bottom:$r('app.float.alarm_dialog_text_margin_bottom')})
      Button($r('app.string.confirm')).key('AlarmDialog_Button_confirm')
        .width($r('app.float.dialog_button_width'))
        .height($r('app.float.dialog_button_height'))
        .margin({bottom:$r('app.float.dialog_button_margin_bottom')})
        .onClick(()=>{
          this.alarmDialogCtl?.close()
        })
    }
    .width($r('app.float.dialog_width'))
    .height($r('app.float.alarm_dialog_height'))
    .backgroundColor($r('app.color.white'))
    .borderRadius($r('app.float.radius_l'))
    .alignItems(HorizontalAlign.Center)
  }
}

@CustomDialog
export struct WLANConfirmDialog{
  private WLANConfirmDialogCtl: CustomDialogController
  @Consume('PrintAdapter') adapter:PrintAdapter;
  @Consume('PrinterSelectFlag') printerSelectFlag:boolean
  @Consume('IsNeedListenWlan') isNeedListenWlan:boolean
  build(){
    Column(){
      Text($r('app.string.wlan_confirm_dialog_open_wlan')).key('WLANConfirmDialog_Text_openWIFI')
        .fontWeight(FontWeight.Regular)
        .fontSize($r('app.float.font_size_body1'))
        .margin({top:$r('app.float.wlan_dialog_text_margin_top'),left:$r('app.float.wlan_dialog_text_margin_left')
        ,right:$r('app.float.wlan_dialog_text_margin_right'),bottom:$r('app.float.wlan_dialog_text_margin_bottom')})
      Row(){
        CancelButton({
          cancelLabel: $r('app.string.JobManagerPage_ok'),
          cancelWidth: $r('app.float.wlan_dialog_button_width'),
          cancelHeight: $r('app.float.dialog_button_height'),
          cancelClick: () => {
            this.WLANConfirmDialogCtl.close()
          }
        })
          .margin({right:$r('app.float.wlan_dialog_button_cancel_margin_right')})
          .key('WLANConfirmDialog_Button_cancel')
      }.margin({left:$r('app.float.wlan_dialog_buttons_margin_left'),right:$r('app.float.wlan_dialog_buttons_margin_right')
      ,bottom:$r('app.float.wlan_dialog_buttons_margin_bottom')})
    }
    .width($r('app.float.dialog_width'))
    .backgroundColor($r('app.color.white'))
    .borderRadius($r('app.float.radius_l'))
    .alignItems(HorizontalAlign.Center)
  }

  aboutToAppear(){}

  showToast(message: Resource) {
    try {
      promptAction.showToast({
        message: message,
        duration: Constants.TOAST_INTERVAL,
        bottom: Constants.TOAST_BOTTOM
      });
    } catch (error) {
      Log.error(TAG, `showToast args error code is ${error.code}, message is ${error.message}`);
    };
  }
}

@CustomDialog
export struct connectConfirmDialog{
  private connectConfirmDialogCtl: CustomDialogController
  @Consume('ConnectCountDown') count:number

  build(){
    Column(){
      Text($r('app.string.connect_confirm_dialog_confirm')).key('ConnectConfirmDialog_Text_confirm')
        .fontWeight(FontWeight.Medium)
        .maxFontSize($r('app.float.connect_dialog_text_max_font'))
        .minFontSize($r('app.float.connect_dialog_text_min_font'))
        .maxLines(Constants.NUMBER_2)
        .textOverflow({overflow:TextOverflow.Ellipsis})
        .margin({top:$r('app.float.connect_dialog_text_margin_top'),left:$r('app.float.connect_dialog_text_margin_left')
        ,right:$r('app.float.connect_dialog_text_margin_right'),bottom:$r('app.float.connect_dialog_text_margin_bottom')})
      Text($r('app.string.connect_confirm_dialog_tips')).key('ConnectConfirmDialog_Text_tips')
        .fontWeight(FontWeight.Medium)
        .fontSize($r('app.float.font_size_body1'))
        .margin({left:$r('app.float.connect_dialog_confirm_text_margin_left'),right:$r('app.float.connect_dialog_confirm_text_margin_right')
        ,bottom:$r('app.float.connect_dialog_confirm_text_margin_bottom')})
      Button($r('app.string.connectConfirmDialog_countDown',this.count-Constants.COUNTDOWN_TO_FAIL))
        .key('ConnectConfirmDialog_Button_confirmed')
        .fontColor($r('sys.color.ohos_id_color_text_primary_activated'))
        .backgroundColor($r('sys.color.ohos_id_color_button_normal'))
        .width($r('app.float.dialog_button_width'))
        .height($r('app.float.dialog_button_height'))
        .margin({bottom:$r('app.float.connect_dialog_button_margin_bottom')})
        .onClick(()=>{
          this.connectConfirmDialogCtl.close()
        })
    }
    .width($r('app.float.dialog_width'))
    .backgroundColor($r('app.color.white'))
    .borderRadius($r('app.float.radius_l'))
    .alignItems(HorizontalAlign.Center)
  }

}