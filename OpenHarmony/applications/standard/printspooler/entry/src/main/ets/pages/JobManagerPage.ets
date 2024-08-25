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
import CheckEmptyUtils, {Constants, Log, StringUtil } from '@ohos/common';
import { GlobalThisHelper, GlobalThisStorageKey} from '@ohos/common';
import Util from '../Common/Utils/Util';
import common from '@ohos.app.ability.common';
import { PageData, PrintJobItem, ShowTips } from '../Model/JobViewModel/PrintPageModel';
import { printJobMgrVM, PrintJobViewModel } from '../Model/JobViewModel/PrintJobViewModel';

const TAG = '[JobManagerPage]'
@Entry
@Component
struct JobManagerPage {
  @Provide('Context') abilityContext : common.UIAbilityContext | undefined = undefined;
  @State uiJobQueue: PrintJobItem[] = [];
  @State tips: ShowTips = new ShowTips();
  private viewModel: PrintJobViewModel = printJobMgrVM;
  private delayCloseTimer: number = -1;
  build() {
    Column(){
      Column(){
        Text($r('app.string.print_job')).key('JobManagerPage_Text_printJob')
          .fontSize($r('app.float.font_size_headline8'))
          .fontWeight(FontWeight.Medium)
          .maxLines(Constants.NUMBER_1)
          .textOverflow({overflow:TextOverflow.Ellipsis})
        Text(this.getPrinterName()).key('JobManagerPage_Text_printerName')
          .fontSize($r('app.float.font_size_body2'))
          .fontWeight(FontWeight.Regular)
          .maxLines(Constants.NUMBER_1)
          .textOverflow({overflow:TextOverflow.Ellipsis})
      }
      .justifyContent(FlexAlign.Center)
      .alignItems(HorizontalAlign.Start)
      .width($r('app.float.print_job_comp_width'))
      .height($r('app.float.print_job_title_height'))
      .margin({left:$r('app.float.print_job_margin_left'),right:$r('app.float.print_job_margin_right')})
      Row(){
        Image($r('app.media.ic_printer_tips')).key('JobManagerPage_Image_printerTips')
          .width($r('app.float.image_comp_width'))
          .height($r('app.float.image_comp_height'))
          .margin({right:$r('app.float.print_job_tips_image_margin_right')})
        Text(StringUtil.getStringByName(this.tips.showTipsText, this.abilityContext)).key('JobManagerPage_Text_blockedReason')
          .fontSize($r('app.float.font_size_body2'))
          .fontColor(this.tips.fontColor)
          .fontWeight(FontWeight.Regular)
      }
      .width($r('app.float.print_job_comp_width'))
      .margin({left:$r('app.float.print_job_margin_left'),right:$r('app.float.print_job_margin_right')})
      .visibility(this.tips.isShowTips?Visibility.Visible:Visibility.None)

      Row() {
        List() {
          ForEach(this.uiJobQueue, (jobItem: PrintJobItem)=>{
            ListItem(){
              printJobComponent({ item: jobItem,
                compId: 'JobManagerPage_printJobComponent_'+ jobItem.jobId,
                action: () => {
                  this.viewModel.cancelPrintJob(jobItem.jobId);
                }
              });
            }.key(`JobManagerPage_ListItem_${jobItem.jobId}`)
          }, (jobItem: PrintJobItem)=>jobItem.getKey())
        }
        .key('JobManagerPage_List_jobQueue')
        .edgeEffect(EdgeEffect.Spring)
        .divider({ strokeWidth: $r('app.float.print_job_item_divider_strokeWidth')
        , color: $r('app.color.divider_color'), startMargin: $r('app.float.print_job_item_divider_startMargin')})
      }
      .width($r('app.float.print_job_comp_width'))
      .height($r('app.float.print_job_height'))
      .margin({left:$r('app.float.print_job_margin_left'),right:$r('app.float.print_job_margin_right')})
      .alignItems(VerticalAlign.Top)
      Button($r('app.string.JobManagerPage_ok')).key('JobManagerPage_Button_confirmed')
        .fontColor($r('app.color.button_cancel_text'))
        .backgroundColor($r('app.color.button_color_cancel'))
        .width($r('app.float.print_job_button_width'))
        .height($r('app.float.print_job_button_height'))
        .margin({top:$r('app.float.print_job_button_margin_top'),bottom:$r('app.float.print_job_button_margin_bottom')})
        .onClick(()=>{
          this.abilityContext?.terminateSelf().then((data) => {
            Log.info('===>terminateSelfCallBack===>: '+data);
          });
        })
    }
    .width('100%')
    .height('100%')
    .backgroundColor(Color.White)
    .alignItems(HorizontalAlign.Center)
  }

  aboutToAppear() {
    this.abilityContext = GlobalThisHelper.getValue<common.UIAbilityContext>(
      GlobalThisStorageKey.KEY_JOB_MANAGER_ABILITY_CONTEXT);
  }

  onPageShow() {
    Log.debug(TAG, 'onPageShow');
    this.viewModel.aboutToAppear(this);
    this.viewModel.getPrintJobQueue();
  }

  onPageHide() {
    Log.debug(TAG, 'onPageHide');
    this.viewModel.aboutToDisappear();
  }

  onPrintItemsChanged(data: PageData) {
    Log.info(TAG, 'onPrintItemsChanged enter.');
    this.tips = data.tips;
    this.uiJobQueue = data.uiJobQueue;
    Log.info(TAG, `onPrintItemsChanged length:${this.uiJobQueue.length}, tips:${this.tips.toString()}`);
    if (this.uiJobQueue.length === 0) {
      this.delayCloseTimer = setTimeout(() => {
        this.abilityContext?.terminateSelf().then((data) => {
          Log.info(TAG, 'all print jobs has been finished, '+data);
        });
      }, Constants.SHOW_JOB_COMPLETED_TIMEOUT);
    } else {
      if (this.delayCloseTimer !== -1) {
        clearTimeout(this.delayCloseTimer);
        this.delayCloseTimer = -1;
      }
    }
  }

  getPrinterName(): string {
    let printerName = '';
    let printerInfo = Util.getLastUsedPrinterInfo(this.abilityContext);
    if (!CheckEmptyUtils.isEmpty(printerInfo)) {
      printerName = printerInfo.printerName;
    }
    return printerName;
  }
}

@Component
struct printJobComponent {
  item?: PrintJobItem;
  compId?: string;
  action?: () => void;
  @Consume('Context') context : common.UIAbilityContext
  @State imagePath: Resource = $r('app.media.ic_delete')

  build(){
    Flex({justifyContent: FlexAlign.SpaceBetween, alignItems:ItemAlign.Center}) {
      Image(this.item!.fileNum > Constants.NUMBER_1 ? $r('app.media.ic_two') : $r('app.media.ic_one'))
        .width($r('app.float.image_comp_width')).height($r('app.float.image_comp_height')).objectFit(ImageFit.Contain).flexGrow(0).flexShrink(0).key(this.compId + '_image')
      Column() {
        Text(this.item?.jobTitleText)
          .fontSize($r('sys.float.ohos_id_text_size_body3'))
          .fontWeight(FontWeight.Regular)
          .fontFamily('sans-serif')
          .fontStyle(FontStyle.Normal)
          .fontColor($r('sys.color.ohos_id_color_primary'))
          .textOverflow({ overflow: TextOverflow.Ellipsis })
          .maxLines(1)
          .key(this.compId + '_jobTitle')
        Text(this.item!.jobDescriptionText)
          .fontSize($r('sys.float.ohos_id_text_size_body3'))
          .fontWeight(FontWeight.Regular)
          .fontFamily('sans-serif')
          .fontStyle(FontStyle.Normal)
          .fontColor($r('sys.color.ohos_id_color_secondary'))
          .textOverflow({ overflow: TextOverflow.Ellipsis })
          .maxLines(1)
          .margin({ top: '2vp', bottom: '2vp' })
          .key(this.compId + '_jobDescriptionText')
        Text(this.context?.resourceManager?.getStringByNameSync(this.item!.jobStateStrName) ?? '')
          .fontSize($r('sys.float.ohos_id_text_size_body3'))
          .fontColor(this.item!.jobStateColor)
          .fontWeight(FontWeight.Regular)
          .textOverflow({ overflow: TextOverflow.Ellipsis })
          .key(this.compId + '_jobStateStrName')
      }
      .alignItems(HorizontalAlign.Start).justifyContent(FlexAlign.SpaceBetween)
      .width($r('app.float.print_job_item_des_width'))
      .margin({right: '12vp'})

      Image(this.imagePath).width($r('app.float.image_comp_width')).height($r('app.float.image_comp_height')).objectFit(ImageFit.Contain)
        .visibility(this.item!.isHideCancelBtn ? Visibility.Hidden:Visibility.Visible)
        .key(this.compId + '_deleteBtn')
        .onHover((isHover: boolean) => {
          if (isHover) {
            this.imagePath = $r('app.media.ic_delete_hover');
          } else {
            this.imagePath = $r('app.media.ic_delete');
          }
        })
        .onTouch((event: TouchEvent) => {
          if (event.type === TouchType.Down) {
            this.imagePath = $r('app.media.ic_delete_press');
          }
          if (event.type === TouchType.Up) {
            this.imagePath = $r('app.media.ic_delete');
          }

        })
        .onClick(this.action)
    }
    .height($r('app.float.print_job_item_height'))
    .padding({top :'4vp', bottom: '4vp'})
  }
}