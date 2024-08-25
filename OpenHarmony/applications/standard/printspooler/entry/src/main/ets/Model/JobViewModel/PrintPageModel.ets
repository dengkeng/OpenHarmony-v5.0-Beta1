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
import { Log, PrintJob, PrintJobOptions, StringUtil } from '@ohos/common';

const TAG: string = 'PrintPageModel';
/**
 * 打印任务界面显示的每一行Item数据
 */
export class PrintJobItem {
  /**
   * jobId
   */
  public jobId: string = '';
  /**
   * 文件数量
   */
  public fileNum: number = 1;
  /**
   * 打印任务Title-文件名称
   */
  public jobTitleText: string = '';
  /**
   * 打印任务详情-参数项
   */
  public jobDescriptionText: string = '';
  /**
   * 任务状态描述
   */
  public jobStateStrName: string = '';
  /**
   * 打印任务删除按钮是否隐藏
   */
  public isHideCancelBtn: boolean = true;
  /**
   * 打印任务是否block
   */
  public jobStateColor: Resource;

  constructor(job: PrintJob, isHideCancelBtn: boolean, jobStateColor: Resource, jobStateStrName: string) {
    this.jobId = job.jobId;
    this.isHideCancelBtn = isHideCancelBtn;
    this.jobStateStrName = jobStateStrName;
    this.jobStateColor = jobStateColor;
    try {
      let optObj: PrintJobOptions = JSON.parse(job.options);
      this.fileNum = optObj?.jobNum ?? 1;
      this.jobTitleText = optObj?.jobName ?? '';
      this.jobDescriptionText = optObj?.jobDescription ?? '';
    } catch (err) {
      Log.error(TAG, `PrintJobItem constructor failed, parse Options err:${JSON.parse(err)}`);
    }
  }

  toString(): string {
    return `[PrintJobItem jobId:${this.jobId} , fileNum:${this.fileNum}, jobTitleText:${StringUtil.encodeCommonString(this.jobTitleText)},
jobDescriptionText:${this.jobDescriptionText}, jobStateStrName:${this.jobStateStrName}, isHideCancelBtn:${this.isHideCancelBtn},
jobStateColor:${this.jobStateColor} ]`;
  }

  getKey(): string {
    return this.jobId + '_' + this.jobStateStrName;
  }
}

@Observed
export class ShowTips {
  /**
   * 是否显示横幅提示
   */
  public isShowTips: boolean = false;
  /**
   * 横幅提示内容
   */
  public showTipsText: string = '';
  /**
   * 横幅提示文本字体颜色
   */
  public fontColor: Resource = $r('sys.color.ohos_id_color_warning');
  /**
   * 横幅提示图标
   */
  public icon: Resource = $r('app.media.ic_printer_tips');

  toString(): string {
    return `[ShowTips isShowTips:${this.isShowTips}, showTipsText:${this.showTipsText} ]`;
  }
}

/**
 * 任务列表界面数据
 */
export class PageData {
  public tips: ShowTips;
  public uiJobQueue: Array<PrintJobItem> = [];

  constructor(tips: ShowTips, uiJobQueue: Array<PrintJobItem>) {
    this.tips = tips;
    this.uiJobQueue = uiJobQueue;
  }

  toString(): string {
    let ret: string = '[PageData tips: ' + this.tips.toString();
    for (let i = 0; i < this.uiJobQueue.length; i++) {
      ret += this.uiJobQueue[i].toString();
    }
    ret += ']';
    return ret;
  }
}