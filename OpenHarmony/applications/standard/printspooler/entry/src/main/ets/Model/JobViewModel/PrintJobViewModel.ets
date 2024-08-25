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
import print from '@ohos.print';
import { cancelPrintJob, CustomPrintJobState, Log, PrintItemChangeListener, PrintJob, SingletonHelper } from '@ohos/common';
import { printJobMgr } from '../../Controller/PrintJobManager';
import { PageData, PrintJobItem, ShowTips } from './PrintPageModel';

const TAG: string = 'PrintJobViewModel';
const COMPLETED_STATUS = 'completed';
/**
 * 打印任务状态-任务状态描述字串id映射集合
 */
const JOB_STATUS_MAP: Map<number, string> = new Map([
  [print.PrintJobState.PRINT_JOB_PREPARE, 'print_job_created'],
  [print.PrintJobState.PRINT_JOB_QUEUED, 'print_job_created'],
  [print.PrintJobState.PRINT_JOB_RUNNING, 'print_job_printing'],
  [print.PrintJobState.PRINT_JOB_BLOCKED, 'print_job_blocked'],
  [CustomPrintJobState.PRINT_JOB_CANCELLING as number, 'print_job_cancelling'],
  [print.PrintJobState.PRINT_JOB_COMPLETED, COMPLETED_STATUS]
]);
/**
 * 打印任务完成状态-任务状态描述字串id映射集合
 */
const JOB_COMPLETED_MAP: Map<number, string> = new Map([
  [print.PrintJobSubState.PRINT_JOB_COMPLETED_SUCCESS, 'print_job_completed'],
  [print.PrintJobSubState.PRINT_JOB_COMPLETED_FAILED, 'print_job_failed'],
  [print.PrintJobSubState.PRINT_JOB_COMPLETED_CANCELLED, 'print_job_cancelled']
]);
/**
 * 横幅提示集合：
 */
const SHOW_TIPS_MAP: Map<number, string> = new Map([
  [print.PrintJobSubState.PRINT_JOB_BLOCK_DOOR_OPEN, 'printer_door_open'],
  [print.PrintJobSubState.PRINT_JOB_BLOCK_BUSY, 'printer_busy'],
  [print.PrintJobSubState.PRINT_JOB_BLOCK_JAMMED, 'printer_jammed'],
  [print.PrintJobSubState.PRINT_JOB_BLOCK_LOW_ON_INK, 'printer_low_on_ink'],
  [print.PrintJobSubState.PRINT_JOB_BLOCK_OFFLINE, 'printer_offline'],
  [print.PrintJobSubState.PRINT_JOB_BLOCK_LOW_ON_TONER, 'printer_low_on_toner'],
  [print.PrintJobSubState.PRINT_JOB_BLOCK_OUT_OF_INK, 'printer_out_of_ink'],
  [print.PrintJobSubState.PRINT_JOB_BLOCK_OUT_OF_PAPER, 'printer_out_of_paper'],
  [print.PrintJobSubState.PRINT_JOB_BLOCK_OUT_OF_TONER, 'printer_out_of_tone'],
  [print.PrintJobSubState.PRINT_JOB_BLOCK_REALLY_LOW_ON_INK, 'printer_out_of_ink'],
  [print.PrintJobSubState.PRINT_JOB_BLOCK_SERVICE_REQUEST, 'printer_check'],
  [print.PrintJobSubState.PRINT_JOB_BLOCK_BAD_CERTIFICATE, 'printer_bad_certificate'],
  [print.PrintJobSubState.PRINT_JOB_BLOCK_NETWORK_ERROR, 'print_block_reason_network_error']
]);
/**
 * 打印任务管理界面基础数据模型
 */
export class PrintJobViewModel {
  private uiJobsMap: Map<string, PrintJobItem> = new Map();
  private listener: PrintItemChangeListener | null = null;
  private tips: ShowTips = new ShowTips();
  aboutToAppear(listener: PrintItemChangeListener): void {
    Log.info(TAG, 'aboutToAppear');
    this.listener = listener;
    printJobMgr.registerJobChangeListener(TAG, this);
  }

  aboutToDisappear(): void {
    this.listener = null;
    printJobMgr.unregisterJobChangeListener(TAG);
    this.uiJobsMap.clear();
  }

  getPrintJobQueue(): void {
    printJobMgr.getPrintJobQueue();
  }

  private getJobStateStrName(jobState: number, jobSubState: print.PrintJobSubState): string {
    Log.debug(TAG, `getJobStateStrName enter jobState:${jobState}, jobSubState:${jobSubState}`);
    let jobStateStrName = JOB_STATUS_MAP.get(jobState)!;
    if (jobStateStrName === COMPLETED_STATUS) {
      jobStateStrName = JOB_COMPLETED_MAP.get(jobSubState)!;
    }
    Log.debug(TAG, `getJobStateStrName end jobStateStrName:${jobStateStrName}`);
    return jobStateStrName;
  }

  private updateShowTips(blockedSubState: number): void {
    if (blockedSubState != -1) {
      this.tips.isShowTips = true;
      this.tips.showTipsText = SHOW_TIPS_MAP.get(blockedSubState)!;
      this.tips.fontColor = $r('sys.color.ohos_id_color_warning');
      this.tips.icon = $r('app.media.ic_print_warning_tips');
    } else {
      this.tips.isShowTips = false;
      this.tips.showTipsText = '';
    }
  }

  private getJobStateFontColor(jobState: number, jobSubState?: print.PrintJobSubState): Resource {
    Log.debug(TAG, 'getJobStateFontColor enter jobState: ' + jobState + ' ,jobSubState:' + jobSubState);
    let color: Resource;
    if (jobState == print.PrintJobState.PRINT_JOB_BLOCKED) {
      color = $r('app.color.text_jobState_blocked');
    } else if (jobState == print.PrintJobState.PRINT_JOB_COMPLETED) {
      color = $r('app.color.text_jobState_completed');
    } else {
      color = $r('app.color.text_jobState_running');
    }
    return color;
  }

  private isHideCancelBtn(jobState: number) : boolean {
    return jobState == print.PrintJobState.PRINT_JOB_COMPLETED;
  }

  onAddPrintJob(job: PrintJob, blockedSubState: number) : void {
    Log.info(TAG, 'onAddPrintJob enter.');
    if (!this.uiJobsMap.has(job.jobId)) {
      Log.info(TAG, `onAddPrintJob jobId:${job.jobId}, blockedSubState:${blockedSubState}`);
      let jobStateStrName: string = this.getJobStateStrName(job.jobState as number, job.jobSubstate);
      let jobStateFontColor: Resource = this.getJobStateFontColor(job.jobState as number, job.jobSubstate);
      let jobItem: PrintJobItem = new PrintJobItem(job, this.isHideCancelBtn(job.jobState as number),
        jobStateFontColor, jobStateStrName);
      Log.debug(TAG, `onAddPrintJob ${jobItem.toString()}`);
      this.uiJobsMap.set(job.jobId, jobItem);
      // 刷新横幅提示状态
      this.updateShowTips(blockedSubState);
      this.refreshUi();
    }
    Log.info(TAG, 'onAddPrintJob end.');
  }

  onUpdatePrintJob(job: PrintJob, blockedSubState: number): void {
    Log.info(TAG, 'onUpdatePrintJob enter.');
    let jobItem = this.uiJobsMap.get(job.jobId);
    if (jobItem) {
      Log.info(TAG, `onUpdatePrintJob jobId:${job.jobId}, blockedSubState:${blockedSubState}`);
      jobItem.jobStateStrName = this.getJobStateStrName(job.jobState, job.jobSubstate);
      jobItem.isHideCancelBtn = this.isHideCancelBtn(job.jobState as number);
      jobItem.jobStateColor = this.getJobStateFontColor(job.jobState as number, job.jobSubstate);
      Log.debug(TAG, `onUpdatePrintJob ${jobItem.toString()}`);
      this.uiJobsMap.set(job.jobId, jobItem);
      // 刷新横幅提示状态
      this.updateShowTips(blockedSubState);
      this.refreshUi();
    }
    Log.info(TAG, 'onUpdatePrintJob end.');
  }

  onRemovePrintJob(jobId: string, blockedSubState: number): void {
    Log.info(TAG, 'onRemovePrintJob enter.');
    if (this.uiJobsMap.delete(jobId)) {
      Log.info(TAG, `onRemovePrintJob success, jobId:${jobId}, blockedSubState:${blockedSubState}`);
      // 刷新横幅提示状态
      this.updateShowTips(blockedSubState);
      this.refreshUi();
    }
    Log.info(TAG, 'onRemovePrintJob end.');
  }

  onAllPrintJobsFinished(): void {
    Log.info(TAG, 'onAllPrintJobsFinished enter.');
    this.uiJobsMap.clear();
    // 刷新横幅提示状态
    this.updateShowTips(-1);
    this.refreshUi();
    Log.info(TAG, 'onAllPrintJobsFinished end.');
  }

  cancelPrintJob(jobId: string): void {
    Log.debug(TAG, 'cancelPrintJob enter.');
    let jobItem = this.uiJobsMap.get(jobId);
    if (jobItem) {
      Log.info(TAG, `cancelPrintJob jobId:${jobId}`);
      jobItem.jobStateStrName = JOB_STATUS_MAP.get(CustomPrintJobState.PRINT_JOB_CANCELLING as number)!;
      jobItem.jobStateColor = this.getJobStateFontColor(CustomPrintJobState.PRINT_JOB_CANCELLING as number)!;
      Log.debug(TAG, `cancelPrintJob ${jobItem.toString()}`);
      this.uiJobsMap.set(jobId, jobItem);
      this.refreshUi();
    }
    cancelPrintJob(jobId);
    Log.info(TAG, 'cancelPrintJob end.');
  }

  refreshUi(): void {
    Log.info(TAG, 'refreshUi enter.');
    if (this.listener == null) {
      return;
    }
    let jobList: PrintJobItem[] = [];
    this.uiJobsMap.forEach((value, key) => {
      jobList.push(value);
    })
    let pageData: PageData = new PageData(this.tips, jobList);
    Log.info(TAG, `refreshUi pageData: ${pageData.toString()}`);
    this.listener.onPrintItemsChanged(pageData);
    Log.info(TAG, 'refreshUi end.');
  }
}
export let printJobMgrVM = SingletonHelper.getInstance(PrintJobViewModel, TAG);
