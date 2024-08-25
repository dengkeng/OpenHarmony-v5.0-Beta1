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
import CheckEmptyUtils, { Constants, convertToSpoolerPrintJob, isValidPrintJob, Log, PrintJob, PrintJobChangeListener, queryAllPrintJobs, SingletonHelper } from '@ohos/common';
import print from '@ohos.print';
import FileUtil from '../Common/Utils/FileUtil';

const TAG: string = 'PrintJobManager';
class PrintJobManager {
  private localJobMap: Map<string, PrintJob> = new Map();
  private isStarted: boolean = false;
  private isRegister: boolean = false;
  private printJobChangeListeners: Map<string, PrintJobChangeListener> = new Map();

  private onJobStateChanged = (jobState: print.PrintJobState, job: print.PrintJob): void => {
    Log.info(TAG, `onJobStateChanged jobId:${job?.jobId}, jobState:${jobState}, jobSubstate:${job?.jobSubstate}`);
    if (!isValidPrintJob(job)) {
      Log.warn(TAG, 'onJobStateChanged invalid job.');
      return;
    }
    let printJob: PrintJob = convertToSpoolerPrintJob(job);
    this.deleteLocalSource(printJob);
    this.updatePrintJob(printJob);
  };

  onStart(printerId?: string): void {
    if (this.isStarted) {
      return;
    }
    this.isStarted = true;
    this.registerCallback();
  }

  onStop(): void {
    this.unregisterCallback();
    this.printJobChangeListeners?.clear();
  }

  registerCallback(): void {
    Log.info(TAG, `registerCallback isRegister:${this.isRegister}`);
    if (!this.isRegister) {
      print.on(`jobStateChange`, this.onJobStateChanged);
      this.isRegister = true;
    }
  }
  unregisterCallback(): void {
    Log.info(TAG, `unregisterCallback isRegister:${this.isRegister}`);
    if (this.isRegister) {
      print.off('jobStateChange', (data: boolean) => {
        Log.info(TAG, `off jobStateChange data:` + JSON.stringify(data));
      });
      this.isRegister = false;
    }
  }

  registerJobChangeListener(key: string, listener: PrintJobChangeListener): void {
    Log.info(TAG, `registerJobChangeListener key:${key}`);
    if (key === null || listener === null) {
      return;
    }
    this.printJobChangeListeners?.set(key, listener);
  }

  unregisterJobChangeListener(key: string): void {
    if (key === null) {
      return;
    }
    this.printJobChangeListeners?.delete(key);
  }

  async getPrintJobQueue(printerId?: string): Promise<void> {
    let remoteJobQueue: Array<PrintJob> = await Promise.resolve(queryAllPrintJobs(printerId));
    let sortedJobQueue: Array<PrintJob> = await Promise.resolve(this.sortPrintJobs(remoteJobQueue));
    await Promise.resolve(this.updateLocalPrintJobQueue(sortedJobQueue));
  }

  private updateLocalPrintJobQueue(remoteJobQueue?: Array<PrintJob>): void {
    Log.info(TAG, `updateLocalPrintJobQueue remoteJobQueue.length:${remoteJobQueue.length},localJobMap.length: ${this.localJobMap.size}`)
    if (remoteJobQueue.length === 0) {
      this.localJobMap.clear();
      this.notifyAllPrintJobsFinished();
      Log.debug(TAG, 'updateLocalPrintJobQueue notifyAllPrintJobsFinished');
    } else {
      for (let item of remoteJobQueue) {
        this.localJobMap.set(item.jobId, item);
        this.printJobChangeListeners?.forEach((listener, key) => {
          Log.info(TAG, `updateLocalPrintJobQueue listener.onAddPrintJob:Key:${key}, jobId:${item.jobId}`);
          listener?.onAddPrintJob(item, this.checkBlockInQueue());
        });
      }
    }
  }

  cancelPrintJob(jobId: string): void {
    Log.info(TAG, 'cancelPrintJob enter.');
    let job = this.localJobMap.get(jobId);
    if (job) {
      Log.info(TAG, `cancelPrintJob jobId:${jobId}`);
      print.cancelPrintJob(jobId).then((data)=> {
        Log.info(TAG, 'cancelPrintJob success, data:' + JSON.stringify(data));
      }).catch((err) =>{
        Log.info(TAG, 'cancelPrintJob failed, err:' + JSON.stringify(err));
      });
    }
    Log.info(TAG, 'cancelPrintJob end.');
  }

  updatePrintJob(job: PrintJob): void {
    Log.info(TAG, 'updatePrintJob enter.');
    if (this.localJobMap.has(job.jobId)) {
      Log.info(TAG, `updatePrintJob jobId: ${job.jobId}`);
      this.localJobMap.set(job.jobId, job);
      this.printJobChangeListeners?.forEach((listener, key) => {
        Log.info(TAG, `updatePrintJob listener.onUpdatePrintJob: Key:${key}, jobState:${job.jobState}`);
        listener?.onUpdatePrintJob(job, this.checkBlockInQueue());
      });
      this.handleCompleteJob(job);
    }
    Log.info(TAG, 'updatePrintJob end.');
  }

  handleCompleteJob(job: PrintJob): void {
    Log.info(TAG, 'handleCompleteJob enter.');
    if (job.jobState == print.PrintJobState.PRINT_JOB_COMPLETED) {
      setTimeout(() => {
        Log.info(TAG, 'handleCompleteJob show completed job time out, jobId=' + job.jobId);
        this.removePrintJob(job.jobId);
      }, Constants.SHOW_JOB_COMPLETED_TIMEOUT);
    }
    Log.info(TAG, `handleCompleteJob end, jobId:${job.jobId}`);
  }

  private removePrintJob(jobId: string): void {
    Log.info(TAG, `removePrintJob enter, jobId:${jobId}`);
    if (this.localJobMap.delete(jobId)) {
      Log.info(TAG, `removePrintJob jobId:${jobId} success.`);
      this.printJobChangeListeners?.forEach((listener, key) => {
        Log.info(TAG, `removePrintJob listener.onRemovePrintJob: Key:${key}, jobId:${jobId}`);
        listener?.onRemovePrintJob(jobId, this.checkBlockInQueue());
      });
    }

    if (this.localJobMap.size === 0) {
      Log.debug(TAG, 'removePrintJob notifyAllPrintJobsFinished.');
      this.notifyAllPrintJobsFinished();
    }
    Log.info(TAG, `removePrintJob end.`);
  }

  private deleteLocalSource(job: PrintJob): Promise<void> {
    if (CheckEmptyUtils.isEmpty(job)) {
      Log.warn(TAG, 'deleteLocalSource invalid job.');
      return;
    }
    if (job.jobState === print.PrintJobState.PRINT_JOB_BLOCKED || job.jobState === print.PrintJobState.PRINT_JOB_COMPLETED) {
      Log.info(TAG, `deleteLocalSource jobId:${job.jobId}`);
      FileUtil.deleteSource(job.jobFiles);
    }
    Log.info(TAG, 'deleteLocalSource end.');
  }

  checkBlockInQueue(): number {
    for(let value of this.localJobMap.values()) {
      if (value.jobState === print.PrintJobState.PRINT_JOB_BLOCKED) {
        return value.jobSubstate;
      }
    }
    return Constants.NEGATIVE_1;
  }

  private sortPrintJobs(jobArray: Array<PrintJob>): Promise<Array<PrintJob>> {
    return new Promise((resolve) => {
      jobArray.sort((job1, job2): number => {
        return Number(job1.jobId) - Number(job2.jobId);
      });
      resolve(jobArray);
    });
  }

  private notifyAllPrintJobsFinished(): void {
    Log.info(TAG, 'notifyAllPrintJobsFinished enter.');
    this.printJobChangeListeners?.forEach((listener, key) => {
      Log.info(TAG, 'notifyAllPrintJobsFinished listener.onAllPrintJobsFinished.');
      listener?.onAllPrintJobsFinished();
    });
    Log.info(TAG, 'notifyAllPrintJobsFinished end.');
  }
}
export let printJobMgr = SingletonHelper.getInstance(PrintJobManager, TAG);