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
import { BusinessError } from '@ohos.base';
import CheckEmptyUtils from '../utils/CheckEmptyUtils';
import { Log } from '../utils/Log';
import { PrintUtil } from '../utils/PrintUtil';
import { CustomPrintJobState } from '../model/PrintBean';
import { StringUtil } from '../utils/StringUtil';

const TAG: string = 'print_fwk';
/**
 * defines print margin.
 */
export class PrintMargin implements print.PrintMargin {
  top?: number;
  bottom?: number;
  left?: number;
  right?: number;

  constructor(top: number, bottom: number, left: number, right: number) {
    this.top = top;
    this.bottom = bottom;
    this.left = left;
    this.right = right;
  }
}

/**
 * defines print range.
 */
export class PrinterRange implements print.PrinterRange {
  startPage?: number;
  endPage?: number;
  pages?: Array<number>;

  constructor(startPage: number, endPage: number, pages: Array<number>) {
    this.startPage = startPage;
    this.endPage = endPage;
    this.pages = pages;
  }
}

/**
 * defines print preview attribute.
 */
export class PreviewAttribute implements print.PreviewAttribute {
  previewRange: PrinterRange;
  result?: number;

  constructor(previewRange: PrinterRange, result: number) {
    this.previewRange = previewRange;
    this.result = result;
  }
}

/**
 * defines print resolution.
 */
export class PrintResolution implements print.PrintResolution {
  id: string;
  horizontalDpi: number;
  verticalDpi: number;
}

export class PrintPageSize implements print.PrintPageSize {
  id: string;
  name: string;
  width: number;
  height: number;

  constructor(id: string, name: string, width: number, height: number) {
    this.id = id;
    this.name = name;
    this.width = width;
    this.height = height;
  }
}

/**
 * defines print capability.
 */
export class PrinterCapability implements print.PrinterCapability {
  colorMode: number;
  duplexMode: number;
  pageSize: Array<PrintPageSize>;
  resolution?: Array<PrintResolution>;
  minMargin?: PrintMargin;
  options?: string; /* Change Type*/
}

/**
 * defines print info.
 */
export class PrinterInfo implements print.PrinterInfo {
  printerId: string;
  printerName: string;
  printerState: print.PrinterState;
  printerIcon?: number;
  description?: string;
  capability?: PrinterCapability;
  options?: string;

  constructor(printerId: string, printerName: string, printerState: print.PrinterState, printerIcon?: number, description?: string,
              capability?: PrinterCapability, options?: string) {
    this.printerId = printerId;
    this.printerName = printerName;
    this.printerState = printerState;
    if (printerIcon) {
      this.printerIcon = printerIcon;
    }
    if (description) {
      this.description = description;
    }
    if (capability) {
      this.capability = capability;
    }
    if (options) {
      this.options = options;
    }
  }

  toString(): string {
    return '[PrinterInfo printerId:' + StringUtil.splitMac(this.printerId) +
    ' ,printerName:' + StringUtil.encodeCommonString(this.printerName) +
    ' , printerState:' + this.printerState + ']';
  }
}

/**
 * PrinterInfo.options数据结构
 */
export class PrinterCapsOptions {
  supportedMediaTypes: number[];
  supportedQualities: number[];
  make: string;
  printerUri: string;
}

/**
 * defines print job
 */
export class PrintJob implements print.PrintJob {
  jobFiles: Array<string>; /* Add a Variable */
  fdList: Array<number>;
  jobId: string;
  printerId: string;
  jobState: print.PrintJobState;
  jobSubstate: print.PrintJobSubState;
  copyNumber: number;
  pageRange: PrinterRange;
  isSequential: boolean;
  pageSize: PrintPageSize;
  isLandscape: boolean;
  colorMode: number;
  duplexMode: number;
  margin: PrintMargin;
  preview: PreviewAttribute;
  options: string; /* Change Type */

  constructor(jobFiles: Array<string>, fdList: Array<number>, jobId: string, printerId: string, jobState: print.PrintJobState,
              jobSubstate: print.PrintJobSubState, copyNumber: number, pageRange: PrinterRange, isSequential: boolean,
              pageSize: PrintPageSize, isLandscape: boolean, colorMode: number, duplexMode: number, margin: PrintMargin,
              preview: PreviewAttribute, options: string) {
    this.jobFiles = jobFiles;
    this.fdList = fdList;
    this.jobId = jobId;
    this.printerId = printerId;
    this.jobState = jobState;
    this.jobSubstate = jobSubstate;
    this.copyNumber = copyNumber;
    this.pageRange = pageRange;
    this.isSequential = isSequential;
    this.pageSize = pageSize;
    this.isLandscape = isLandscape;
    this.colorMode = colorMode;
    this.duplexMode = duplexMode;
    this.margin = margin;
    this.preview = preview;
    this.options = options;
  }
}

export class PrinterExtensionInfo implements print.PrinterExtensionInfo {
  extensionId: string; // extension id of printer extension
  vendorId: string; // vendor id of extension
  vendorName: string;  // vendor name
  vendorIcon: number; // resource id of vendor
  version: string; // version of current printer extension
  constructor(extensionId: string, vendorId: string, vendorName: string, vendorIcon: number, version: string) {
    this.extensionId = extensionId;
    this.vendorId = vendorId;
    this.vendorName = vendorName;
    this.vendorIcon = vendorIcon;
    this.version = version;
  }
}

/**
 * PrintJob.options数据结构
 */
export class PrintJobOptions {
  jobName: string;
  jobNum: number;
  jobDescription: string;
  mediaType: string;
  documentCategory: number;
  printQuality: string;
  printerName: string;
  printerUri: string;
  documentFormat: string;
  files: string[];
}
export function startPrintJob(printJobInfo: PrintJob): Promise<boolean> {
  Log.info(TAG, 'startPrintJob enter.');
  return new Promise((resolve) => {
    if (CheckEmptyUtils.isEmpty(printJobInfo)) {
      Log.info(TAG, 'startPrintJob, printJobInfo invalid.');
      return resolve(false);
    }
    let printJob: print.PrintJob = convertToFwkPrintJob(printJobInfo);
    Log.info(TAG, 'startPrintJob, jobId =' + JSON.stringify(printJobInfo.jobId));
    print.startPrintJob(printJob).then(() => {
      Log.info(TAG, 'start print success.');
      resolve(true);
    }).catch((err: BusinessError) => {
      Log.error(TAG, 'failed to start Print because ' + JSON.stringify(err));
      return resolve(false);
    });
  });
}

export function queryAllPrintJobs(printerId?: string): Promise<Array<PrintJob>> {
  return new Promise((resolve, reject) => {
    print.queryPrintJobList().then((data: Array<print.PrintJob>) => {
      Log.info(TAG, `queryAllPrintJobs data.length:${data.length}`);
      let retPrintJobs: Array<PrintJob> = [];
      for (let printJob of data) {
        Log.debug(TAG, `queryAllPrintJobs printJob:${JSON.stringify(printJob)}`);
        let printJobInfo = convertToSpoolerPrintJob(printJob);
        if (CheckEmptyUtils.isEmpty(printJobInfo)) {
          Log.warn(TAG, 'queryAllPrintJobs invalid job.');
          continue;
        }
        if (CheckEmptyUtils.checkStrIsEmpty(printerId) || printJobInfo.printerId === printerId) {
          retPrintJobs.push(printJobInfo);
        }
      }
      Log.info(TAG, `queryAllPrintJobs retPrintJobs.length: ${retPrintJobs.length}`);
      resolve(retPrintJobs);
    }).catch((err: BusinessError) => {
      Log.error(TAG, `failed to queryAllPrintJobs Cause: ${JSON.stringify(err)}`);
      return reject(err);
    });
  });
}

export function cancelPrintJob(jobId: string): void {
  Log.info(TAG, 'cancelPrintJob enter.');
  if (CheckEmptyUtils.checkStrIsEmpty(jobId)) {
    Log.info(TAG, 'cancelPrintJob, jobId is empty.');
    return;
  }
  Log.info(TAG, 'cancelPrintJob jobId=' + jobId);
  print.cancelPrintJob(jobId).then((data) => {
    Log.info(TAG, 'cancel print success data: ' + JSON.stringify(data));
  }).catch((error: BusinessError) => {
    Log.error(TAG, 'cancel print failed, because: ' + JSON.stringify(error));
  });
  Log.info(TAG, 'cancelPrintJob end.');
}

export function isValidPrintJob(job: print.PrintJob): boolean {
  if (CheckEmptyUtils.isEmpty(job)) {
    Log.info(TAG, 'isValidPrintJob job is empty.');
    return false;
  }
  if (CheckEmptyUtils.checkStrIsEmpty(job.printerId) || CheckEmptyUtils.checkStrIsEmpty(job.jobId) ||
  !(PrintUtil.isValueInEnum(job.jobState, print.PrintJobState) || PrintUtil.isValueInEnum(job.jobState, CustomPrintJobState)) ||
  !PrintUtil.isValueInEnum(job.jobSubstate, print.PrintJobSubState)) {
    return false;
  }
  return true;
}

export function convertToSpoolerPrintJob(job: print.PrintJob): PrintJob {
  if (!isValidPrintJob(job)) {
    return null;
  }
  return new PrintJob([], job.fdList, job.jobId, job.printerId, job.jobState as print.PrintJobState, job.jobSubstate,
    job.copyNumber, job.pageRange, job.isSequential, job.pageSize, job.isLandscape, job.colorMode,
    job.duplexMode, job.margin, job.preview, job.options as string);
}

export function convertToFwkPrintJob(printJobInfo: PrintJob): print.PrintJob {
  let pageRangeInfo: PrinterRange;
  if (printJobInfo.pageRange.pages.length === 0) {
    pageRangeInfo = { startPage: printJobInfo.pageRange.startPage, endPage: printJobInfo.pageRange.endPage };
  } else {
    pageRangeInfo = { pages: printJobInfo.pageRange.pages };
  }
  // remove: preview, jobFiles
  let printJob: print.PrintJob = {
    fdList: printJobInfo.fdList,
    jobId: printJobInfo.jobId,
    printerId: printJobInfo.printerId,
    jobState: printJobInfo.jobState,
    jobSubstate: printJobInfo.jobSubstate,
    copyNumber: printJobInfo.copyNumber,
    pageRange: pageRangeInfo,
    isSequential: printJobInfo.isSequential,
    pageSize: printJobInfo.pageSize,
    isLandscape: printJobInfo.isLandscape,
    colorMode: printJobInfo.colorMode,
    duplexMode: printJobInfo.duplexMode,
    margin: printJobInfo.margin,
    options: printJobInfo.options
  };
  return printJob;
}

export function convertToPrinterInfo(info: print.PrinterInfo): PrinterInfo {
  if (CheckEmptyUtils.isEmpty(info)) {
    return null;
  }
  let printerInfo: PrinterInfo = new PrinterInfo(info.printerId, info.printerName, info.printerState, info.printerIcon, info.description,
    info.capability as PrinterCapability, info.options as string);
  return printerInfo;
}
