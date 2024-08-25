/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

import ExcelJS from 'exceljs';
import path from 'path';
import fs from 'fs';
import { LogUtil } from '../utils/logUtil';
import { ToolNameExcelCallback, joinNewMessage, joinOldMessage, ToolReturnData } from './config';
import { BasicDiffInfo, diffTypeMap } from '../typedef/diff/ApiInfoDiff';
import { FunctionUtils } from '../utils/FunctionUtils';
import { SyscapProcessorHelper } from '../coreImpl/diff/syscapFieldProcessor';

export namespace WriterHelper {
  export function JSONReporter(data: string, dest: string, fileName: string) {
    const outputFile = path.resolve(dest, fileName);
    fs.writeFileSync(outputFile, data);
    LogUtil.i('JSONReporter', `report is in ${outputFile}`);
  }

  export async function ExcelReporter(
    data: ToolReturnData,
    dest: string,
    fileName: string,
    callback: ToolNameExcelCallback | undefined
  ) {
    const workbook: ExcelJS.Workbook = new ExcelJS.Workbook();
    const sheet: ExcelJS.Worksheet = workbook.addWorksheet();

    if (typeof callback === 'function') {
      //callback是一个函数，才能当回调函数使用
      callback(data, sheet, dest);
    }

    const buffer: NodeJS.ArrayBufferView = (await workbook.xlsx.writeBuffer()) as NodeJS.ArrayBufferView;
    const outputFile: string = path.resolve(dest, fileName);
    fs.writeFileSync(outputFile, buffer);
    LogUtil.i('ExcelReporter', `report is in ${outputFile}`);
  }

  export class MarkdownReporter {
    static writeInMarkdown(data: BasicDiffInfo[], dest: string | undefined): void {
      const kitInfoSet: Set<string> = MarkdownReporter.getAllKitInfo(data);
      kitInfoSet.forEach((kitInfo: string) => {
        let diffsInSameKit: BasicDiffInfo[] = [];
        data.forEach((diffInfo: BasicDiffInfo) => {
          if (SyscapProcessorHelper.getSingleKitInfo(diffInfo) === kitInfo) {
            diffsInSameKit.push(diffInfo);
          }
        });

        if (diffsInSameKit.length === 0) {
          return;
        }

        MarkdownReporter.sortDiffInfoByFile(diffsInSameKit, kitInfo, dest);
      });
    }

    /**
     * 获取所有的kit信息
     *
     * @param {BasicDiffInfo[]} data
     * @returns
     */
    static getAllKitInfo(data: BasicDiffInfo[]): Set<string> {
      const kitInfoSet: Set<string> = new Set();
      data.forEach((diffInfo) => {
        kitInfoSet.add(diffInfo.getOldKitInfo());
        kitInfoSet.add(diffInfo.getNewKitInfo());
      });
      return kitInfoSet;
    }

    static getSingleKitInfo(data: BasicDiffInfo): string {
      if (data.getNewKitInfo() !== '') {
        return data.getNewKitInfo();
      }
      return data.getOldKitInfo();
    }

    static getFileNameInkit(diffsInSameSystem: BasicDiffInfo[]): Set<string> {
      const fileNameSet: Set<string> = new Set();
      diffsInSameSystem.forEach((diffInfo) => {
        if (diffInfo.getNewDtsName() !== '') {
          fileNameSet.add(diffInfo.getNewDtsName());
        } else {
          fileNameSet.add(diffInfo.getOldDtsName());
        }
      });
      return fileNameSet;
    }

    static getSingleFileName(data: BasicDiffInfo): string {
      if (data.getNewDtsName() !== '') {
        return data.getNewDtsName();
      }
      return data.getOldDtsName();
    }
    
    /**
     * 使用文件名进行排序
     *
     * @param { BasicDiffInfo[] } diffsInSameKit 所属kit一样的diffInfo
     * @param { string } kitInfo kit信息
     * @param dest
     */
    static sortDiffInfoByFile(diffsInSameKit: BasicDiffInfo[], kitInfo: string, dest: string | undefined): void {
      const fileNameSet = MarkdownReporter.getFileNameInkit(diffsInSameKit);
      const diffInfosInSameFile: BasicDiffInfo[] = [];
      fileNameSet.forEach((fileName: string) => {
        diffsInSameKit.forEach((diffInfo: BasicDiffInfo) => {
          if (MarkdownReporter.getSingleFileName(diffInfo) === fileName) {
            diffInfosInSameFile.push(diffInfo);
          }
        });
        MarkdownReporter.sortDiffInfoByStatus(diffInfosInSameFile, kitInfo, dest);
      });
    }

    static sortDiffInfoByStatus(diffsInSameSystem: BasicDiffInfo[], kitInfo: string, dest: string | undefined): void {
      const sortDiffInfos: BasicDiffInfo[] = [];
      for (const type of diffTypeMap.keys()) {
        diffsInSameSystem.forEach((diffInfo) => {
          if (diffInfo.getDiffType() === type) {
            sortDiffInfos.push(diffInfo);
          }
        });
      }
      MarkdownReporter.exportDiffMd(kitInfo, sortDiffInfos, dest);
    }

    static exportDiffMd(kitInfo: string, diffInfos: BasicDiffInfo[], dest: string | undefined): void {
      let markDownContent: string =
        '| 操作 | 旧版本 | 新版本 | d.ts文件 |\n' + '| ---- | ------ | ------ | -------- |\n';
      for (let i = 0; i < diffInfos.length; i++) {
        let diffInfo: BasicDiffInfo = diffInfos[i];
        const dtsName = diffInfo.getNewDtsName() ? diffInfo.getNewDtsName() : diffInfo.getOldDtsName();
        markDownContent +=
          `|${diffTypeMap.get(diffInfo.getDiffType())}|${MarkdownReporter.formatDiffMessage(
            joinOldMessage(diffInfo)
          )}` + `|${MarkdownReporter.formatDiffMessage(joinNewMessage(diffInfo))}|${dtsName.replace(/\\/g, '/')}|\n`;
      }
      const mdFilesDir = `${dest}\\diff合集`;
      if (!fs.existsSync(mdFilesDir)) {
        fs.mkdirSync(mdFilesDir);
      }

      fs.writeFileSync(`${dest}\\diff合集\\js-apidiff-${kitInfo}.md`, markDownContent);
    }

    static formatDiffMessage(diffMessage: string): string {
      const message = diffMessage
        .replace(/\r|\n/g, '<br>')
        .replace(/\|/g, '\\|')
        .replace(/\<(?!br>)/g, '\\<');
      return message;
    }
  }
}
