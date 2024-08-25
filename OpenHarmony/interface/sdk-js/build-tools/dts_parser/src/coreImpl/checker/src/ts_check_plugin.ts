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
import fs from 'fs';
import path from 'path';
import ts from 'typescript';
import { Check } from './api_check_plugin';
import { AddErrorLogs } from './compile_info';
import {
  ApiResultSimpleInfo,
  ErrorType,
  ErrorID,
  LogType,
  ErrorLevel,
  ApiResultInfo,
} from '../../../typedef/checker/result_type';
import { StringConstant } from '../../../utils/Constant';
import { CompolerOptions, ObtainFullPath } from '../../../utils/checkUtils';
import { compositiveResult, compositiveLocalResult } from '../../../utils/checkUtils';

export class TsSyntaxCheck {
  /**
   * ts语法检查工具入口
   * @param { string } url -File path for storing critical information.
   */
  static checkAPISyntax(url: string): ApiResultSimpleInfo[] {
    const tsResult: ApiResultSimpleInfo[] = [];
    const tsLocalResult: ApiResultInfo[] = [];
    if (fs.existsSync(url)) {
      const fullFilesPath: string[] = [];
      ObtainFullPath.getFullFiles(path.resolve(__dirname, '../../../../../../api'), fullFilesPath);
      const files: Array<string> = Check.getMdFiles(url);
      const program: ts.Program = ts.createProgram({
        rootNames: fullFilesPath,
        options: CompolerOptions.getCompolerOptions(),
      });
      //ts存在bug，仅为解决无法绑定sourcefile根节点的问题
      program.getTypeChecker();
      const programSourceFiles: readonly ts.SourceFile[] = program.getSourceFiles();
      const host: ts.CompilerHost = ts.createCompilerHost(CompolerOptions.getCompolerOptions());
      const diagnostics: ts.Diagnostic[] = ts.runArkTSLinter(program, host);
      files.forEach((filePath: string, index: number) => {
        TsSyntaxCheck.checkAPISyntaxCallback(
          filePath,
          program,
          diagnostics,
          programSourceFiles,
          compositiveResult,
          compositiveLocalResult
        );
        console.log(`api check scaning file in no ${++index}!`);
      });
    }
    return tsResult;
  }
  /**
   * ts检查主要处理过程
   * @param { string } fileName
   * @param { ts.Program } program
   * @param { ts.Diagnostic[] } diagnostics
   * @param { readonly ts.SourceFile[] } programSourceFiles
   * @param { ApiResultSimpleInfo[] } tsResult
   * @param { ApiResultInfo[] } checkErrorAllInfos
   */
  static checkAPISyntaxCallback(
    fileName: string,
    program: ts.Program,
    diagnostics: ts.Diagnostic[],
    programSourceFiles: readonly ts.SourceFile[],
    tsResult: ApiResultSimpleInfo[],
    checkErrorAllInfos: ApiResultInfo[]
  ): void {
    const fileContent: string = fs.readFileSync(fileName, StringConstant.UTF8);
    const node: ts.Node = ts.createSourceFile(fileName, fileContent, ts.ScriptTarget.ES2017, true);
    const fileSuffix: string = fileName.substring(fileName.lastIndexOf('.'), fileName.length);
    // tsc诊断日志
    if (fileSuffix === '.ts') {
      const targetSourceFile: ts.SourceFile = node.getSourceFile();
      programSourceFiles.forEach((programSourceFile) => {
        if (programSourceFile.fileName !== targetSourceFile.fileName) {
          return;
        }
        const result: readonly ts.Diagnostic[] = program.getSemanticDiagnostics(programSourceFile);
        result.forEach((item) => {
          const filePath: string = item.file?.fileName as string;
          const fileName: string = filePath.substring(filePath.indexOf('api'), filePath.length);
          AddErrorLogs.addAPICheckErrorLogs(
            ErrorID.TS_SYNTAX_ERROR_ID,
            ErrorLevel.MIDDLE,
            fileName,
            ts.getLineAndCharacterOfPosition(node.getSourceFile(), item.start as number),
            ErrorType.TS_SYNTAX_ERROR,
            LogType.LOG_API,
            -1,
            'NA',
            'NA',
            item.messageText as string,
            tsResult,
            checkErrorAllInfos
          );
        });
      });
    }
    // ArkTS诊断日志
    if (fileSuffix === '.ets') {
      diagnostics.forEach((item) => {
        if (path.normalize(item.file?.fileName as string) === path.normalize(fileName)) {
          const filePath: string = item.file?.fileName as string;
          const fileName: string = filePath.substring(filePath.indexOf('api'), filePath.length);
          AddErrorLogs.addAPICheckErrorLogs(
            ErrorID.TS_SYNTAX_ERROR_ID,
            ErrorLevel.MIDDLE,
            fileName,
            ts.getLineAndCharacterOfPosition(node.getSourceFile(), item.start as number),
            ErrorType.TS_SYNTAX_ERROR,
            LogType.LOG_API,
            -1,
            'NA',
            'NA',
            item.messageText as string,
            tsResult,
            checkErrorAllInfos
          );
        }
      });
    }
  }
}
